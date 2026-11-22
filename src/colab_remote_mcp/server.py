"""Standalone OAuth-enabled FastMCP service and its owner-checked file resources."""

from __future__ import annotations

import asyncio
import base64
import re
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from mcp.server.auth.handlers.token import TokenHandler
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.routes import build_metadata, cors_middleware
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.streamable_http import MCP_PROTOCOL_VERSION_HEADER
from mcp.server.transport_security import (
    DEFAULT_MAX_REQUEST_BODY_SIZE,
    RequestBodyLimitMiddleware,
)
from mcp.shared.auth_utils import check_resource_allowed, resource_url_from_server_url
from mcp.types import (
    BlobResourceContents,
    EmbeddedResource,
    Resource,
    TextContent,
    TextResourceContents,
)
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, request_response

from colab_remote_mcp.auth_flow import AuthorizationPage
from colab_remote_mcp.config import MCP_SCOPE, Config
from colab_remote_mcp.credentials import ColabAuthorization, CredentialsStore
from colab_remote_mcp.executor import ColabExecutor
from colab_remote_mcp.jobs import JobError, JobManager
from colab_remote_mcp.store import Store

VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
TEXTUAL_MIMES = {"application/json", "application/xml", "image/svg+xml"}
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def owner(mcp: FastMCP[Any]) -> str:
    """Read the identity of this message, not the request which opened a session."""
    context: Context[Any, Any, Any] = mcp.get_context()
    request = context.request_context.request
    user = request.scope.get("user") if request is not None else None
    if not isinstance(user, AuthenticatedUser) or not user.access_token.subject:
        raise JobError("A verified OAuth subject is required for this operation.")
    return user.access_token.subject


def artifact_uri(value: str) -> tuple[str, str]:
    parts = urlsplit(value)
    if (
        parts.scheme != "col.file"
        or not re.fullmatch(r"[a-f0-9]{32}", parts.netloc)
        or parts.port is not None
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
        raise JobError("Only col.file://<job_id>/<captured_filename> resources are supported.")
    filename = unquote(parts.path)
    if not filename.startswith("/") or filename.count("/") != 1:
        raise JobError("The captured artifact URI must contain exactly one filename.")
    return parts.netloc, filename[1:]


class TokenResourceHandler(TokenHandler):
    """Fill resource/PKCE checks omitted by the pinned SDK's token handler."""

    def __init__(self, provider: Store) -> None:
        super().__init__(provider, ClientAuthenticator(provider))
        self.provider = provider

    async def handle(self, request: Request) -> Response:
        form = await request.form()
        verifier = form.get("code_verifier")
        resource = form.get("resource")
        if verifier is not None and (
            not isinstance(verifier, str) or not VERIFIER.fullmatch(verifier)
        ):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Invalid PKCE verifier syntax."},
                status_code=400,
                headers=NO_STORE,
            )
        if self.provider.resource is not None and (
            not isinstance(resource, str)
            or urlsplit(resource).fragment
            or not check_resource_allowed(resource, self.provider.resource)
            or resource_url_from_server_url(resource) != self.provider.resource
        ):
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Invalid MCP resource indicator.",
                },
                status_code=400,
                headers=NO_STORE,
            )
        return await super().handle(request)


async def public_client_metadata(request: Request) -> Response:
    """Correct MCP 1.30.0's conflicting public-client metadata advertisement."""
    content = request.app.state.oauth_metadata.model_copy(
        update={
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
        }
    )
    return PydanticJSONResponse(content, headers=NO_STORE)


@dataclass
class Service:
    mcp: FastMCP[Any]
    provider: Store
    jobs: JobManager
    page: AuthorizationPage
    _stack: AsyncExitStack = field(default_factory=AsyncExitStack, init=False)

    def create_app(self) -> Starlette:
        app = self.mcp.streamable_http_app()
        settings = self.mcp.settings.auth
        assert settings is not None
        app.state.oauth_metadata = build_metadata(
            settings.issuer_url,
            settings.service_documentation_url,
            settings.client_registration_options,
            settings.revocation_options,
        )
        for index, route in enumerate(app.routes):
            if not isinstance(route, Route):
                continue
            if route.path == "/.well-known/oauth-authorization-server":
                endpoint = cors_middleware(public_client_metadata, ["GET", "OPTIONS"])
                methods = ["GET", "OPTIONS"]
            elif route.path == "/token":
                # Replace only the SDK handler, retaining its outer CORS and 4 MiB
                # body-limit behavior for both successful and error responses.
                endpoint = CORSMiddleware(
                    RequestBodyLimitMiddleware(
                        request_response(TokenResourceHandler(self.provider).handle),
                        DEFAULT_MAX_REQUEST_BODY_SIZE,
                    ),
                    allow_origins=["*"],
                    allow_methods=["POST", "OPTIONS"],
                    allow_headers=[MCP_PROTOCOL_VERSION_HEADER],
                )
                methods = ["POST", "OPTIONS"]
            else:
                continue
            app.routes[index] = Route(route.path, endpoint=endpoint, methods=methods)

        app.router.lifespan_context = self._lifespan
        return app

    @asynccontextmanager
    async def _lifespan(self, app: Starlette):
        # StreamableHTTPSessionManager.run() owns an AnyIO cancel scope. Enter and
        # exit it in one task, not in pytest's separate setup/teardown tasks.
        import anyio

        entered = anyio.Event()
        leave = anyio.Event()
        failure: BaseException | None = None

        async def serve() -> None:
            nonlocal failure
            try:
                async with self._stack:
                    await self._stack.enter_async_context(self.mcp.session_manager.run())
                    self._stack.push_async_callback(self.close)
                    entered.set()
                    await leave.wait()
            except BaseException as error:
                failure = error
                entered.set()

        task = asyncio.create_task(serve(), name="colab-mcp-lifespan")
        await entered.wait()
        if failure is not None:
            await task
            raise failure
        try:
            yield
        finally:
            leave.set()
            await task
            if failure is not None:
                raise failure

    async def close(self) -> None:
        await self.jobs.stop_all()


def create_server(
    config: Config,
    *,
    credential_store: Any = None,
    authorization: Any = None,
) -> Service:
    if credential_store is None:
        if not config.keyring_password:
            raise ValueError("An explicit file-keyring password is required.")
        credential_store = CredentialsStore(config.keyring_root, config.keyring_password)
    credentials: Any = credential_store
    if authorization is None:
        authorization = ColabAuthorization(credentials)
    provider = Store(config.data, resource=config.public_url + "/mcp")
    executor = ColabExecutor(credentials)
    jobs = JobManager(config.data, executor)
    page = AuthorizationPage(provider, authorization, config.public_url)
    auth = AuthSettings(
        issuer_url=config.public_url,
        resource_server_url=config.public_url + "/mcp",
        required_scopes=[MCP_SCOPE],
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[MCP_SCOPE], default_scopes=[MCP_SCOPE]
        ),
        revocation_options=RevocationOptions(enabled=True),
        validate_token_resource=True,
    )
    mcp = FastMCP(
        "Colab Remote MCP",
        instructions=(
            "Run Python only on an ephemeral free standard Colab CPU or T4. Poll sequence-numbered "
            "events with get_job_output. Download only explicitly captured /content/output files. "
            "Authorization uses one Google Colab consent and code paste; no separate MCP login."
        ),
        host=config.host,
        port=config.port,
        auth_server_provider=provider,
        auth=auth,
        streamable_http_path="/mcp",
        json_response=False,
    )

    @mcp.custom_route("/oauth/complete", methods=["GET", "POST"])
    async def complete_google_authorization(request: Request) -> Response:
        if request.method == "GET":
            return await page.get(request)
        return await page.post(request)

    @mcp.tool(
        description=(
            "Start a temporary standard Colab CPU/T4 job and return immediately. Code is arbitrary "
            "remote Python; only /content/output paths listed in client_exports are captured. "
            "requirements are named package requirement specifiers "
            "(no pip options, URLs, paths or credentials). "
            "idle_timeout_seconds measures silence between kernel messages, not a total limit. "
            "One active job per server."
        )
    )
    async def run_code(
        code: str,
        accelerator: Literal["cpu", "gpu"] = "cpu",
        idle_timeout_seconds: int = 1800,
        requirements: list[str] | None = None,
        client_exports: list[str] | None = None,
    ) -> dict[str, Any]:
        return await jobs.start(
            owner(mcp),
            code,
            accelerator,
            idle_timeout_seconds=idle_timeout_seconds,
            requirements=requirements or [],
            client_exports=client_exports or [],
        )

    @mcp.tool(
        description=(
            "Read events after a sequence cursor. Keep polling next_cursor with wait_seconds up to "
            "30; inspect terminal cleanup.unassigned before considering remote release confirmed."
        )
    )
    async def get_job_output(
        job_id: str, after: int = 0, limit: int = 100, wait_seconds: float = 15
    ) -> dict[str, Any]:
        return await jobs.output(
            owner(mcp), job_id, after=after, limit=limit, wait_seconds=wait_seconds
        )

    @mcp.tool(
        description=(
            "Cooperatively cancel a job, close transport channels and await tracked cleanup. "
            "This returns the current state; poll get_job_output for the terminal cleanup report."
        )
    )
    async def cancel_job(job_id: str) -> dict[str, Any]:
        return await jobs.cancel(owner(mcp), job_id)

    def text_or_blob(
        data: bytes, mime: str, uri: AnyUrl
    ) -> TextResourceContents | BlobResourceContents:
        if mime.startswith("text/") or mime in TEXTUAL_MIMES:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError(
                    "A file marked as text is not valid UTF-8; export it with a binary MIME type."
                ) from error
            return TextResourceContents(uri=uri, text=text, mimeType=mime)
        return BlobResourceContents(
            uri=uri,
            blob=base64.b64encode(data).decode("ascii"),
            mimeType=mime,
        )

    def contents(job_id: str, filename: str, uri: str) -> ReadResourceContents:
        data, mime = jobs.read_file(owner(mcp), job_id, filename)
        resource = text_or_blob(data, mime, AnyUrl(uri))
        if isinstance(resource, TextResourceContents):
            return ReadResourceContents(content=resource.text, mime_type=mime, meta={"uri": uri})
        return ReadResourceContents(
            content=base64.b64decode(resource.blob), mime_type=mime, meta={"uri": uri}
        )

    @mcp.tool(description="Read an owned captured col.file:// artifact as typed MCP content.")
    async def download_file(resource_uri: str) -> list[TextContent | EmbeddedResource]:
        job_id, filename = artifact_uri(resource_uri)
        data, mime = jobs.read_file(owner(mcp), job_id, filename)
        resource = text_or_blob(data, mime, AnyUrl(resource_uri))
        return [EmbeddedResource(type="resource", resource=resource)]

    @mcp.resource(
        "col.file://{job_id}/{filename}",
        name="captured_colab_output",
        description=(
            "An explicitly captured Colab output, available only to its OAuth client's jobs."
        ),
        mime_type="application/octet-stream",
    )
    async def captured_resource(job_id: str, filename: str) -> bytes | str:
        uri = f"col.file://{job_id}/{filename}"
        return contents(job_id, filename, uri).content

    # FastMCP stores ResourceTemplate MIME statically. Use the low-level API for
    # per-file MIME and identity-filtered ListResources, without removing discovery.
    async def list_owned_resources() -> list[Resource]:
        return [
            Resource(
                uri=AnyUrl(item["resource_uri"]),
                name=item["name"],
                description=f"Captured output from job {item['job_id']}",
                mimeType=item["mime_type"],
                size=item["size"],
                _meta={"sha256": item["sha256"]},
            )
            for item in jobs.list_artifacts(owner(mcp))
        ]

    async def read_owned_resource(uri: AnyUrl) -> list[ReadResourceContents]:
        job_id, filename = artifact_uri(str(uri))
        return [contents(job_id, filename, str(uri))]

    mcp._mcp_server.list_resources()(list_owned_resources)
    mcp._mcp_server.read_resource()(read_owned_resource)
    return Service(mcp=mcp, provider=provider, jobs=jobs, page=page)
