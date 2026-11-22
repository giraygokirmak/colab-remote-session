"""Shared, fully local fixtures for the Streamable HTTP integration tests.

No Google OAuth request, real credential store, or Colab runtime is used here.
Only an isolated loopback listener carries the production Store and SDK handlers.
"""

from __future__ import annotations

import asyncio
import html
import json
import re
import socket
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import httpx
import pytest
import uvicorn
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from colab_remote_mcp.config import Config
from colab_remote_mcp.server import create_server

CALLBACK_URL = "http://127.0.0.1:8765/callback"
GOOGLE_CODE = "integration-fixture-google-code"
CLIENT_REGISTRATION = {
    "client_name": "Local MCP integration fixture",
    "redirect_uris": [CALLBACK_URL],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "scope": "colab",
}


class FakeCredentialStore:
    """A test-only credential sink, not a Google or keyring credential class."""

    def __init__(self) -> None:
        self.saved: list[dict[str, str]] = []

    def save(self, record: dict[str, str]) -> None:
        self.saved.append(record)

    def sessions(self) -> None:
        raise AssertionError("The fake executor must not request Google credentials.")


class FakeColabAuthorization:
    """The synchronous Authorization boundary used by AuthorizationPage."""

    def __init__(self, credentials: FakeCredentialStore) -> None:
        self.credentials = credentials
        self.begun: list[str] = []
        self.completed: list[tuple[str, str]] = []
        self.discarded: list[str] = []
        self._active: set[str] = set()
        self._lock = threading.Lock()

    def begin(self, state: str) -> str:
        with self._lock:
            self.begun.append(state)
            self._active.add(state)
        # Reserved .test host; the fake browser never dereferences this URL.
        return "https://accounts.google.test/o/oauth2/auth?" + urlencode(
            {
                "client_id": "fixture-only.apps.googleusercontent.com",
                "redirect_uri": "https://sdk.cloud.google.com/applicationdefaultauthcode.html",
                "response_type": "code",
                "scope": "https://www.googleapis.com/auth/colaboratory",
                "state": state,
            }
        )

    def complete(self, state: str, code: str) -> None:
        with self._lock:
            if state not in self._active or code != GOOGLE_CODE:
                raise ValueError("The fixture did not accept that Colab code.")
            self.completed.append((state, code))
            self._active.remove(state)
        # Deliberately not a credentials JSON document, OAuth token, or real identity.
        self.credentials.save({"fixture": "offline-colab-credential-placeholder"})


class ImmediateExecutor:
    """Exercise real JobManager/MCP logic without allocating a Colab runtime."""

    result_text = "fixture result for MCP integration\n"

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.completed = asyncio.Event()

    async def run(self, job: Any, code: str, **options: Any) -> None:
        self.calls.append({"job_id": job.id, "code": code, **options})
        try:
            job.status = "running"
            await job.event("status", {"status": "running"})
            await job.event("stdout", {"text": "Local Colab execution fixture\n"})
            for index, source in enumerate(options.get("client_exports") or [], 1):
                from colab_remote_mcp.jobs import ExportRequest

                request = ExportRequest(index, source)
                staging = job.export_path(request)
                staging.write_text(self.result_text, encoding="utf-8")
                artifact = job.finish_export(request, staging, "text/plain")
                await job.event("artifact", {"artifact": artifact})
            job.status = "completed"
            await job.event("status", {"status": "completed"})
        except Exception as error:
            job.status = "failed"
            job.error = f"Local executor fixture failed: {type(error).__name__}"
            await job.event("status", {"status": "failed"})
        finally:
            self.completed.set()

    async def request_cancel(self, job: Any) -> None:
        job.cancelled.set()


class MemoryTokenStorage:
    """The actual TokenStorage protocol expected by OAuthClientProvider."""

    def __init__(self) -> None:
        self.tokens: OAuthToken | None = None
        self.client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self.client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self.client_info = client_info


@dataclass
class IntegrationEnvironment:
    service: Any
    app: Any
    http: httpx.AsyncClient
    public_url: str
    mcp_url: str
    credentials: FakeCredentialStore
    authorization: FakeColabAuthorization
    executor: ImmediateExecutor
    store_path: Path


@pytest.fixture
async def integration_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Run the real app on a randomized loopback Uvicorn listener."""

    # Even an erroneous fallback cannot discover developer credentials or use TCP.
    monkeypatch.setenv("HOME", str(tmp_path / "empty-home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty-config"))
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("CLOUDSDK_CONFIG", raising=False)

    # Reserve a loopback port before installing the network guard. This is the
    # only server socket any test may contact; there is no outbound connection.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    create_connection = socket.create_connection
    connect = socket.socket.connect

    def guarded(host: Any, *args: Any, **kwargs: Any) -> Any:
        address = args[0] if args and isinstance(args[0], tuple) else host
        if isinstance(address, tuple) and address == ("127.0.0.1", port):
            return create_connection(host, *args, **kwargs)
        raise AssertionError("Integration tests may contact only their loopback fixture.")

    def guarded_connect(sock: socket.socket, address: Any) -> Any:
        if address == ("127.0.0.1", port):
            return connect(sock, address)
        raise AssertionError("Integration tests may contact only their loopback fixture.")

    monkeypatch.setattr(socket, "create_connection", guarded)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)

    public_url = f"http://127.0.0.1:{port}"
    mcp_url = public_url + "/mcp"
    data = tmp_path / "server-data"
    credentials = FakeCredentialStore()
    authorization = FakeColabAuthorization(credentials)
    config = Config(
        public_url=public_url,
        host="127.0.0.1",
        port=port,
        data=data,
        keyring_password="test-only-keyring-passphrase",
        keyring_root=tmp_path / "unused-keyring",
    )
    service = create_server(
        config,
        credential_store=credentials,
        authorization=authorization,
    )
    # Documented seam for this integration fixture: the exposed JobManager uses
    # the same executor interface as ColabExecutor.run/request_cancel.
    service.jobs.executor = ImmediateExecutor()
    app = service.create_app()
    # Use a real loopback HTTP transport. Otherwise httpx's ASGITransport waits
    # for a streaming SSE body while mcp 1.30.0 has its OAuth lock held, blocking
    # the SDK's concurrent notification GET and all later calls artificially.
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="critical",
            access_log=False,
            server_header=False,
        )
    )
    serve = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
        if serve.done():
            await serve
            raise AssertionError("The loopback integration server did not start.")
    try:
        async with httpx.AsyncClient(
            base_url=public_url,
            timeout=httpx.Timeout(5.0),
        ) as http:
            yield IntegrationEnvironment(
                service=service,
                app=app,
                http=http,
                public_url=public_url,
                mcp_url=mcp_url,
                credentials=credentials,
                authorization=authorization,
                executor=service.jobs.executor,
                store_path=data / "state.json",
            )
    finally:
        server.should_exit = True
        await asyncio.wait_for(serve, timeout=10)


_TRANSACTION = re.compile(
    r'<script\b[^>]*\bid=["\']transaction["\'][^>]*>(?P<json>.*?)</script>',
    re.DOTALL,
)


@dataclass
class BrowserResult:
    callback: dict[str, str]
    transaction: str
    google_url: str


@dataclass
class LocalOAuthBrowser:
    """Fetch the wrapped page and submit it; never follow its Google link."""

    http: httpx.AsyncClient
    authorization: FakeColabAuthorization
    result: BrowserResult | None = field(default=None, init=False)

    async def authorize(self, authorization_url: str) -> BrowserResult:
        authorization_response = await self.http.get(authorization_url, follow_redirects=False)
        assert authorization_response.status_code == 302
        completion_url = urljoin(
            str(self.http.base_url), authorization_response.headers["location"]
        )
        assert urlsplit(completion_url).path == "/oauth/complete"

        page = await self.http.get(completion_url)
        assert page.status_code == 200
        assert page.headers["content-type"].startswith("text/html")
        assert page.headers["cache-control"] == "no-store, private"
        match = _TRANSACTION.search(page.text)
        assert match is not None, "The real Colab completion transaction was not rendered."
        values = json.loads(html.unescape(match.group("json")))
        assert isinstance(values, list) and len(values) == 2
        transaction, google_url = values
        parsed_completion = parse_qs(urlsplit(completion_url).query)
        assert transaction == parsed_completion["state"][0]
        assert self.authorization.begun[-1] == transaction
        assert urlsplit(google_url).hostname == "accounts.google.test"

        # The production HTML uses name="code". Use that exact form, rather
        # than bypassing the handler through Store.finish_colab directly.
        submitted = await self.http.post(
            completion_url,
            data={"state": transaction, "code": GOOGLE_CODE},
            follow_redirects=False,
        )
        assert submitted.status_code == 303
        callback_url = submitted.headers["location"]
        parsed_callback = urlsplit(callback_url)
        callback_origin = parsed_callback._replace(query="", fragment="").geturl()
        assert callback_origin == CALLBACK_URL
        query = parse_qs(parsed_callback.query)
        assert set(query).issuperset({"code", "state"})
        assert len(query["code"]) == len(query["state"]) == 1
        assert self.authorization.completed[-1] == (transaction, GOOGLE_CODE)
        self.result = BrowserResult(
            callback={name: values[0] for name, values in query.items() if len(values) == 1},
            transaction=transaction,
            google_url=google_url,
        )
        return self.result


def pkce_pair() -> tuple[str, str]:
    """Generate a real S256 verifier/challenge using the pinned SDK."""

    from mcp.client.auth import PKCEParameters

    value = PKCEParameters.generate()
    return value.code_verifier, value.code_challenge


def different_value(value: str) -> str:
    replacement = "A" if not value.endswith("A") else "B"
    return value[:-1] + replacement


async def register_public_client(http: httpx.AsyncClient) -> dict[str, Any]:
    response = await http.post("/register", json=CLIENT_REGISTRATION)
    assert response.status_code == 201
    registration = response.json()
    assert isinstance(registration.get("client_id"), str) and registration["client_id"]
    assert registration["token_endpoint_auth_method"] == "none"
    assert registration.get("client_secret") is None
    assert registration["redirect_uris"] == [CALLBACK_URL]
    return registration
