"""End-to-end public-client OAuth and Streamable HTTP tests over loopback.

These are intentionally real HTTP/MCP SDK tests rather than provider unit tests:
DCR, metadata, user-code bridging, PKCE, Bearer middleware, MCP tools, and MCP
resources are exercised together. Only Colab authorization/execution is faked.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest
from conftest import (
    CALLBACK_URL,
    CLIENT_REGISTRATION,
    FakeColabAuthorization,
    IntegrationEnvironment,
    LocalOAuthBrowser,
    MemoryTokenStorage,
    different_value,
    pkce_pair,
    register_public_client,
)
from mcp import ClientSession, types
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientMetadata, OAuthToken
from mcp.shared.exceptions import McpError
from pydantic import AnyUrl

EXPECTED_TOOLS = {"run_code", "get_job_output", "cancel_job", "download_file"}


def _token_request(
    client: dict[str, Any], browser: LocalOAuthBrowser, resource: str
) -> dict[str, str]:
    assert browser.result is not None
    # This is also what the pinned OAuthClientProvider sends after discovering PRM.
    return {
        "grant_type": "authorization_code",
        "code": browser.result.callback["code"],
        "redirect_uri": CALLBACK_URL,
        "client_id": client["client_id"],
        "resource": resource,
    }


async def initialize_mcp(session: ClientSession) -> types.InitializeResult:
    result = await asyncio.wait_for(session.initialize(), timeout=3)
    assert result.capabilities.tools is not None
    assert result.capabilities.resources is not None
    return result


@asynccontextmanager
async def bearer_session(mcp_url: str, token: str) -> AsyncIterator[ClientSession]:
    """Open an SDK MCP session; callers assert failures instead of logging tokens."""
    async with httpx.AsyncClient(
        base_url=mcp_url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=httpx.Timeout(5.0, read=10.0),
    ) as http:
        async with streamable_http_client(mcp_url, http_client=http) as (reader, writer, _):
            async with ClientSession(
                reader, writer, read_timeout_seconds=timedelta(seconds=5)
            ) as session:
                yield session


async def test_public_oauth_direct_http_pkce_and_refresh(
    integration_environment: IntegrationEnvironment,
) -> None:
    """A public DCR client can complete each real endpoint without a secret."""

    env = integration_environment
    client = await register_public_client(env.http)

    confidential = await env.http.post(
        "/register",
        json={**CLIENT_REGISTRATION, "token_endpoint_auth_method": "client_secret_post"},
    )
    assert confidential.status_code == 400
    assert confidential.json()["error"] == "invalid_client_metadata"

    resource_metadata = await env.http.get("/.well-known/oauth-protected-resource/mcp")
    assert resource_metadata.status_code == 200
    assert resource_metadata.json() == {
        "resource": env.mcp_url,
        "authorization_servers": [env.public_url + "/"],
        "scopes_supported": ["colab"],
        "bearer_methods_supported": ["header"],
    }
    authorization_metadata = await env.http.get("/.well-known/oauth-authorization-server")
    assert authorization_metadata.status_code == 200
    assert authorization_metadata.json()["issuer"] == env.public_url + "/"
    assert authorization_metadata.json()["registration_endpoint"] == env.public_url + "/register"
    assert authorization_metadata.json()["code_challenge_methods_supported"] == ["S256"]
    assert authorization_metadata.json()["token_endpoint_auth_methods_supported"] == ["none"]
    assert authorization_metadata.headers["cache-control"] == "no-store"
    for path, methods in (
        ("/.well-known/oauth-authorization-server", "GET"),
        ("/token", "POST"),
    ):
        preflight = await env.http.options(
            path,
            headers={
                "Origin": "https://client.example.test",
                "Access-Control-Request-Method": methods,
                "Access-Control-Request-Headers": "mcp-protocol-version",
            },
        )
        assert preflight.status_code == 200
        assert preflight.headers["access-control-allow-origin"] == "*"
        assert methods in preflight.headers["access-control-allow-methods"]
        assert "mcp-protocol-version" in preflight.headers["access-control-allow-headers"]
    metadata_cors = await env.http.get(
        "/.well-known/oauth-authorization-server",
        headers={"Origin": "https://client.example.test"},
    )
    assert metadata_cors.headers["access-control-allow-origin"] == "*"
    oversized = await env.http.post(
        "/token",
        content="x" * (4 * 1024 * 1024 + 1),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://client.example.test",
        },
    )
    assert oversized.status_code == 413
    assert oversized.headers["access-control-allow-origin"] == "*"

    verifier, challenge = pkce_pair()
    from urllib.parse import urlencode

    request = {
        "response_type": "code",
        "client_id": client["client_id"],
        "redirect_uri": CALLBACK_URL,
        "state": "direct-http-client-state",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scope": "colab",
        "resource": env.mcp_url,
    }
    browser = LocalOAuthBrowser(env.http, env.authorization)
    result = await browser.authorize("/authorize?" + urlencode(request))
    assert result.callback["state"] == request["state"]
    assert env.credentials.saved == [{"fixture": "offline-colab-credential-placeholder"}]

    token_data = _token_request(client, browser, env.mcp_url)
    for wrong_resource in (None, env.public_url + "/", env.mcp_url + "#fragment"):
        if env.service.provider.data["codes"] == {}:
            # Each rejected exchange needs an unused grant; otherwise the loop
            # would accidentally test the prior rejection's one-time code use.
            browser = LocalOAuthBrowser(env.http, env.authorization)
            result = await browser.authorize("/authorize?" + urlencode(request))
            token_data = _token_request(client, browser, env.mcp_url)
        bad_request = {
            key: value
            for key, value in {
                **token_data,
                "code_verifier": verifier,
                "resource": wrong_resource,
            }.items()
            if value is not None
        }
        wrong_audience = await env.http.post("/token", data=bad_request)
        assert wrong_audience.status_code == 400
        assert wrong_audience.json()["error"] == "invalid_request"
        assert len(env.service.provider.data["codes"]) == 1
    malformed_verifier = await env.http.post(
        "/token",
        data={**token_data, "code_verifier": "short"},
    )
    assert malformed_verifier.status_code == 400
    assert malformed_verifier.json()["error"] == "invalid_grant"
    rejected = await env.http.post(
        "/token",
        data={**token_data, "code_verifier": different_value(verifier)},
    )
    assert rejected.status_code == 400
    assert rejected.json()["error"] == "invalid_grant"
    assert rejected.headers["cache-control"] == "no-store"

    exchanged = await env.http.post(
        "/token",
        data={**token_data, "code_verifier": verifier},
    )
    assert exchanged.status_code == 200
    tokens = exchanged.json()
    assert tokens["token_type"] == "Bearer"
    assert tokens["scope"] == "colab"
    assert tokens["expires_in"] > 0
    assert tokens["access_token"] and tokens["refresh_token"]
    assert exchanged.headers["cache-control"] == "no-store"

    # The wrong verifier must not consume a code; the successful exchange must.
    replay = await env.http.post(
        "/token",
        data={**token_data, "code_verifier": verifier},
    )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"

    access = await env.service.provider.load_access_token(tokens["access_token"])
    assert access is not None
    assert access.client_id == client["client_id"]
    assert access.resource == env.mcp_url
    assert access.scopes == ["colab"]
    refresh_record = await env.service.provider.load_refresh_token(
        await env.service.provider.get_client(client["client_id"]), tokens["refresh_token"]
    )
    assert refresh_record is not None
    # The resource bound at authorization is authoritative at both exchanges.
    wrong_refresh_resource = await env.http.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client["client_id"],
            "resource": env.public_url + "/",
        },
    )
    assert wrong_refresh_resource.status_code == 400
    assert wrong_refresh_resource.json()["error"] == "invalid_request"
    loaded = await env.service.provider.load_refresh_token(
        await env.service.provider.get_client(client["client_id"]), tokens["refresh_token"]
    )
    assert loaded is not None

    # A client without a secret can use its one-time refresh grant.
    refreshed = await env.http.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client["client_id"],
            "resource": env.mcp_url,
        },
    )
    assert refreshed.status_code == 200
    rotated = refreshed.json()
    assert rotated["access_token"] != tokens["access_token"]
    assert rotated["refresh_token"] != tokens["refresh_token"]
    assert rotated["scope"] == "colab"
    assert await env.service.provider.load_access_token(tokens["access_token"]) is None
    assert (
        await env.service.provider.load_refresh_token(
            await env.service.provider.get_client(client["client_id"]),
            tokens["refresh_token"],
        )
        is None
    )
    refresh_replay = await env.http.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client["client_id"],
            "resource": env.mcp_url,
        },
    )
    assert refresh_replay.status_code == 400
    assert refresh_replay.json()["error"] == "invalid_grant"

    # Do not dump token values in an assertion failure; inspect hashed storage only.
    state_text = env.store_path.read_text(encoding="utf-8")
    for token in (tokens, rotated):
        assert token["access_token"] not in state_text
        assert token["refresh_token"] not in state_text
    assert await env.service.provider.load_access_token(rotated["access_token"]) is not None
    assert (
        await env.service.provider.load_refresh_token(
            await env.service.provider.get_client(client["client_id"]), rotated["refresh_token"]
        )
        is not None
    )
    for secret in (rotated["access_token"], rotated["refresh_token"]):
        assert secret not in state_text
        assert hashlib.sha256(secret.encode()).hexdigest() in state_text
    assert verifier not in state_text
    assert CLIENT_REGISTRATION["client_name"] in state_text
    state = json.loads(state_text)
    assert not state["pending"] and not state["codes"]
    assert all(not record.get("client_secret") for record in state["clients"].values())


async def test_audience_bound_token_and_two_client_resource_isolation(
    integration_environment: IntegrationEnvironment,
) -> None:
    env = integration_environment
    verifier, challenge = pkce_pair()

    async def issue_token() -> tuple[MemoryTokenStorage, LocalOAuthBrowser, dict[str, Any]]:
        registration = await register_public_client(env.http)
        browser = LocalOAuthBrowser(env.http, env.authorization)
        url = (
            env.public_url
            + "/authorize?"
            + urlencode(
                {
                    "response_type": "code",
                    "client_id": registration["client_id"],
                    "redirect_uri": CALLBACK_URL,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "two-client-isolation-" + registration["client_id"],
                    "scope": "colab",
                    "resource": env.mcp_url,
                }
            )
        )
        await browser.authorize(url)
        response = await env.http.post(
            "/token",
            data={**_token_request(registration, browser, env.mcp_url), "code_verifier": verifier},
        )
        assert response.status_code == 200
        storage = MemoryTokenStorage()
        await storage.set_tokens(OAuthToken.model_validate(response.json()))
        return storage, browser, registration

    first, _browser, _registration = await issue_token()
    assert first.tokens is not None
    async with bearer_session(env.mcp_url, first.tokens.access_token) as session:
        await initialize_mcp(session)
        started = await session.call_tool(
            "run_code",
            {
                "code": "print('first client only')",
                "client_exports": ["/content/output/private.txt"],
            },
        )
        assert not started.isError
        assert isinstance(started.structuredContent, dict)
        job_id = started.structuredContent["job_id"]
    await asyncio.wait_for(env.executor.completed.wait(), timeout=3)
    uri = f"col.file://{job_id}/001__private.txt"
    second, _second_browser, _second_registration = await issue_token()
    assert second.tokens is not None
    async with bearer_session(env.mcp_url, second.tokens.access_token) as session:
        await initialize_mcp(session)
        assert len((await session.list_resources()).resources) == 0
        for tool, arguments in (
            ("get_job_output", {"job_id": job_id, "wait_seconds": 0}),
            ("download_file", {"resource_uri": uri}),
            ("cancel_job", {"job_id": job_id}),
        ):
            rejected = await session.call_tool(tool, arguments)
            assert rejected.isError
            assert "not found for this MCP client" in str(rejected.content)
        with pytest.raises(McpError, match="not found for this MCP client"):
            await session.read_resource(uri)

    # A genuine token with no/wrong audience cannot initialize this MCP endpoint.
    for wrong_audience in (None, env.public_url + "/other-mcp"):
        entry = next(
            value
            for value in env.service.provider.data["access"].values()
            if value["client_id"] == _registration["client_id"]
        )
        entry["resource"] = wrong_audience
        env.service.provider._save()
        with pytest.raises(BaseExceptionGroup) as caught:
            async with bearer_session(env.mcp_url, first.tokens.access_token) as session:
                await initialize_mcp(session)
        assert "401" in repr(caught.value)
        assert await env.service.provider.load_access_token(first.tokens.access_token) is None

    # Tokens created with no subject cannot be used for ownership checks.
    digest = hashlib.sha256(first.tokens.access_token.encode()).hexdigest()
    env.service.provider.data["access"][digest]["resource"] = env.mcp_url
    env.service.provider.data["access"][digest]["subject"] = ""
    assert await env.service.provider.load_access_token(first.tokens.access_token) is None


async def test_mcp_requires_a_bearer_token_before_oauth(
    integration_environment: IntegrationEnvironment,
) -> None:
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "unauthenticated-fixture", "version": "0"},
        },
    }
    response = await integration_environment.http.post(
        "/mcp",
        json=request,
        headers={"accept": "application/json, text/event-stream"},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"
    authenticate = response.headers["www-authenticate"]
    assert authenticate.startswith("Bearer ")
    assert (
        f'resource_metadata="{integration_environment.public_url}/.well-known/oauth-protected-resource/mcp"'
        in authenticate
    )


async def test_real_sdk_public_oauth_client_calls_tools_and_reads_resources(
    integration_environment: IntegrationEnvironment,
) -> None:
    await asyncio.wait_for(
        _real_sdk_public_oauth_client_calls_tools_and_reads_resources(integration_environment),
        timeout=20,
    )


async def _real_sdk_public_oauth_client_calls_tools_and_reads_resources(
    integration_environment: IntegrationEnvironment,
) -> None:
    """The pinned MCP client itself drives DCR + PKCE, then actual MCP requests."""

    env = integration_environment
    browser = LocalOAuthBrowser(env.http, env.authorization)
    storage = MemoryTokenStorage()

    async def redirect_handler(authorization_url: str) -> None:
        await browser.authorize(authorization_url)

    async def callback_handler() -> tuple[str, str | None]:
        # mcp==1.30.0 expects (code, state), not a synthetic authorization response.
        assert browser.result is not None
        return browser.result.callback["code"], browser.result.callback.get("state")

    oauth = OAuthClientProvider(
        server_url=env.mcp_url,
        client_metadata=OAuthClientMetadata.model_validate(CLIENT_REGISTRATION),
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )
    async with httpx.AsyncClient(
        base_url=env.public_url,
        auth=oauth,
        timeout=httpx.Timeout(5.0, read=10.0),
    ) as streaming_http:
        async with streamable_http_client(
            env.mcp_url,
            http_client=streaming_http,
        ) as (read_stream, write_stream, get_session_id):
            async with ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=5),
            ) as session:
                initialized = await initialize_mcp(session)
                assert initialized.serverInfo.name
                assert get_session_id()
                assert browser.result is not None

                # Storage is supplied by the test and uses genuine SDK objects;
                # never log its bearer/refresh values when an assertion fails.
                assert storage.client_info is not None
                assert storage.client_info.client_id
                assert storage.client_info.token_endpoint_auth_method == "none"
                assert storage.client_info.client_secret is None
                assert storage.client_info.redirect_uris[0] == AnyUrl(CALLBACK_URL)
                assert storage.tokens is not None
                assert storage.tokens.access_token
                assert storage.tokens.refresh_token
                assert storage.tokens.scope == "colab"
                assert len(env.credentials.saved) == 1

                tools = await session.list_tools()
                assert {tool.name for tool in tools.tools} == EXPECTED_TOOLS
                assert all(tool.inputSchema for tool in tools.tools)
                resource_templates = await session.list_resource_templates()
                assert [item.uriTemplate for item in resource_templates.resourceTemplates] == [
                    "col.file://{job_id}/{filename}"
                ]

                call = await session.call_tool(
                    "run_code",
                    {
                        "code": "print('not executed on a real Colab runtime')",
                        "accelerator": "cpu",
                        "requirements": [],
                        "client_exports": ["/content/output/answer.txt"],
                        "idle_timeout_seconds": 1,
                    },
                )
                assert not call.isError
                started = call.structuredContent
                assert isinstance(started, dict)
                assert isinstance(started.get("job_id"), str) and started["job_id"]
                assert started["status"] in {"queued", "assigning", "running", "completed"}
                assert started["accelerator"] == "cpu"
                assert env.executor.calls == [
                    {
                        "job_id": started["job_id"],
                        "code": "print('not executed on a real Colab runtime')",
                        "idle_timeout_seconds": 1,
                        "requirements": [],
                        "client_exports": ["/content/output/answer.txt"],
                    }
                ]

                await asyncio.wait_for(env.executor.completed.wait(), timeout=3)
                output: dict[str, Any] | None = None
                for _attempt in range(3):
                    result = await session.call_tool(
                        "get_job_output",
                        {
                            "job_id": started["job_id"],
                            "after": 0,
                            "limit": 100,
                            "wait_seconds": 0,
                        },
                    )
                    assert not result.isError
                    assert isinstance(result.structuredContent, dict)
                    output = result.structuredContent
                    if output["status"] in {"completed", "failed", "cancelled"}:
                        break
                    await asyncio.sleep(0.01)
                assert output is not None
                assert output["status"] == "completed"
                assert output["error"] is None
                assert output["next_cursor"] == len(output["events"])
                assert any(
                    event["kind"] == "stdout" and "Local Colab execution fixture" in event["text"]
                    for event in output["events"]
                )
                artifacts = [
                    event["artifact"] for event in output["events"] if event["kind"] == "artifact"
                ]
                assert len(artifacts) == 1
                artifact = artifacts[0]
                assert artifact["name"] == "001__answer.txt"
                assert artifact["resource_uri"] == f"col.file://{started['job_id']}/001__answer.txt"
                assert (
                    artifact["sha256"]
                    == hashlib.sha256(env.executor.result_text.encode()).hexdigest()
                )

                resources = await session.list_resources()
                assert [str(resource.uri) for resource in resources.resources] == [
                    artifact["resource_uri"]
                ]
                resource = await session.read_resource(AnyUrl(artifact["resource_uri"]))
                assert len(resource.contents) == 1
                assert str(resource.contents[0].uri) == artifact["resource_uri"]
                assert getattr(resource.contents[0], "text", None) == env.executor.result_text
                assert resource.contents[0].mimeType == "text/plain"

                downloaded = await session.call_tool(
                    "download_file", {"resource_uri": artifact["resource_uri"]}
                )
                assert not downloaded.isError
                embedded = [
                    item for item in downloaded.content if isinstance(item, types.EmbeddedResource)
                ]
                assert len(embedded) == 1
                assert isinstance(embedded[0].resource, types.TextResourceContents)
                assert embedded[0].resource.text == env.executor.result_text
                assert str(embedded[0].resource.uri) == artifact["resource_uri"]

    # The completion consumed only the fake authorization state, not a real
    # Google session, and did not leak an MCP token into the OAuth state file.
    assert isinstance(env.authorization, FakeColabAuthorization)
    assert browser.result.transaction in env.authorization.begun
    replay_form = await env.http.post(
        "/oauth/complete",
        data={"state": browser.result.transaction, "code": "fixture-replayed-code"},
    )
    assert replay_form.status_code == 400
    state_text = env.store_path.read_text(encoding="utf-8")
    assert "offline-colab-credential-placeholder" not in state_text
    assert storage.client_info.client_id
    assert storage.tokens.access_token not in state_text
    assert storage.tokens.refresh_token not in state_text
