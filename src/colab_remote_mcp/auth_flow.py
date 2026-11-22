"""MCP authorization page wrapping only the existing Colab interactive flow."""

from __future__ import annotations

import asyncio
import html
import json
from importlib import resources
from typing import Any

from google.auth.exceptions import GoogleAuthError
from mcp.server.auth.provider import construct_redirect_uri
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from colab_remote_mcp.credentials import AuthenticationRequired
from colab_remote_mcp.store import Store

SECURITY_HEADERS = {
    "Cache-Control": "no-store, private",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
}


class AuthorizationPage:
    def __init__(self, store: Store, google: Any, public_url: str) -> None:
        self.store = store
        self.google = google
        self.public_url = public_url.rstrip("/")

    async def get(self, request: Request) -> Response:
        state = str(request.query_params.get("state", ""))
        if not self._valid_state(state) or await self.store.pending(state) is None:
            return error(
                "This Colab authorization window is invalid or expired; "
                "reconnect MCP to restart its one Google authorization.",
                400,
            )
        url = await asyncio.to_thread(self.google.begin, state)
        document = resources.files("colab_remote_mcp").joinpath("auth.html").read_text()
        values = json.dumps([state, url]).replace("<", "\\u003c")
        document = document.replace("__TRANSACTION__", values)
        # Account identity UI would imply a separate MCP auth workflow. This constant
        # page only guides the user through the API-permitted Colab consent.
        return HTMLResponse(document, headers=SECURITY_HEADERS)

    async def post(self, request: Request) -> Response:
        form = await request.form()
        state = str(form.get("state", ""))
        code = str(form.get("code", "")).strip()
        if (
            not self._valid_state(state)
            or not code
            or len(code) > 4096
            or await self.store.pending(state) is None
        ):
            return error(
                "Invalid or expired Colab code window. Reconnect the MCP server; "
                "no different Colab auth command exists.",
                400,
            )
        try:
            await asyncio.wait_for(  # noqa: ASYNC109 - Google token-exchange deadline
                asyncio.to_thread(self.google.complete, state, code),
                timeout=60,
            )
        except (
            GoogleAuthError,
            AuthenticationRequired,
            ValueError,
            TypeError,
            RuntimeError,
            TimeoutError,
        ):
            # Do not forward the upstream response/Exception headers/secrets. Let them
            # try the same Colab code flow, without implementing alternate login.
            return self._retry_page(state)
        pending = await self.store.pending(state)
        if pending is None:
            return error("The MCP transaction expired; start this connection again.")
        result = await self.store.finish_colab(state)
        if result is None:
            return error("The connection is already complete. Return to your coding agent.", 409)
        mcp_code, record = result
        target = construct_redirect_uri(
            record["redirect_uri"], code=mcp_code, state=record.get("state")
        )
        return RedirectResponse(
            target,
            status_code=303,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )

    def _retry_page(self, state: str) -> HTMLResponse:
        target = self.public_url + "/oauth/complete?state=" + state
        return message(
            "Google did not accept that code. If you selected the wrong browser "
            "window, return to the same Colab connection and use a fresh code; "
            "otherwise restart your agent's MCP connection.",
            target,
            "Return to the same Colab authorization",
        )

    @staticmethod
    def _valid_state(state: str) -> bool:
        return 20 <= len(state) <= 256 and state.isascii()


def error(text: str, status: int = 400) -> HTMLResponse:
    return message(text, link="", status=status)


def message(
    text: str, link: str = "", label: str = "Return to agent", status: int = 200
) -> HTMLResponse:
    anchor = f'<a href="{html.escape(link, quote=True)}">{html.escape(label)}</a>' if link else ""
    safe_text = html.escape(text)
    return HTMLResponse(
        "<!doctype html><html lang=en><meta charset=utf-8><title>Google Colab</title>"
        f"<main><p>{safe_text}</p>{anchor}</main>",
        status_code=status,
        headers=SECURITY_HEADERS,
    )
