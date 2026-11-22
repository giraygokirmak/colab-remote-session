"""Single-process MCP OAuth state, isolated from Google Colab credentials.

Pending browser transaction IDs, MCP authorization codes, access tokens and
refresh tokens are persisted only by SHA-256 digest. Returned dynamic-client
credentials are not retained: this deployment supports public MCP clients
(PKCE), not long-lived MCP client secrets.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import tempfile
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import quote

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.shared.auth_utils import check_resource_allowed, resource_url_from_server_url

from colab_remote_mcp.config import MCP_SCOPE

AUTH_WINDOW_SECONDS = 30 * 60
CODE_SECONDS = 120
ACCESS_SECONDS = 3600
REFRESH_SECONDS = 30 * 24 * 3600
MAX_PENDING = 100


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def private_write(path: Path, text: str) -> None:
    """Atomically replace a file without retaining an insecure temporary copy."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise PermissionError("Private storage refuses symbolic links.")
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".write-", text=True)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _serialize_resource(resource: str | Any | None) -> str | None:
    return str(resource) if resource is not None else None


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise PermissionError("Private data directories must not be symbolic links.")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"Private data directory must have mode 0700: {path}")


class Store:
    """OAuth provider guarded by one per-process asyncio lock."""

    def __init__(self, data: Path, resource: str | None = None) -> None:
        private_directory(data)
        self.resource = resource_url_from_server_url(resource) if resource else None
        self.path = data / "state.json"
        self.lock = asyncio.Lock()
        if self.path.is_symlink() or (self.path.exists() and self.path.stat().st_mode & 0o077):
            raise PermissionError("OAuth state must be a regular mode-0600 file.")
        if self.path.exists() and not self.path.is_file():
            raise PermissionError("OAuth state must be a regular file.")
        content = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
        if not isinstance(content, dict):
            raise ValueError("Invalid OAuth state document.")
        self.data: dict[str, dict[str, Any]] = content
        for key in ("clients", "pending", "codes", "access", "refresh"):
            if not isinstance(self.data.setdefault(key, {}), dict):
                raise ValueError("Invalid OAuth state namespace.")
        self._prune_unlocked()
        self._save()

    def _save(self) -> None:
        # client_secret is never meant in this state file, even as public constants.
        private_write(self.path, json.dumps(self.data, separators=(",", ":")))

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[dict[str, dict[str, Any]]]:
        async with self.lock:
            before = deepcopy(self.data)
            try:
                yield self.data
                self._save()
            except BaseException:
                self.data.clear()
                self.data.update(before)
                raise

    def _prune_unlocked(self) -> None:
        now = time.time()
        self.data["pending"] = {
            key: value
            for key, value in self.data["pending"].items()
            if 0 <= now - value["created_at"] < AUTH_WINDOW_SECONDS
        }
        for kind in ("codes", "access", "refresh"):
            self.data[kind] = {
                key: value for key, value in self.data[kind].items() if value["expires_at"] > now
            }

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        async with self.lock:
            raw = self.data["clients"].get(client_id)
            return OAuthClientInformationFull(**raw) if raw else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        public_method = "none"  # noqa: S105 - OAuth public-client method, not a password
        if client_info.client_id is None or client_info.token_endpoint_auth_method != public_method:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description=(
                    "Only public PKCE clients are supported; explicitly register "
                    "token_endpoint_auth_method='none'. MCP 1.30.0 otherwise defaults "
                    "to a client-secret method."
                ),
            )
        if client_info.scope not in (None, MCP_SCOPE):
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="Only the 'colab' scope is supported.",
            )
        if not client_info.redirect_uris or any(url.fragment for url in client_info.redirect_uris):
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description="Client callbacks must be nonempty and contain no fragment.",
            )
        stored = client_info.model_copy(
            update={"client_id": client_info.client_id, "client_secret": None}
        )
        async with self.transaction() as data:
            # Random SDK-issued IDs make accidental collisions an error, not an update.
            if client_info.client_id in data["clients"]:
                raise RegistrationError(
                    error="invalid_client_metadata",
                    error_description="Client identifier is already registered.",
                )
            data["clients"][client_info.client_id] = stored.model_dump(mode="json")

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if set(params.scopes or [MCP_SCOPE]) != {MCP_SCOPE}:
            raise AuthorizeError(
                error="invalid_scope", error_description="Only the 'colab' scope is supported."
            )
        if client.client_id is None:
            raise AuthorizeError(
                error="invalid_request", error_description="Missing client identity."
            )
        resource = _serialize_resource(params.resource)
        if self.resource is not None:
            if resource is None or not check_resource_allowed(resource, self.resource):
                raise AuthorizeError(
                    error="invalid_request",
                    error_description="The resource indicator must name this MCP endpoint.",
                )
            resource = resource_url_from_server_url(resource)
        async with self.transaction() as data:
            self._prune_unlocked()
            if len(data["pending"]) >= MAX_PENDING:
                raise AuthorizeError(
                    error="temporarily_unavailable",
                    error_description=(
                        "Complete an existing Colab authorization window before retrying."
                    ),
                )
            if any(
                pending["client_id"] == client.client_id for pending in data["pending"].values()
            ):
                raise AuthorizeError(
                    error="temporarily_unavailable",
                    error_description=(
                        "This MCP client already has a Colab authorization window open."
                    ),
                )
            transaction = secrets.token_urlsafe(32)
            data["pending"][digest(transaction)] = {
                "client_id": client.client_id,
                "scopes": [MCP_SCOPE],
                "code_challenge": params.code_challenge,
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "resource": resource,
                "state": params.state,
                "created_at": time.time(),
                "subject": f"client:{digest(client.client_id)}",
            }
        return "/oauth/complete?state=" + quote(transaction, safe="")

    async def pending(self, transaction: str) -> dict[str, Any] | None:
        async with self.lock:
            raw = self.data["pending"].get(digest(transaction))
            if not raw or not 0 <= time.time() - raw["created_at"] < AUTH_WINDOW_SECONDS:
                return None
            return deepcopy(raw)

    async def finish_colab(self, transaction: str) -> tuple[str, dict[str, Any]] | None:
        """Consume one browser completion after its encrypted credential save succeeds."""
        code = secrets.token_urlsafe(32)
        async with self.transaction() as data:
            self._prune_unlocked()
            pending = data["pending"].pop(digest(transaction), None)
            if pending is None:
                return None
            record = AuthorizationCode(
                code=code,
                client_id=pending["client_id"],
                scopes=pending["scopes"],
                expires_at=time.time() + CODE_SECONDS,
                code_challenge=pending["code_challenge"],
                redirect_uri=pending["redirect_uri"],
                redirect_uri_provided_explicitly=pending["redirect_uri_provided_explicitly"],
                resource=pending.get("resource"),
                subject=pending["subject"],
            )
            data["codes"][digest(code)] = record.model_dump(mode="json")
            return code, pending

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        async with self.lock:
            raw = self.data["codes"].get(digest(authorization_code))
            if not raw or raw["client_id"] != client.client_id:
                return None
            return AuthorizationCode(**raw)

    async def discard_expired_code(self, code: AuthorizationCode) -> None:
        if code.expires_at >= time.time():
            return
        async with self.transaction() as data:
            if data["codes"].get(digest(code.code), {}).get("expires_at") == code.expires_at:
                data["codes"].pop(digest(code.code), None)

    def _issue_unlocked(
        self, client_id: str, subject: str, scopes: list[str], resource: str | None
    ) -> OAuthToken:
        access = secrets.token_urlsafe(48)
        refresh = secrets.token_urlsafe(48)
        issued = {
            "client_id": client_id,
            "scopes": scopes,
            "subject": subject,
            "resource": resource,
        }
        now = time.time()
        issued["token_family"] = uuid.uuid4().hex
        self.data["access"][digest(access)] = {
            **issued,
            "expires_at": int(now + ACCESS_SECONDS),
        }
        self.data["refresh"][digest(refresh)] = {
            **issued,
            "expires_at": int(now + REFRESH_SECONDS),
        }
        token_type = "Bearer"  # noqa: S105 - required OAuth token type, not a password
        return OAuthToken(  # noqa: S106 - required OAuthToken constructor argument
            access_token=access,
            token_type=token_type,
            expires_in=ACCESS_SECONDS,
            refresh_token=refresh,
            scope=" ".join(scopes),
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, code: AuthorizationCode
    ) -> OAuthToken:
        async with self.lock:
            record = self.data["codes"].get(digest(code.code))
            if record is None:
                raise TokenError(
                    error="invalid_grant", error_description="Authorization code was already used."
                )
            if record["client_id"] != client.client_id or code.expires_at < time.time():
                raise TokenError(
                    error="invalid_grant", error_description="Invalid authorization grant."
                )
            self.data["codes"].pop(digest(code.code))
            if not client.client_id or not code.subject:
                raise TokenError(
                    error="invalid_grant",
                    error_description="The authorization grant has no declared owner.",
                )
            result = self._issue_unlocked(
                client.client_id, code.subject, code.scopes, code.resource
            )
            self._save()
            return result

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        async with self.lock:
            raw = self.data["refresh"].get(digest(refresh_token))
            if not raw or raw["client_id"] != client.client_id or raw["expires_at"] <= time.time():
                return None
            return RefreshToken(token=refresh_token, **raw)

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        async with self.lock:
            record = self.data["refresh"].get(digest(refresh_token.token))
            if (
                record is None
                or record["client_id"] != client.client_id
                or refresh_token.expires_at is not None
                and refresh_token.expires_at < time.time()
            ):
                raise TokenError(
                    error="invalid_grant",
                    error_description="Refresh token was already rotated, expired, or revoked.",
                )
            previous_access = [
                key
                for key, value in self.data["access"].items()
                if value.get("token_family") == record.get("token_family")
                and value.get("client_id") == client.client_id
            ]
            for key in previous_access:
                self.data["access"].pop(key, None)
            self.data["refresh"].pop(digest(refresh_token.token))
            if not client.client_id or not refresh_token.subject:
                raise TokenError(
                    error="invalid_grant",
                    error_description="The refresh grant has no declared owner.",
                )
            result = self._issue_unlocked(
                client.client_id,
                refresh_token.subject,
                scopes,
                refresh_token.resource,
            )
            self._save()
            return result

    async def load_access_token(self, token: str) -> AccessToken | None:
        async with self.lock:
            raw = self.data["access"].get(digest(token))
            if (
                not raw
                or raw["expires_at"] <= time.time()
                or not isinstance(raw.get("subject"), str)
                or not raw["subject"]
            ):
                return None
            resource = _serialize_resource(raw.get("resource"))
            if self.resource is not None and resource != self.resource:
                # Do not authenticate a token minted for a different audience or a
                # missing resource, even when its client and scope are otherwise valid.
                return None
            return AccessToken(token=token, **raw)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        async with self.lock:
            selected = self.data["access"].get(digest(token.token)) or self.data["refresh"].get(
                digest(token.token)
            )
            family = selected.get("token_family") if selected else None
            for kind in ("access", "refresh"):
                for key, value in list(self.data[kind].items()):
                    if key == digest(token.token) or (
                        family is not None
                        and value.get("token_family") == family
                        and value.get("client_id") == token.client_id
                    ):
                        self.data[kind].pop(key, None)
            self._save()
