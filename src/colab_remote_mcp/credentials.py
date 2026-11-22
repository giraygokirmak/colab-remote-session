"""Encrypted Colab credentials and the single interactive Google OAuth boundary."""

from __future__ import annotations

import json
import secrets
import threading
import time
from importlib import resources
from pathlib import Path
from typing import Any

from colab_cli.auth import KEYRING_SERVICE_NAME, KEYRING_USERNAME, PUBLIC_SCOPES
from google.auth.transport.requests import AuthorizedSession, Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from keyrings.alt.file import EncryptedKeyring

from colab_remote_mcp.keyring_backend import AgentKeyring
from colab_remote_mcp.store import private_directory

REMOTE_REDIRECT_URI = "https://sdk.cloud.google.com/applicationdefaultauthcode.html"
AUTH_WINDOW_SECONDS = 30 * 60


class AuthenticationRequired(RuntimeError):
    """No usable offline Colab credentials; the caller needs MCP /authorize."""


class CredentialsStore:
    """Only this class accesses Colab's keyring service/username record."""

    def __init__(self, root: Path, passphrase: str) -> None:
        private_directory(root)
        path = root / EncryptedKeyring.filename
        if path.is_symlink() or (
            path.exists() and (not path.is_file() or path.stat().st_mode & 0o077)
        ):
            raise PermissionError("Encrypted Colab keyring must be a regular mode-0600 file.")
        self._lock = threading.RLock()
        self._ring = AgentKeyring()
        self._ring.file_path = path
        self._ring.keyring_key = passphrase
        self._ring._get_crypto_impl()
        if path.exists():
            try:
                marker = self._ring.get_password("colab-remote-mcp", "keyring-integrity")
                reference = self._ring.get_password("keyring-setting", "password reference")
                if marker != "verified" or reference != "password reference value":
                    raise ValueError("Invalid encrypted keyring markers.")
                self._get()
            except Exception as error:
                raise ValueError(
                    "Could not unlock or validate the encrypted Colab keyring."
                ) from error
        else:
            # Standard keyrings.alt reference, initialized explicitly without getpass.
            self._ring.set_password(
                "keyring-setting", "password reference", "password reference value"
            )
            self._ring._write_config_value("keyring-setting", "scheme", self._ring.scheme)
            self._ring._write_config_value("keyring-setting", "version", self._ring.version)
            self._ring.set_password("colab-remote-mcp", "keyring-integrity", "verified")
            path.chmod(0o600)

    @property
    def path(self) -> Path:
        return self._ring.explicit_file_path

    def _get(self) -> str | None:
        return self._ring.get_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME)

    def available(self) -> bool:
        with self._lock:
            return self._get() is not None

    def _read(self) -> Credentials:
        with self._lock:
            serialized = self._get()
        if not serialized:
            raise AuthenticationRequired(
                "No Colab credentials are in the encrypted keyring. "
                "Reconnect MCP for its one Google authorization."
            )
        try:
            content = json.loads(serialized)
            credentials = Credentials.from_authorized_user_info(content, PUBLIC_SCOPES)
        except (TypeError, ValueError, KeyError) as error:
            raise AuthenticationRequired(
                "The stored Colab credential record is invalid."
            ) from error
        if not credentials.refresh_token:
            raise AuthenticationRequired("Stored Colab credentials have no offline refresh token.")
        return credentials

    def _save_unlocked(self, credentials: Credentials) -> None:
        if not credentials.refresh_token or not credentials.token:
            raise ValueError("Google did not provide complete offline Colab credentials.")
        self._ring.set_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME, credentials.to_json())
        self.path.chmod(0o600)

    def save(self, credentials: Credentials) -> None:
        with self._lock:
            self._save_unlocked(credentials)
            self._read()

    def sessions(self) -> AuthorizedSession:
        """Use only keyring credentials, never colab_cli's interactive auth fallback."""
        with self._lock:
            credentials = self._read()
            if not credentials.valid:
                if not credentials.expired:
                    raise AuthenticationRequired(
                        "Stored Colab credentials are not valid for a request."
                    )
                credentials.refresh(Request())
                self._save_unlocked(credentials)
            return _PersistingAuthorizedSession(self, credentials)


class _PersistingAuthorizedSession(AuthorizedSession):
    """Persist a refresh performed by google-auth during a Colab API request."""

    def __init__(self, store: CredentialsStore, credentials: Credentials) -> None:
        self._owner_store = store
        self._last_saved_token = credentials.token
        super().__init__(credentials)

    def request(self, method: str, url: str, *args: Any, **kwargs: Any) -> Any:
        with self._owner_store._lock:
            response = super().request(method, url, *args, **kwargs)
            if self.credentials.token != self._last_saved_token and self.credentials.token:
                self._owner_store._save_unlocked(self.credentials)
                self._last_saved_token = self.credentials.token
            return response


class ColabAuthorization:
    """Every pending MCP browser transaction has its own inner Gemini-looking flow."""

    def __init__(self, credentials: CredentialsStore) -> None:
        self.credentials = credentials
        self._lock = threading.RLock()
        self._flows: dict[str, InstalledAppFlow] = {}
        self._authorization_urls: dict[str, str] = {}
        self._created_at: dict[str, float] = {}

    def begin(self, state: str) -> str:
        with self._lock:
            self._prune_unlocked()
            if state in self._authorization_urls:
                return self._authorization_urls[state]
            config = json.loads(
                resources.files("colab_cli")
                .joinpath("oauth_config.json")
                .read_text(encoding="utf-8")
            )
            flow = InstalledAppFlow.from_client_config(config, PUBLIC_SCOPES)
            flow.redirect_uri = REMOTE_REDIRECT_URI
            flow.code_verifier = secrets.token_urlsafe(64)
            url, returned_state = flow.authorization_url(
                access_type="offline",
                include_granted_scopes="false",
                prompt="consent",
                state=state,
                token_usage="remote",  # noqa: S106 - remote installs the SDK's code page
            )
            if returned_state != state:
                raise ValueError("Google OAuth state did not match the MCP transaction.")
            self._flows[state] = flow
            self._authorization_urls[state] = url
            self._created_at[state] = time.time()
            return url

    def complete(self, state: str, code: str) -> None:
        with self._lock:
            self._prune_unlocked()
            flow = self._flows.get(state)
            if flow is None:
                raise ValueError("This Colab browser transaction is not active.")
            try:
                flow.fetch_token(code=code)
                self.credentials.save(flow.credentials)
            except Exception:
                # GET on the same pending MCP page creates a fresh inner flow.
                self._discard_unlocked(state)
                raise
            self._discard_unlocked(state)

    def discard(self, state: str) -> None:
        with self._lock:
            self._discard_unlocked(state)

    def _discard_unlocked(self, state: str) -> None:
        flow = self._flows.pop(state, None)
        self._authorization_urls.pop(state, None)
        self._created_at.pop(state, None)
        if flow is not None:
            try:
                flow.oauth2session.close()
            except OSError:
                pass

    def _prune_unlocked(self) -> None:
        for state, created in list(self._created_at.items()):
            if time.time() - created >= AUTH_WINDOW_SECONDS:
                self._discard_unlocked(state)
