"""Encrypted file-keyring refresh tests with no host or Google credential access."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials

from colab_remote_mcp.credentials import AuthenticationRequired, CredentialsStore
from colab_remote_mcp.executor import safe_error
from colab_remote_mcp.keyring_backend import AgentKeyring, generate
from colab_remote_mcp.privacy import redact


def fixture_credentials(token: str, *, expired: bool = False) -> Credentials:
    return Credentials(
        token=token,
        refresh_token="fixture-only-refresh-token",
        token_uri="https://oauth2.example.test/token",
        client_id="fixture-only-client-id",
        client_secret="fixture-only-client-secret",
        scopes=["https://www.googleapis.com/auth/colaboratory"],
        expiry=datetime.now(UTC) + (timedelta(minutes=-5 if expired else 30)),
    )


def test_encrypted_keyring_and_local_refresh_persist_no_host_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "empty-home"))
    generate(tmp_path / "passwords")
    passphrase = (tmp_path / "passwords" / "keyring.password").read_text().strip()
    store = CredentialsStore(tmp_path / "encrypted", passphrase)
    store.save(fixture_credentials("old-token", expired=True))

    def refresh(credentials: Credentials, request: object) -> None:
        assert isinstance(credentials, Credentials)
        assert request is not None
        credentials.token = "refreshed-fixture-token"
        credentials.expiry = datetime.now(UTC) + timedelta(hours=1)

    monkeypatch.setattr(Credentials, "refresh", refresh)
    session = store.sessions()
    assert session.credentials.token == "refreshed-fixture-token"
    session.close()
    # Mis-tampering/auth failures are represented as fixed client-safe messages.
    reopened = CredentialsStore(tmp_path / "encrypted", passphrase)
    stored_serialized = reopened._get()
    assert stored_serialized is not None
    assert stored_serialized == reopened._ring.get_password("google-colab-cli", "oauth_token")
    assert json.loads(stored_serialized)["token"] == "refreshed-fixture-token"

    ring = AgentKeyring()
    ring.file_path = tmp_path / "encrypted" / "crypted_pass.cfg"
    ring.keyring_key = passphrase
    assert "refreshed-fixture-token" in str(ring.get_password("google-colab-cli", "oauth_token"))
    raw = reopened.path.read_bytes()
    assert b"refreshed-fixture-token" not in raw
    assert b"fixture-only-refresh-token" not in raw
    assert reopened.path.stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError, match="unlock or validate"):
        CredentialsStore(tmp_path / "encrypted", "incorrect-only-test-passphrase")


def test_keyring_missing_and_refresh_failures_are_stable(tmp_path: Path) -> None:
    store = CredentialsStore(tmp_path / "encrypted", "fixture-passphrase")
    with pytest.raises(AuthenticationRequired):
        store.sessions()
    assert "credentials" in safe_error(AuthenticationRequired())
    store.save(fixture_credentials("old-token", expired=True))

    def fail(credentials: Credentials, request: object) -> None:
        raise RefreshError("Bearer sensitive-token should never be exposed")

    import colab_remote_mcp.credentials as module

    module_authenticate = module.Credentials.refresh
    module.Credentials.refresh = fail  # type: ignore[method-assign]
    try:
        with pytest.raises(RefreshError):
            store.sessions()
    finally:
        module.Credentials.refresh = module_authenticate  # type: ignore[method-assign]
    assert "sensitive-token" not in safe_error(RefreshError("Bearer sensitive-token"))
    assert redact("Bearer sensitive-token\nrefresh_token=another").count("REDACTED") == 2


def test_google_flow_replaces_failed_transaction_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from colab_remote_mcp.credentials import ColabAuthorization

    class Flow:
        instances: list[Flow] = []
        close_count = 0

        def __init__(self) -> None:
            self.code_verifier = None
            self.redirect_uri = None
            self.credentials = object()
            self.oauth2session = self

        @classmethod
        def from_client_config(cls, config: dict, scopes: list[str]) -> Flow:
            assert isinstance(config, dict)
            from colab_cli.auth import PUBLIC_SCOPES

            assert scopes == PUBLIC_SCOPES
            assert "https://www.googleapis.com/auth/colaboratory" in scopes
            instance = cls()
            cls.instances.append(instance)
            return instance

        def authorization_url(self, **options: object) -> tuple[str, str]:
            assert options["access_type"] == "offline"
            assert options["prompt"] == "consent"
            state = str(options["state"])
            return "https://accounts.example.test/authorize?state=" + state, state

        def fetch_token(self, code: str) -> None:
            if code != "accepted-fixture-code":
                raise ValueError("Invalid fake Google code")

        def close(self) -> None:
            Flow.close_count += 1

    class Sink:
        def __init__(self) -> None:
            self.saved: list[object] = []

        def save(self, value: object) -> None:
            self.saved.append(value)

    monkeypatch.setattr(
        "colab_remote_mcp.credentials.resources.files",
        lambda _name: Path(tmp_path),
    )
    (tmp_path / "oauth_config.json").write_text(
        '{"installed":{"client_id":"fixture-only"}}', encoding="utf-8"
    )
    monkeypatch.setattr("colab_remote_mcp.credentials.InstalledAppFlow", Flow)
    sink = Sink()
    authorization = ColabAuthorization(sink)  # type: ignore[arg-type]
    first = authorization.begin("first-local-state")
    second = authorization.begin("second-local-state")
    assert "first-local-state" in first
    assert "second-local-state" in second
    assert all(
        flow.redirect_uri.endswith("applicationdefaultauthcode.html") for flow in Flow.instances
    )
    assert all(flow.code_verifier for flow in Flow.instances)
    with pytest.raises(ValueError):
        authorization.complete("first-local-state", "rejected")
    assert sink.saved == []
    authorization.complete("second-local-state", "accepted-fixture-code")
    assert sink.saved == [Flow.instances[1].credentials]
    assert authorization._flows == {}
    assert Flow.close_count == 2


def test_no_colab_keyring_exposed_as_mcp_resources() -> None:
    import inspect

    import colab_remote_mcp.server as server

    source = inspect.getsource(server.create_server)
    assert 'name="captured_colab_output"' in source
    assert "keyring" not in source[source.index("async def download_file") :]
