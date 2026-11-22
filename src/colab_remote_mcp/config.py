"""Server configuration; no credentials are read from environment variables."""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
from urllib.parse import urlsplit

MCP_SCOPE = "colab"
DEFAULT_DATA = Path("/data")
DEFAULT_HOST = "127.0.0.1"


class ConfigurationError(ValueError):
    pass


class Config(argparse.Namespace):
    public_url: str
    host: str
    port: int
    keyring_password: str | None
    keyring_root: Path
    data: Path
    proxy_headers: bool

    def __init__(
        self,
        public_url: str = "http://127.0.0.1:8000",
        host: str = DEFAULT_HOST,
        port: int = 8000,
        keyring_password: str | None = None,
        keyring_root: Path | None = None,
        data: Path | None = None,
        proxy_headers: bool = False,
    ) -> None:
        value = public_url.rstrip("/")
        parts = urlsplit(value)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
            or parts.path not in {"", "/"}
        ):
            raise ConfigurationError(
                "Public URL must be an HTTP(S) origin, without path or userinfo."
            )
        loopback = parts.hostname in {"localhost", "127.0.0.1", "::1"}
        if parts.scheme != "https" and not loopback:
            raise ConfigurationError(
                "Nonloopback deployment requires HTTPS through a reverse proxy."
            )
        if loopback and host != DEFAULT_HOST:
            raise ConfigurationError(
                "Loopback public URL cannot be bound to a nonloopback address."
            )
        if not loopback and not proxy_headers:
            raise ConfigurationError(
                "HTTPS origin requires --proxy-headers behind its trusted TLS proxy."
            )
        if not 0 < port < 65536:
            raise ConfigurationError("Port must be between 1 and 65535.")
        self.public_url = value
        self.host = host
        self.port = port
        self.keyring_password = keyring_password
        self.keyring_root = keyring_root or (data or DEFAULT_DATA) / "secrets" / "keyring"
        self.data = data or DEFAULT_DATA
        self.proxy_headers = proxy_headers


def _validate_binding(host: str) -> None:
    try:
        ipaddress.ip_address(host)
    except ValueError as error:
        raise ConfigurationError("Bind address must be a literal IP address.") from error


def parse_args(argv: list[str] | None = None) -> Config:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--public-url",
        default=os.getenv("MCP_PUBLIC_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument("--host", default=os.getenv("MCP_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.getenv("MCP_PORT", "8000")))
    parser.add_argument("--data", type=Path, default=Path(os.getenv("MCP_DATA", str(DEFAULT_DATA))))
    parser.add_argument("--proxy-headers", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--keyring-password",
        help=(
            "Local keyring passphrase; avoid exposing this in command history or process listings."
        ),
    )
    group.add_argument("--keyring-password-stdin", action="store_true")
    group.add_argument("--keyring-password-file", type=Path)
    parser.add_argument("--keyring-root", type=Path)
    options = parser.parse_args(argv)

    _validate_binding(options.host)
    password: str | None = options.keyring_password
    if options.keyring_password_stdin:
        import sys

        password = sys.stdin.readline().rstrip("\r\n")
    elif options.keyring_password_file:
        path = options.keyring_password_file.expanduser()
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
            raise ConfigurationError(
                "Passphrase input must be a regular mode-0600 non-symlink file."
            )
        password = path.read_text(encoding="utf-8").splitlines()[0]
    if password is None:
        raise ConfigurationError(
            "Provide a local keyring passphrase once using --keyring-password-file or "
            "--keyring-password-stdin. It is not a Google or MCP token."
        )
    if not password:
        raise ConfigurationError("Keyring passphrase cannot be empty.")
    return Config(
        public_url=options.public_url,
        host=options.host,
        port=options.port,
        keyring_password=password,
        keyring_root=options.keyring_root,
        data=options.data.expanduser(),
        proxy_headers=options.proxy_headers,
    )
