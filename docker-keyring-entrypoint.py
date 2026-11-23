"""Create/reuse the private volume-held passphrase, then start the MCP server."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from colab_remote_mcp.config import read_password_file
from colab_remote_mcp.store import private_directory

PASSWORD_PATH = Path("/data/secrets/keyring.password")


def prepare_data_directory(path: Path, *, euid: int | None = None) -> None:
    """Secure the volume root without deleting or moving any existing content."""
    if path.is_symlink() or not path.is_dir():
        raise PermissionError("The persistent data mount must be a real directory.")
    effective_uid = os.geteuid() if euid is None else euid
    if effective_uid != 0 and path.stat().st_uid != effective_uid:
        raise PermissionError("The persistent data mount is owned by another uid.")
    path.chmod(0o700, follow_symlinks=False)
    private_directory(path)


def validate_existing(path: Path) -> None:
    if not read_password_file(path):
        raise ValueError("Volume-held keyring passphrase must not be empty.")


def ensure_password(directory: Path) -> None:
    """Create exactly one random passphrase on a fresh writable private volume.

    Retries reuse the existing file rather than generating another key. No value
    enters argv, environment variables, logs, process listings or MCP output.
    """
    private_directory(directory)
    path = directory / "keyring.password"
    terminal_flags = os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | terminal_flags,
            0o600,
        )
    except FileExistsError:
        # Reuse a real regular 0600 file, or stop safely at its boundary.
        validate_existing(path)
        return
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(secrets.token_urlsafe(48) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # Do not leave a partial/corrupt passphrase that would permanently
        # separate any subsequently encrypted Google credentials from its key.
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise
    # Re-read using the same safe validation as the non-generating application.
    validate_existing(path)


def main() -> None:
    path = PASSWORD_PATH
    try:
        prepare_data_directory(path.parent.parent)
        ensure_password(path.parent)
    except (OSError, ValueError):
        # Storage errors can contain sensitive paths or data. Fixed safe text only.
        print(
            "Could not secure /data or create the volume-held keyring passphrase. "
            "Run the one-time root ownership repair documented in README.md when "
            "upgrading an older volume; its existing files are preserved.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    os.execv(  # noqa: S606 - fixed interpreter plus a non-shell argument vector
        sys.executable,
        [
            sys.executable,
            "-m",
            "colab_remote_mcp",
            "--keyring-password-file",
            str(path),
            *sys.argv[1:],
        ],
    )


if __name__ == "__main__":
    main()
