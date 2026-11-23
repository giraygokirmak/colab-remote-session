"""Validate a regular non-symlink 0600 passphrase before the server runs."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def validate(path: Path, *, euid: int | None = None) -> None:
    """Reject unsafe mounts without ever including their content in diagnostics."""
    try:
        if path.is_symlink():
            raise ValueError("The keyring passphrase mount must not be a symbolic link.")
        if not path.exists():
            raise ValueError(
                "Missing ./keyring.password. Follow the README recovery steps; "
                "no passphrase was read or displayed."
            )
        if not path.is_file():
            raise ValueError(
                "Keyring passphrase mount is not a file. Remove only its empty "
                "accidental mount directory, then provide ./keyring.password."
            )
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise ValueError(
                f"Keyring passphrase mode is 0{mode:o}; run chmod 600 "
                "./keyring.password on the host file."
            )
        effective_uid = os.geteuid() if euid is None and hasattr(os, "geteuid") else euid
        if effective_uid == 10001:
            owner = path.stat().st_uid
            if owner not in {0, 10001}:
                raise ValueError(
                    "Keyring passphrase belongs to a different uid; run "
                    "sudo chown 10001:10001 ./keyring.password on the host."
                )
        # Validate nonempty UTF-8, but never forward its value to argv or logs.
        lines = path.read_text(encoding="utf-8").splitlines()
        if not lines or not lines[0]:
            raise ValueError("Keyring passphrase file is empty.")
    except (OSError, UnicodeError):
        raise ValueError(
            "Keyring passphrase could not be read; use UTF-8 and ensure uid 10001 "
            "can read its mode-0600 file."
        ) from None


def main() -> None:
    path = Path(os.environ.get("MCP_KEYRING_PATH", "/run/secrets/keyring.password"))
    try:
        validate(path)
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from None
    # Both tools share the same installed script location with Docker/PyPI.
    os.execv(  # noqa: S606 - fixed interpreter plus a non-shell argument vector
        sys.executable, [sys.executable, "-m", "colab_remote_mcp", *sys.argv[1:]]
    )


if __name__ == "__main__":
    main()
