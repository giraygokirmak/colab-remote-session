"""Explicit encrypted file keyring with noninteractive daemon unlock."""

from __future__ import annotations

import argparse
import os
import secrets
from pathlib import Path

from keyrings.alt.file import EncryptedKeyring


class AgentKeyring(EncryptedKeyring):
    """Use keyrings.alt encryption with a passphrase supplied exactly once.

    Failure is explicit instead of falling back to getpass, Secret Service,
    plaintext files, or the host user's keyring.
    """

    priority = 5

    @property
    def file_path(self) -> str:  # type: ignore[override]
        return str(self.explicit_file_path)

    @file_path.setter
    def file_path(self, value: str | Path) -> None:
        self.explicit_file_path = Path(value)

    @property
    def keyring_key(self) -> str:  # type: ignore[override]
        return self.explicit_passphrase

    @keyring_key.setter
    def keyring_key(self, value: str) -> None:
        self.explicit_passphrase = value

    def _check_file(self) -> bool:
        return self.explicit_file_path.exists()

    def _init_file(self) -> None:
        # Encryption uses the explicitly provided passphrase on first use.
        return None

    def _unlock(self) -> None:
        return None


def generate(directory: Path) -> None:
    """Generate a new independent passphrase, never print the value itself."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink():
        raise ValueError("Passphrase destination cannot be a symbolic link.")
    path = directory / "keyring.password"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(secrets.token_urlsafe(48) + "\n")
    print(str(path))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("generate").add_argument("directory", type=Path)
    subcommands.add_parser("status")
    arguments = parser.parse_args()
    if arguments.command == "generate":
        generate(arguments.directory)
    else:
        print("Encrypted file keyring; Colab credentials are never displayed.")


if __name__ == "__main__":
    main()
