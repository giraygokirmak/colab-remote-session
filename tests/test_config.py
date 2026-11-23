"""Safe diagnostics at the keyring passphrase-file boundary."""

from __future__ import annotations

import importlib.util
from importlib.util import module_from_spec
from pathlib import Path

import pytest

from colab_remote_mcp.config import ConfigurationError, parse_args, read_password_file


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("missing", "Passphrase file is missing"),
        ("directory", "Passphrase input is not a regular file"),
        ("symlink", "must not be a symbolic link"),
        ("insecure", "mode 0644"),
        ("non_utf8", "Passphrase file could not be read"),
        ("empty", "Keyring passphrase cannot be empty"),
    ],
)
def test_password_file_rejects_unsafe_or_unreadable_input(
    tmp_path: Path, kind: str, expected: str
) -> None:
    path = tmp_path / "keyring.password"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        (tmp_path / "destination").write_text("fixture-only-secret\n", encoding="utf-8")
        path.symlink_to(tmp_path / "destination")
    elif kind == "empty":
        path.write_text("\n", encoding="utf-8")
        path.chmod(0o600)
    elif kind == "non_utf8":
        path.write_bytes(b"\xff\xfe")
        path.chmod(0o600)
    elif kind != "missing":
        path.write_text("fixture-only-secret\n", encoding="utf-8")
    if kind == "insecure":
        path.chmod(0o644)

    with pytest.raises(ConfigurationError) as caught:
        parse_args(["--keyring-password-file", str(path)])
    assert expected in str(caught.value)
    assert "fixture-only-secret" not in str(caught.value)


def test_password_file_reads_valid_protected_input(tmp_path: Path) -> None:
    path = tmp_path / "keyring.password"
    path.write_text("fixture-only-secret\n", encoding="utf-8")
    path.chmod(0o600)
    config = parse_args(["--keyring-password-file", str(path)])
    assert config.keyring_password == "fixture-only-secret"
    assert read_password_file(path) == "fixture-only-secret"


async def test_docker_entrypoint_validation_is_actionable_and_secret_free(
    tmp_path: Path,
) -> None:
    location = Path(__file__).parent.parent / "docker-keyring-entrypoint.py"
    spec = importlib.util.spec_from_file_location("docker_keyring_entrypoint", location)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    validate = module.validate

    regular = tmp_path / "regular"
    regular.write_text("fixture-only-secret\n", encoding="utf-8")
    regular.chmod(0o600)
    for euid in (None, 10001):
        if euid == 10001 and regular.stat().st_uid not in {0, 10001}:
            with pytest.raises(ValueError, match="chown 10001:10001") as caught:
                validate(regular, euid=euid)
        else:
            validate(regular, euid=euid)
            break
    regular.chmod(0o644)
    with pytest.raises(ValueError, match="chmod 600") as caught:
        validate(regular, euid=10001)
    assert "fixture-only-secret" not in str(caught.value)
