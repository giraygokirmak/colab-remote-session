"""Safe diagnostics at the keyring passphrase-file boundary."""

from __future__ import annotations

import importlib.util
from importlib.util import module_from_spec
from pathlib import Path

import pytest

from colab_remote_mcp.config import Config, ConfigurationError, parse_args, read_password_file


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


FORWARD_LISTENER_HOST = "0.0.0.0"  # noqa: S104 - explicit Docker forwarding fixture.


def test_docker_forwarding_preserves_loopback_public_origin() -> None:
    config = parse_args(
        [
            "--keyring-password",
            "fixture-only-secret",
            f"--host={FORWARD_LISTENER_HOST}",
            "--public-url=http://127.0.0.1:6012",
            "--allow-nonloopback-bind",
        ]
    )
    assert config.public_url == "http://127.0.0.1:6012"
    assert config.host == FORWARD_LISTENER_HOST
    assert config.port == 8000
    assert config.allow_nonloopback_bind


def test_nonloopback_bind_still_requires_an_explicit_opt_in() -> None:
    with pytest.raises(ConfigurationError, match="allow-nonloopback-bind"):
        Config(host=FORWARD_LISTENER_HOST, keyring_password="fixture-only-secret")


def load_entrypoint():
    location = Path(__file__).parent.parent / "docker-keyring-entrypoint.py"
    spec = importlib.util.spec_from_file_location("docker_keyring_entrypoint", location)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_volume_data_directory_is_secured_without_deleting_content(
    tmp_path: Path,
) -> None:
    entrypoint = load_entrypoint()
    marker = tmp_path / "state.json"
    marker.touch(mode=0o600)
    tmp_path.chmod(0o755)
    entrypoint.prepare_data_directory(tmp_path)
    assert tmp_path.stat().st_mode & 0o777 == 0o700
    assert marker.exists()
    entrypoint.prepare_data_directory(tmp_path)
    assert marker.exists()


def test_volume_data_directory_does_not_claim_another_users_mount(
    tmp_path: Path,
) -> None:
    entrypoint = load_entrypoint()
    tmp_path.chmod(0o755)
    other_uid = 1 if tmp_path.stat().st_uid != 1 else 2
    with pytest.raises(PermissionError, match="owned by another uid"):
        entrypoint.prepare_data_directory(tmp_path, euid=other_uid)
    assert tmp_path.stat().st_mode & 0o777 == 0o755


def test_volume_data_directory_rejects_symlink(tmp_path: Path) -> None:
    entrypoint = load_entrypoint()
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    symlink = tmp_path / "link"
    symlink.symlink_to(actual, target_is_directory=True)
    with pytest.raises(PermissionError, match="real directory"):
        entrypoint.prepare_data_directory(symlink)
    assert actual.stat().st_mode & 0o777 == 0o700


def test_volume_passphrase_is_created_once_and_reused(tmp_path: Path) -> None:
    entrypoint = load_entrypoint()
    entrypoint.prepare_data_directory(tmp_path)
    directory = tmp_path / "secrets"
    entrypoint.ensure_password(directory)
    path = directory / "keyring.password"
    original = path.read_bytes()
    assert original.splitlines()[0]
    assert path.stat().st_mode & 0o777 == 0o600
    entrypoint.ensure_password(directory)
    assert path.read_bytes() == original
    assert not path.is_symlink()
    assert not list(directory.glob("*.tmp"))


@pytest.mark.parametrize("kind", ["directory", "symlink", "insecure", "empty"])
def test_existing_unsafe_volume_passphrase_is_not_replaced(tmp_path: Path, kind: str) -> None:
    entrypoint = load_entrypoint()
    directory = tmp_path / "secrets"
    directory.mkdir(mode=0o700)
    path = directory / "keyring.password"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        destination = tmp_path / "other"
        destination.write_text("fixture-only-credential\n", encoding="utf-8")
        path.symlink_to(destination)
    elif kind == "insecure":
        path.write_text("fixture-only-credential\n", encoding="utf-8")
        path.chmod(0o644)
    else:
        path.write_text("", encoding="utf-8")
        path.chmod(0o600)
    before = path.lstat()
    with pytest.raises((OSError, ValueError)) as caught:
        entrypoint.ensure_password(directory)
    assert path.lstat().st_ino == before.st_ino
    assert "fixture-only-credential" not in str(caught.value)
    if kind in {"insecure", "empty"}:
        assert path.stat().st_mode & 0o777 == before.st_mode & 0o777
