"""Job input, artifact integrity, ownership and restart invariants."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from colab_remote_mcp.executor import pip_code
from colab_remote_mcp.jobs import (
    ExportRequest,
    Job,
    JobError,
    JobManager,
    validate_run,
)


class UnusedExecutor:
    async def run(self, job: Job, code: str, **options: Any) -> None:
        raise AssertionError("Restart and validation tests must not allocate a runtime.")

    async def request_cancel(self, job: Job) -> None:
        job.cancelled.set()


def make_job(tmp_path: Path, owner: str = "client:one") -> Job:
    directory = tmp_path / "jobs" / uuid4().hex
    directory.mkdir(parents=True, mode=0o700)
    directory.parent.chmod(0o700)
    directory.chmod(0o700)
    job = Job(directory.name, directory, owner, "cpu")
    return job


@pytest.mark.parametrize(
    "requirements",
    [
        ["--index-url=https://packages.example.test/simple", "numpy"],
        ["--requirement=private.txt"],
        ["-e", "git+https://example.test/repo"],
        ["https://user:password@example.test/package.whl"],
        ["package@sha256:abcd"],
        ["../../../etc/passwd"],
        ["numpy @ https://example.test/numpy.whl"],
        [r"C:\\secret\\package.whl"],
    ],
)
def test_requirements_disable_pip_options_urls_and_local_paths(
    requirements: list[str],
) -> None:
    with pytest.raises(JobError):
        validate_run("print('remote')", requirements)
    with pytest.raises(JobError):
        validate_run("print('remote')", requirements + ["--dry-run"])


@pytest.mark.parametrize(
    "requirements",
    [
        ["numpy==2.4.2"],
        ["torch>=2.6,<3", "transformers[sentencepiece]"],
        ["numpy==2.4.2; python_version >= '3.12'"],
    ],
)
def test_named_requirements_are_passed_as_literal_arguments(
    requirements: list[str],
) -> None:
    validate_run("print('remote')", requirements)
    remote = pip_code(requirements)
    assert "--" in remote
    for value in requirements:
        assert repr(value) in remote


@pytest.mark.parametrize(
    "export",
    [
        "/content/output/../secret",
        "/content/output//double",
        "/content/other/answer.txt",
        "/content/output/answer.txt\\..\\secret",
        "/content/output/über.txt",
    ],
)
def test_export_path_is_strict(export: str) -> None:
    with pytest.raises(JobError):
        ExportRequest(1, export)


async def test_artifact_hash_owner_and_restart_are_enforced(tmp_path: Path) -> None:
    job = make_job(tmp_path)
    request = ExportRequest(1, "/content/output/result.txt")
    staged = job.export_path(request)
    staged.write_text("remote output\n", encoding="utf-8")
    record = job.finish_export(request, staged)
    await job.event("artifact", {"artifact": record})
    job.status = "running"
    job.save()

    (job.files / record["name"]).write_text("tampered\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        job.read_file(record["name"])

    # Restore independently recomputes the SHA-256 rather than trusting the event.
    (tmp_path / "restored-root").mkdir()
    (tmp_path / "jobs").rename(tmp_path / "restored-root" / "jobs")

    moved = tmp_path / "restored-root" / "jobs" / job.id
    (moved / "files" / record["name"]).write_text("tampered\n", encoding="utf-8")
    manager = JobManager(tmp_path / "restored-root", UnusedExecutor())
    restored = manager.authorized("client:one", job.id)
    assert restored.status == "failed"
    assert restored.cleanup == {
        "unassigned": False,
        "reason": "The ephemeral runtime handle was not persisted.",
    }
    assert record["name"] not in restored.artifacts
    assert not (restored.files / record["name"]).exists()
    with pytest.raises(JobError):
        manager.authorized("client:another", job.id)


async def test_orphan_file_and_truncated_final_event_are_not_exposed(tmp_path: Path) -> None:
    job = make_job(tmp_path)
    request = ExportRequest(1, "/content/output/result.txt")
    staged = job.export_path(request)
    staged.write_text("üretim ✓\n", encoding="utf-8")
    record = job.finish_export(request, staged)
    await job.event("status", {"status": "completed"})
    await job.event("artifact", {"artifact": record})
    job.status = "completed"
    job.save()
    (job.files / ".download-partial").write_text("not announced", encoding="utf-8")
    (job.files / "unannounced.txt").write_text("not announced", encoding="utf-8")

    manager = JobManager(tmp_path, UnusedExecutor())
    restored = manager.authorized("client:one", job.id)
    assert restored.read_file(record["name"])[0].decode("utf-8") == "üretim ✓\n"
    assert restored.read_file(record["name"])[1] == "text/plain"
    assert not (restored.files / ".download-partial").exists()
    assert not (restored.files / "unannounced.txt").exists()

    with job.event_path.open("ab") as stream:
        stream.write(b'{"seq": 3, "kind": "stdou')
    reread = JobManager(tmp_path, UnusedExecutor()).authorized("client:one", job.id)
    assert len(reread.records) == 2
    assert reread.status == "completed"
    await reread.event("stdout", {"text": "valid after restart"})
    assert reread.records[-1]["seq"] == 3
    restarted = JobManager(tmp_path, UnusedExecutor()).authorized("client:one", job.id)
    assert restarted.records[-1]["text"] == "valid after restart"
    assert restarted.event_path.read_bytes().endswith(b'"valid after restart"}\n')

    # Aligning the metadata cursor cannot make a syntactically torn event valid.
    metadata = json.loads((job.directory / "job.json").read_text(encoding="utf-8"))
    metadata["last_event_seq"] = 3
    (job.directory / "job.json").write_text(json.dumps(metadata), encoding="utf-8")
    with job.event_path.open("ab") as stream:
        stream.write(b'{"seq": 3, "kind": "stale"}')
    assert JobManager(tmp_path, UnusedExecutor()).jobs == {}


async def test_event_log_integrity_and_cursor_type_checks(tmp_path: Path) -> None:
    job = make_job(tmp_path)
    await job.event("stdout", {"text": "safe fixture"})
    job.status = "completed"
    job.save()
    with job.event_path.open("ab") as stream:
        stream.write(b'{"seq":2,"kind":"status","status":"completed"}\nnot-json\n')
    assert JobManager(tmp_path, UnusedExecutor()).jobs == {}
    for arguments in (
        {"after": True},
        {"limit": True},
        {"wait_seconds": True},
        {"wait_seconds": float("nan")},
        {"wait_seconds": float("inf")},
        {"limit": 0},
        {"after": len(job.records) + 1},
    ):
        with pytest.raises(JobError):
            await job.response(**arguments)


def test_inline_output_binary_passthrough(tmp_path: Path) -> None:
    from colab_remote_mcp.outputs import decode_base64, output_events, text

    job = make_job(tmp_path)
    assert text("ü🙂") == "ü🙂"
    assert text("ü🙂" * 100_000).encode("utf-8")
    assert decode_base64("not base64!") is None
    assert output_events({"output_type": "display_data", "data": {}}, job) == []
    blob = b"\x00\xff\xfe"
    import base64

    events = output_events(
        {"output_type": "display_data", "data": {"image/png": base64.b64encode(blob).decode()}},
        job,
    )
    artifact = events[0][1]["artifact"]
    assert hashlib.sha256(job.read_file(artifact["name"])[0]).hexdigest() == artifact["sha256"]
    assert job.read_file(artifact["name"])[0] == blob
