"""Executable contract tests for the Colab executor adapter.

The runtime/client/contents doubles are deliberately synchronous, just like
``google-colab-cli``.  They provide outputs to the SDK's output hook rather
than returning jobs or coroutines.  No test creates a Colab session.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from colab_remote_mcp.executor import ColabExecutor, Handle
from colab_remote_mcp.jobs import Job


class FakeRuntime:
    def __init__(
        self,
        outputs: list[dict[str, Any]] | None = None,
        *,
        error: BaseException | None = None,
    ) -> None:
        self.outputs = outputs or []
        self.error = error
        self.executions: list[dict[str, Any]] = []
        self.stop_calls: list[dict[str, Any]] = []

    def execute_code(
        self,
        code: str,
        *,
        allow_stdin: bool = False,
        stdin_hook: Any = None,
        output_hook: Any = None,
        timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        self.executions.append(
            {
                "code": code,
                "allow_stdin": allow_stdin,
                "stdin_hook": stdin_hook,
                "timeout": timeout,
                "thread_id": threading.get_ident(),
            }
        )
        for output in self.outputs:
            output_hook(output)
        if self.error is not None:
            raise self.error
        return self.outputs

    def stop(self, shutdown_kernel: bool = False) -> None:
        self.stop_calls.append(
            {
                "shutdown_kernel": shutdown_kernel,
                "thread_id": threading.get_ident(),
            }
        )


class FakeClient:
    def __init__(self) -> None:
        self.unassign_calls: list[dict[str, Any]] = []

    def unassign(self, endpoint: str) -> None:
        self.unassign_calls.append({"endpoint": endpoint, "thread_id": threading.get_ident()})


class FakeContents:
    def __init__(self, files: dict[str, bytes] | None = None) -> None:
        self.files = files or {}
        self.download_calls: list[dict[str, Any]] = []

    def download(self, remote_path: str, local_path: str) -> None:
        self.download_calls.append(
            {
                "remote_path": remote_path,
                "local_path": local_path,
                "thread_id": threading.get_ident(),
            }
        )
        if remote_path not in self.files:
            raise FileNotFoundError(remote_path)
        Path(local_path).write_bytes(self.files[remote_path])


def make_handle(
    outputs: list[dict[str, Any]] | None = None,
    files: dict[str, bytes] | None = None,
) -> Handle:
    return Handle(
        client=FakeClient(),
        session=FakeSession(),
        runtime=FakeRuntime(outputs),
        contents=FakeContents(files),
        endpoint="assignment-endpoint",
    )


def make_job(tmp_path: Path) -> Job:
    job_id = uuid4().hex
    directory = tmp_path / job_id
    directory.mkdir(mode=0o700)
    return Job(job_id, directory, "test-owner", "cpu")


def events_of(job: Job, kind: str) -> list[dict[str, Any]]:
    return [event for event in job.records if event["kind"] == kind]


def assert_cleanup(job: Job) -> None:
    """A terminal status or finish event exposes the completed cleanup details."""
    assert job.records[-1]["kind"] in {"status", "finish"}
    if job.records[-1]["kind"] == "finish":
        assert job.records[-1].get("cleanup") == job.cleanup
    else:
        assert job.records[-1].get("status") == job.status
        # The dedicated event can precede the terminal status.
        assert len(cleanup_events := events_of(job, "cleanup")) == 1
        assert cleanup_events[0]["cleanup"] == job.cleanup


class FakeSession:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


async def wait_for_thread(event: threading.Event) -> None:
    assert await asyncio.wait_for(asyncio.to_thread(event.wait, 1), timeout=2), (
        "the synchronous SDK double was not called"
    )


async def test_streamed_output_image_export_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop_thread = threading.get_ident()
    image = b"\x89PNG\r\n\x1a\nsmall fake image bytes"
    exported = b"exported result\n"
    outputs = [
        {"output_type": "stream", "name": "stdout", "text": "first stdout\n"},
        {"output_type": "stream", "name": "stderr", "text": "diagnostic\n"},
        {
            "output_type": "display_data",
            "data": {"image/png": base64.b64encode(image).decode("ascii")},
        },
    ]
    handle = make_handle(outputs, {"/content/output/result.txt": exported})
    executor = ColabExecutor(object())
    monkeypatch.setattr(executor, "_allocate", lambda accelerator: handle)
    job = make_job(tmp_path)

    await asyncio.wait_for(
        executor.run(
            job,
            "print('first stdout')",
            idle_timeout_seconds=73,
            client_exports=["/content/output/result.txt"],
        ),
        timeout=3,
    )

    assert job.status == "completed", job.error
    assert job.error is None
    assert len(handle.runtime.executions) == 1
    execution = handle.runtime.executions[0]
    assert execution["thread_id"] != loop_thread
    assert execution["allow_stdin"] is False
    assert execution["stdin_hook"] is None
    assert execution["timeout"] == 73
    assert "print('first stdout')" in execution["code"]
    assert "os.makedirs" in execution["code"] or "_mcp_os.makedirs" in execution["code"]

    stdout, stderr = events_of(job, "stdout"), events_of(job, "stderr")
    assert [event["text"] for event in stdout] == ["first stdout\n"]
    assert [event["text"] for event in stderr] == ["diagnostic\n"]

    artifacts = events_of(job, "artifact")
    assert len(artifacts) == 2
    inline = artifacts[0]["artifact"]
    assert inline["mime_type"] == "image/png"
    assert inline["size"] == len(image)
    assert inline["sha256"] == hashlib.sha256(image).hexdigest()
    assert (job.files / inline["name"]).read_bytes() == image
    download = artifacts[1]["artifact"]
    assert download["name"] == "001__result.txt"
    assert download["size"] == len(exported)
    assert download["sha256"] == hashlib.sha256(exported).hexdigest()
    assert (job.files / download["name"]).read_bytes() == exported

    assert handle.contents.download_calls[0]["remote_path"] == "/content/output/result.txt"
    assert handle.contents.download_calls[0]["thread_id"] != loop_thread
    assert handle.runtime.stop_calls[0]["thread_id"] != loop_thread
    assert handle.client.unassign_calls[0]["thread_id"] != loop_thread
    assert job.id not in executor.handles
    assert job.cleanup is not None and job.cleanup["unassigned"] is True
    assert_cleanup(job)


@pytest.mark.parametrize(
    ("mode", "expected_error"),
    [
        ("kernel", "Agent Python failed"),
        ("exception", ""),
        ("export", "output file was not found"),
    ],
)
async def test_failure_still_unassigns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected_error: str,
) -> None:
    outputs: list[dict[str, Any]] = []
    if mode == "kernel":
        outputs = [
            {
                "output_type": "error",
                "ename": "ValueError",
                "evalue": "bad value",
                "traceback": ["\x1b[31mValueError\x1b[0m: bad value"],
            }
        ]
    remote = "/content/output/missing.txt"
    handle = make_handle(outputs, {remote: b"present"})
    if mode == "exception":
        handle.runtime.error = RuntimeError("upstream transport details")
    files = {} if mode == "export" else {remote: b"present"}
    handle.contents.files = files
    executor = ColabExecutor(object())
    monkeypatch.setattr(executor, "_allocate", lambda accelerator: handle)
    job = make_job(tmp_path)

    await asyncio.wait_for(
        executor.run(
            job,
            "do_work()",
            idle_timeout_seconds=30,
            client_exports=[remote],
        ),
        timeout=3,
    )

    assert job.status == "failed"
    assert expected_error in (job.error or "")
    if mode == "kernel":
        assert [event["ename"] for event in events_of(job, "error")] == ["ValueError"]
        assert "\x1b" not in events_of(job, "error")[0]["text"]
    if mode == "exception":
        assert "upstream transport details" not in (job.error or "")
        assert (job.error or "").startswith("Colab allocation, connection")
    if mode == "export":
        assert len(handle.contents.download_calls) == 1
    assert handle.runtime.stop_calls[0]["shutdown_kernel"] is True
    assert len(handle.runtime.stop_calls) == 1
    assert [call["endpoint"] for call in handle.client.unassign_calls] == [handle.endpoint]
    assert job.id not in executor.handles
    assert job.cleanup is not None and job.cleanup["unassigned"] is True
    assert_cleanup(job)


async def test_repeated_cancel_during_assignment_cleans_late_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop_thread = threading.get_ident()
    handle = make_handle([{"output_type": "stream", "name": "stdout", "text": "must not execute"}])
    started = threading.Event()
    release = threading.Event()

    def allocate(accelerator: str) -> Handle:
        started.set()
        assert release.wait(2), "test did not release allocation"
        return handle

    executor = ColabExecutor(object())
    monkeypatch.setattr(executor, "_allocate", allocate)
    job = make_job(tmp_path)
    run_task = asyncio.create_task(
        executor.run(job, "do_work()", idle_timeout_seconds=30),
        name="test-cancel-during-assignment",
    )
    await wait_for_thread(started)

    await asyncio.gather(*(executor.request_cancel(job) for _ in range(4)))
    assert job.cancelled.is_set()
    assert not run_task.done(), "allocation is synchronous and cannot be abandoned"

    release.set()
    await asyncio.wait_for(run_task, timeout=3)

    assert job.status == "cancelled"
    assert not handle.runtime.executions
    assert handle.runtime.stop_calls[0]["shutdown_kernel"] is True
    assert len(handle.runtime.stop_calls) == 1
    assert [call["endpoint"] for call in handle.client.unassign_calls] == [handle.endpoint]
    for call in handle.runtime.stop_calls + handle.client.unassign_calls:
        assert call["thread_id"] != loop_thread
    assert job.id not in executor.handles
    assert job.cleanup is not None and job.cleanup["unassigned"] is True
    assert_cleanup(job)

    await asyncio.gather(*(executor.request_cancel(job) for _ in range(3)))
    assert len(handle.runtime.stop_calls) == 1
    assert len(handle.client.unassign_calls) == 1


async def test_transport_close_failure_reports_safe_cleanup_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = make_handle()
    executor = ColabExecutor(object())
    job = make_job(tmp_path)
    executor.handles[job.id] = handle
    close_attempted = threading.Event()

    async def finish_after_close() -> None:
        assert await asyncio.to_thread(close_attempted.wait, 2)

    work_task = asyncio.create_task(finish_after_close())
    cancellation_wait = asyncio.create_task(asyncio.sleep(0))

    def fail_close(handle: Handle) -> None:
        close_attempted.set()
        raise RuntimeError("upstream response contains a private runtime token")

    monkeypatch.setattr(executor, "_close_transport", fail_close)
    await asyncio.wait_for(
        executor._finish(job, work_task, cancellation_wait),
        timeout=3,
    )
    assert close_attempted.is_set()
    assert work_task.done()
    assert (await asyncio.gather(work_task)) == [None]
    assert job.cleanup is not None
    assert job.cleanup["transport_close_failed"] is True
    assert "Kernel transport close did not return successfully." in job.cleanup["errors"]
    assert len(handle.client.unassign_calls) == 1
    assert not executor.transport_close_failed
    assert "private runtime token" not in str(job.cleanup) + str(job.records)


async def test_queued_cancel_after_release_does_not_close_again(tmp_path: Path) -> None:
    handle = make_handle()
    executor = ColabExecutor(object())
    job = make_job(tmp_path)
    executor.handles[job.id] = handle
    lock = executor._transport_locks.setdefault(job.id, asyncio.Lock())
    await lock.acquire()
    closer = asyncio.create_task(executor._transport_close(job.id, handle))
    await asyncio.sleep(0)
    executor.handles.pop(job.id)
    lock.release()
    await asyncio.wait_for(closer, timeout=2)
    assert not handle.runtime.stop_calls
    assert not executor._transport_locks
    assert not executor.transport_close_failed
