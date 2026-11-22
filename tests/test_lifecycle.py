"""Cancellation and stream teardown use tracked threads, not abandoned tasks."""

from __future__ import annotations

import asyncio
import gc
import threading
from pathlib import Path
from typing import Any

import pytest
from test_executor import events_of, make_handle, make_job, wait_for_thread

from colab_remote_mcp.config import Config
from colab_remote_mcp.executor import ColabExecutor
from colab_remote_mcp.server import create_server


class BlockingRuntime:
    def __init__(self) -> None:
        self.execute_started = threading.Event()
        self.stop_calls = 0
        self.channel_closed = threading.Event()
        self.inner_socket_closed = False

    def execute_code(self, _code: str, **options: Any) -> list[Any]:
        self.execute_started.set()
        # The eventual worker return demonstrates that no sibling task was used
        # as a substitute runtime-stop signal. Cancellation never returns here.
        options["output_hook"]({"output_type": "stream", "name": "stdout", "text": "ignored\n"})
        import time

        while not self.channel_closed.wait(0.01):
            time.sleep(0.005)
        return []

    def stop(self, shutdown_kernel: bool = False) -> None:
        self.stop_calls += 1
        if not shutdown_kernel:
            self.channel_closed.set()


class FakeKernelClient:
    def __init__(self, runtime: BlockingRuntime) -> None:
        self.runtime = runtime
        self.kernel_socket = self
        self._manager = type("Manager", (), {"client": self})()

    def stop_channels(self) -> None:
        self.runtime.channel_closed.set()

    def close(self) -> None:
        self.runtime.inner_socket_closed = True


async def test_cancel_closes_kernel_then_stops_and_unassigns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = BlockingRuntime()
    handle = make_handle([])
    handle = type(handle)(
        client=handle.client,
        session=handle.session,
        runtime=runtime,
        contents=handle.contents,
        endpoint=handle.endpoint,
    )
    runtime._kernel_client = FakeKernelClient(runtime)  # type: ignore[attr-defined]
    executor = ColabExecutor(object())
    monkeypatch.setattr(executor, "_allocate", lambda accelerator: handle)
    job = make_job(tmp_path)
    task = asyncio.create_task(executor.run(job, "print('fixture')"))
    await wait_for_thread(runtime.execute_started)
    await asyncio.gather(*(executor.request_cancel(job) for _ in range(8)))
    await asyncio.wait_for(task, timeout=15)
    assert job.status == "cancelled"
    assert runtime.inner_socket_closed
    assert job.cleanup is not None
    assert job.cleanup["unassigned"] is True
    assert runtime.stop_calls == 1
    assert len(handle.client.unassign_calls) == 1
    assert len(events_of(job, "stdout")) <= 1
    assert not executor.background
    assert not executor.handles
    assert not executor._transport_locks


async def test_external_task_cancellation_still_finalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = make_handle([])
    executor = ColabExecutor(object())
    monkeypatch.setattr(executor, "_allocate", lambda accelerator: handle)
    job = make_job(tmp_path)
    task = asyncio.create_task(executor.run(job, "print('fixture')"))
    # Let run() enter its own cancellation handler. Cancelling a coroutine twice
    # before its first bytecode would bypass every Python try/finally, which is
    # not a meaningful lifecycle guarantee. Repeated delivery after start is.
    await asyncio.sleep(0)
    for _ in range(2):
        task.cancel()
        await asyncio.sleep(0)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=3)
    assert job.status == "cancelled"
    assert job.cleanup is not None
    assert job.cleanup["unassigned"] is True
    assert len(handle.client.unassign_calls) == 1
    assert not executor.background


async def test_stop_all_cancels_background_job_and_closes_lifespan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class WaitingExecutor:
        cancel_calls: int = 0

        async def run(self, job: Any, code: str, **options: Any) -> None:
            job.status = "running"
            self.cancel_calls = 0
            await job.event("status", {"status": "running"})
            try:
                await asyncio.Event().wait()
            finally:
                self.cancel_calls += 1
                job.status = "cancelled"
                await job.event("cleanup", {"cleanup": {"unassigned": False}})

        async def request_cancel(self, job: Any) -> None:
            job.cancelled.set()

    executor = WaitingExecutor()
    credentials = object()
    config = Config(
        public_url="http://127.0.0.1:8766",
        data=tmp_path,
        keyring_password="fixture-only-keyring",
    )
    service = create_server(config, credential_store=credentials, authorization=object())
    service.jobs.executor = executor
    app = service.create_app()
    async with app.router.lifespan_context(app):
        started = await service.jobs.start("client:one", "print('not remote')", "cpu")
        job = service.jobs.authorized("client:one", started["job_id"])
        assert job.task is not None
        for _ in range(len(job.records) + 1):
            await asyncio.sleep(0)
        assert not job.task.done()
    assert job.task.done()
    assert job.status == "cancelled"
    assert service.jobs.executor is executor
    assert executor.cancel_calls == 1
    assert await service.close() is None
    del job, app, service
    gc.collect()


async def test_allocation_failure_cannot_leak_secret_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = ColabExecutor(object())

    def fail(_accelerator: str) -> Any:
        raise RuntimeError("token=secret-in-upstream-exception")

    monkeypatch.setattr(executor, "_allocate", fail)
    job = make_job(tmp_path)
    await asyncio.wait_for(executor.run(job, "print('fixture')"), timeout=2)
    assert job.status == "failed"
    assert "secret-in-upstream" not in (job.error or "")
    assert job.cleanup is not None
    assert job.cleanup["unassign_attempted"] is False
    # The upstream network call returned no usable handle, so claiming a remote
    # unassignment would be false; this is explicitly reported to the caller.
