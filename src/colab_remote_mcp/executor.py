"""Tracked, streaming Colab execution with a mandatory unassign attempt.

The upstream client is synchronous. Cancellation is therefore cooperative:
mark the job, best-effort close kernel channels, join its worker, then make
independent runtime-stop, unassign and session-close attempts. Python cannot
forcibly kill a thread blocked in an upstream network call.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Coroutine
from dataclasses import dataclass
from typing import Any

from colab_cli.client import TooManyAssignmentsError
from requests import RequestException

from colab_remote_mcp.credentials import AuthenticationRequired
from colab_remote_mcp.jobs import TERMINAL, ExportRequest, Job, JobError, validate_run
from colab_remote_mcp.privacy import redact


def execution_code(code: str) -> str:
    return (
        "import os as _mcp_os\n"
        "_mcp_os.makedirs('/content/output', exist_ok=True)\n"
        "_mcp_os.chdir('/content')\n"
    ) + code


def pip_code(requirements: list[str]) -> str:
    """Encode an argv literal, rather than interpolating a shell command."""
    argv = [
        "_mcp_sys.executable",
        "-m",
        "pip",
        "install",
        "--no-input",
        "--disable-pip-version-check",
        *requirements,
        "--",
    ]
    return (
        "import sys as _mcp_sys, subprocess as _mcp_subprocess\n"
        f"_mcp_subprocess.run({argv!r}, check=True)\n"
    )


def safe_error(error: BaseException) -> str:
    """Never relay upstream response bodies, headers, URLs or tokens."""
    if isinstance(error, AuthenticationRequired):
        return (
            "Colab credentials are unavailable or expired; "
            "reconnect MCP to renew Google authorization."
        )
    if isinstance(error, TooManyAssignmentsError):
        message = "Colab has too many assignments. Release other Colab sessions before retrying."
    elif isinstance(error, TimeoutError):
        message = "No kernel message arrived before the configured idle timeout."
    elif isinstance(error, FileNotFoundError):
        message = "The specifically requested output file was not found on Colab."
    elif isinstance(error, IsADirectoryError):
        message = "The requested Colab export is a directory, not a file."
    elif isinstance(error, JobError | ValueError):
        message = str(error)[:2048]
    elif isinstance(error, RequestException | ConnectionError):
        message = "The Colab network request failed; upstream response details are not exposed."
    else:
        message = (
            "Colab allocation, connection, or execution failed; "
            "output capture may also have failed. Check authorization and quota."
        )
    return redact(message)[:4096]


@dataclass(frozen=True)
class Handle:
    client: Any
    session: Any
    runtime: Any
    contents: Any
    endpoint: str


class ColabExecutor:
    """One tracked ephemeral assignment per active job, with final cleanup."""

    def __init__(self, credential_store: Any) -> None:
        self.credentials = credential_store
        self.handles: dict[str, Handle] = {}
        self.background: set[asyncio.Task[Any]] = set()
        self._transport_locks: dict[str, asyncio.Lock] = {}
        self.transport_close_failed: dict[str, str] = {}

    def _spawn(self, coroutine: Coroutine[Any, Any, Any]) -> asyncio.Task[Any]:
        task = asyncio.create_task(coroutine)
        self.background.add(task)
        task.add_done_callback(self.background.discard)
        return task

    def _allocate(self, accelerator: str) -> Handle:
        from colab_cli.client import Accelerator, Client, Prod, Shape, Variant
        from colab_cli.contents import ContentsClient
        from colab_cli.runtime import ColabRuntime
        from colab_cli.state import SessionState

        session = self.credentials.sessions()
        client = Client(Prod(), session)
        variant = Variant.GPU if accelerator == "gpu" else Variant.DEFAULT
        target = Accelerator.T4 if accelerator == "gpu" else Accelerator.NONE
        result = None
        try:
            result = client.assign(
                uuid.uuid4(), variant=variant, accelerator=target, shape=Shape.STANDARD
            )
            proxy = result.runtime_proxy_info
            if not proxy.url or not proxy.token:
                raise JobError("Colab returned an incomplete runtime assignment.")
            state = SessionState(
                name="mcp-ephemeral",
                url=proxy.url,
                token=proxy.token,
                endpoint=result.endpoint,
                token_expires_at=proxy.expires_at(),
                variant=variant.value,
                accelerator=target.value,
                machine_shape="STANDARD",
            )
            return Handle(
                client=client,
                session=session,
                runtime=ColabRuntime(proxy.url, proxy.token),
                contents=ContentsClient(state),
                endpoint=result.endpoint,
            )
        except BaseException:
            # If an assignment is already known, release it even during local
            # cancellation or construction failure. The exception itself is not
            # returned to the agent because it can contain headers or tokens.
            if result is not None:
                try:
                    client.unassign(result.endpoint)
                except Exception as error:
                    discarded = type(error)  # Do not expose upstream exception details.
                    _ = discarded
            session.close()
            raise

    async def request_cancel(self, job: Job) -> None:
        """Request cooperative cancellation; keep the allocation worker tracked."""
        job.cancelled.set()
        # Do not block the caller waiting for the upstream network library. The
        # run supervisor observes the flag and performs/awaits the same close.
        handle = self.handles.get(job.id)
        if handle is not None:
            self._spawn(self._transport_close(job.id, handle))

    async def run(self, job: Job, code: str, **options: Any) -> None:
        work_task = self._spawn(self._work(job, code, options))
        cancellation_wait = self._spawn(job.cancelled.wait())
        interrupted = False
        try:
            try:
                await asyncio.wait(
                    {work_task, cancellation_wait},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not work_task.done() and job.cancelled.is_set():
                    handle = self.handles.get(job.id)
                    if handle is not None:
                        await self._transport_close(job.id, handle)
                # Cancelling a Future wrapping a synchronous thread would abandon
                # that thread. Shield it; _finish always waits for its completion.
                await asyncio.shield(work_task)
            except asyncio.CancelledError:
                interrupted = True
                job.cancelled.set()
        finally:
            cancellation_wait.cancel()
            finalization = self._spawn(self._finish(job, work_task, cancellation_wait))

        # A task can receive more than one cancellation request. Consume those
        # requests only while joining cleanup, then preserve cancellation for the
        # caller by raising CancelledError after the finalizer has returned.
        while not finalization.done():
            try:
                await asyncio.shield(finalization)
            except asyncio.CancelledError:
                interrupted = True
                current = asyncio.current_task()
                if current is not None:
                    while current.cancelling():
                        current.uncancel()
        finalization.result()
        if interrupted:
            raise asyncio.CancelledError

    async def _work(self, job: Job, code: str, options: dict[str, Any]) -> None:
        try:
            if job.cancelled.is_set():
                job.status = "cancelled"
                return
            validate_run(code, options.get("requirements"))
            job.status = "assigning"
            await job.progress_message("Requesting an ephemeral standard CPU or T4 Colab runtime")
            handle = await asyncio.to_thread(self._allocate, job.accelerator)
            self.handles[job.id] = handle
            if job.cancelled.is_set():
                job.status = "cancelled"
                return
            job.status = "running"
            await job.event("status", {"status": "running"})
            timeout = options.get("idle_timeout_seconds", 1800)
            if requirements := options.get("requirements"):
                await job.progress_message("Installing requested dependencies on Colab")
                outputs = await self._execute(job, handle, pip_code(requirements), timeout)
                self._check_kernel_errors(outputs, "Dependency installation")
            outputs = await self._execute(job, handle, execution_code(code), timeout)
            self._check_kernel_errors(outputs, "Agent Python")
            await job.progress_message("Capturing explicitly requested result files")
            for index, source in enumerate(options.get("client_exports") or [], 1):
                await job.export_file(handle.contents, ExportRequest(index, source))
            job.status = "completed" if not job.cancelled.is_set() else "cancelled"
        except asyncio.CancelledError:
            raise
        except Exception as error:
            job.status = "cancelled" if job.cancelled.is_set() else "failed"
            job.error = safe_error(error)

    @staticmethod
    def _check_kernel_errors(outputs: list[dict[str, Any]], operation: str) -> None:
        if any(output.get("output_type") == "error" for output in outputs):
            raise JobError(f"{operation} failed; inspect the captured remote error event.")

    async def _execute(
        self,
        job: Job,
        handle: Handle,
        code: str,
        idle_timeout_seconds: int,
    ) -> list[dict[str, Any]]:  # noqa: ASYNC109 - upstream kernel-message timeout
        loop = asyncio.get_running_loop()
        stream_history: dict[tuple[str, str], str] = {}

        def capture(output: dict[str, Any]) -> None:
            if job.cancelled.is_set():
                return
            # The official hook can report an existing stream output again with
            # cumulative text. Emit only its new suffix to preserve live stdout.
            event_output = output
            if output.get("output_type") == "stream":
                value = output.get("text", "")
                current = value if isinstance(value, str) else "".join(map(str, value or []))
                key = (str(output.get("name", "stdout")), str(output.get("stream_id", "")))
                previous = stream_history.get(key, "")
                stream_history[key] = current
                if previous and current.startswith(previous):
                    event_output = {**output, "text": current[len(previous) :]}
            # Backpressure/failure propagation and ordering: the thread mutates no
            # job state; it waits until this event is persisted by the event loop.
            future = asyncio.run_coroutine_threadsafe(job.output(event_output), loop)
            future.result()

        return await asyncio.to_thread(
            handle.runtime.execute_code,
            code,
            allow_stdin=False,
            stdin_hook=None,
            output_hook=capture,
            timeout=idle_timeout_seconds or None,
        )

    @staticmethod
    def _close_transport(handle: Handle) -> None:
        """Best-effort channel close so the streaming poll can leave its wait."""
        kernel = getattr(handle.runtime, "_kernel_client", None)
        if kernel is not None:
            client = getattr(getattr(kernel, "_manager", None), "client", None)
            if client is not None:
                client.stop_channels()
                socket = getattr(client, "kernel_socket", None)
                if socket is not None:
                    socket.close()
            return
        handle.runtime.stop(shutdown_kernel=False)

    async def _transport_close(self, job_id: str, handle: Handle) -> None:
        lock = self._transport_locks.setdefault(job_id, asyncio.Lock())
        try:
            async with lock:
                if job_id not in self.handles:
                    # The finalizer already released this exact handle while a
                    # duplicate cancellation was queued behind the lock.
                    return
                try:
                    await asyncio.to_thread(self._close_transport, handle)
                except Exception:
                    # Keep upstream details private while surfacing the failure.
                    self.transport_close_failed[job_id] = (
                        "Kernel transport close did not return successfully."
                    )
        finally:
            if job_id not in self.handles:
                # Finalization popped the handle while cancellation was waiting
                # on this lock. Do not leave a stale error for a future job.
                self._transport_locks.pop(job_id, None)

    async def _finish(
        self,
        job: Job,
        work_task: asyncio.Task[Any],
        cancellation_wait: asyncio.Task[Any],
    ) -> None:
        await asyncio.gather(cancellation_wait, return_exceptions=True)
        try:
            if not work_task.done():
                handle = self.handles.get(job.id)
                if handle is not None:
                    await self._transport_close(job.id, handle)
                # Protect cleanup from internal worker cancellation as well as
                # the run supervisor: never abandon its synchronous thread.
                while not work_task.done():
                    await asyncio.gather(work_task, return_exceptions=True)
        finally:
            # Stop/unassign/report remain independent even if transport close
            # were to fail with BaseException rather than a normal upstream error.
            await self._release_and_report(job)
        await asyncio.gather(work_task, return_exceptions=True)

    async def _release_and_report(self, job: Job) -> None:
        handle = self.handles.pop(job.id, None)
        if job.status not in TERMINAL:
            job.status = "cancelled" if job.cancelled.is_set() else "failed"
            job.error = job.error or "Colab job ended before completion."
        errors: list[str] = []
        cleanup: dict[str, Any] = {
            "assignment_tracked": handle is not None,
            "unassign_attempted": False,
            "unassigned": False,
            "runtime_stop_returned": False,
        }
        if handle is not None:
            try:
                await asyncio.to_thread(handle.runtime.stop, shutdown_kernel=True)
                cleanup["runtime_stop_returned"] = True
            except Exception:
                errors.append("Runtime stop did not return successfully.")
            cleanup["unassign_attempted"] = True
            try:
                await asyncio.to_thread(handle.client.unassign, handle.endpoint)
                cleanup["unassigned"] = True
            except Exception:
                errors.append("Remote assignment release was not confirmed.")
            try:
                handle.session.close()
            except Exception:
                errors.append("The local outbound Colab HTTP session did not close cleanly.")
        elif job.error:
            cleanup["note"] = "No usable assignment handle was returned; remote release is unknown."
        if message := self.transport_close_failed.pop(job.id, None):
            cleanup["transport_close_failed"] = True
            errors.append(message)
        cleanup["errors"] = errors
        job.cleanup = cleanup
        self._transport_locks.pop(job.id, None)
        await job.event("cleanup", {"cleanup": cleanup})
        await job.event("status", {"status": job.status, "error": job.error})
