"""Client-owned, sequence-numbered jobs and explicitly captured artifacts."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import mimetypes
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from colab_remote_mcp.store import private_directory, private_write

TERMINAL = frozenset({"completed", "failed", "cancelled"})
MAX_CODE_BYTES = 128 * 1024
MAX_REQUIREMENTS = 100
MAX_REQUIREMENTS_BYTES = 32 * 1024
MAX_EVENT_TEXT_BYTES = 512 * 1024
MAX_TOTAL_EVENT_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 20_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_FILES = 64
MAX_BINARY_BYTES = 8 * 1024 * 1024
MAX_DOWNLOAD_ENCODED_BYTES = 96 * 1024 * 1024


class JobError(ValueError):
    """A stable agent-facing validation or job-state error."""


def validate_run(code: str, requirements: list[str] | None) -> None:
    if not isinstance(code, str) or not code.strip() or len(code.encode()) > MAX_CODE_BYTES:
        raise JobError("Python code must be nonempty and at most 128 KiB.")
    if not requirements:
        return
    if not isinstance(requirements, list) or not all(
        isinstance(item, str) for item in requirements
    ):
        raise JobError("Requirements must be a list of pip requirement arguments.")
    if len(requirements) > MAX_REQUIREMENTS:
        raise JobError("At most 100 pip requirement arguments are allowed.")
    total = sum(len(item.encode()) for item in requirements)
    if total > MAX_REQUIREMENTS_BYTES or any(
        not item.strip() or item.strip() != item or re.search(r"[\r\n\x00]", item)
        for item in requirements
    ):
        raise JobError(
            "Requirements must be nonempty, trimmed, at most 32 KiB total, and one-line."
        )
    # Everything after pip's literal '--' is a requirement argument. Administrative
    # switches cannot be hidden in that position. Direct URLs, local paths, archives
    # and editable installs are intentionally excluded: they can read Colab files,
    # include credentials, or execute an unintended local setup backend.
    if any(item.startswith("-") for item in requirements):
        raise JobError("Requirements contain only package requirement specifiers, not pip options.")
    for item in requirements:
        try:
            url = urlsplit(item)
            port = url.port
        except ValueError as error:
            raise JobError("Invalid package requirement URL.") from error
        if (
            item.startswith(("/", "./", "../", "~", "."))
            or "\\" in item
            or "://" in item
            or item.lower().startswith(("file:", "git+", "hg+", "svn+", "bzr+"))
            or url.scheme
            or url.username
            or url.password
            or port is not None
            or "@" in item
        ):
            raise JobError(
                "Use named/public-index package requirements, not URLs, paths or credentials."
            )


@dataclass(frozen=True, init=False)
class ExportRequest:
    remote: str
    name: str

    def __init__(self, ordinal: int, source: str) -> None:
        if not isinstance(source, str):
            raise JobError("Export paths must be strings.")
        path = PurePosixPath(source)
        if (
            not source.startswith("/content/output/")
            or any(part == "" for part in source.split("/")[1:])
            or any(part in {"..", "."} for part in path.parts)
            or "\\" in source
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", path.name)
        ):
            raise JobError("Exports must have a simple ASCII basename under /content/output/.")
        object.__setattr__(self, "remote", str(path))
        object.__setattr__(self, "name", f"{ordinal:03d}__{path.name}")


class Job:
    def __init__(self, job_id: str, directory: Path, owner: str, accelerator: str) -> None:
        if not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise JobError("Invalid job directory identifier.")
        self.id = job_id
        self.directory = directory
        self.files = directory / "files"
        self.owner = owner
        self.accelerator = accelerator
        self.status = "queued"
        self.progress = "Queued"
        self.created_at = time.time()
        self.error: str | None = None
        self.cleanup: dict[str, Any] | None = None
        self.records: list[dict[str, Any]] = []
        self.artifacts: dict[str, dict[str, Any]] = {}
        self.event_bytes = 0
        self.condition = asyncio.Condition()
        self.cancelled = asyncio.Event()
        self.task: asyncio.Task[None] | None = None
        self._write_lock = asyncio.Lock()
        self._persisted_events = 0
        self._event_log_digest = ""

    @property
    def event_path(self) -> Path:
        return self.directory / "events.jsonl"

    async def event(self, kind: str, payload: dict[str, Any]) -> None:
        event = {"seq": 0, "kind": kind, "at": time.time(), **payload}
        if {
            "token",
            "access_token",
            "refresh_token",
            "authorization",
            "runtime",
            "session",
        }.intersection(payload):
            raise JobError("Credentials and runtime session values cannot enter job output.")
        size = len(json.dumps(event, ensure_ascii=False).encode())
        if size > MAX_EVENT_TEXT_BYTES:
            raise JobError("One kernel event exceeds the 512 KiB event limit.")
        async with self._write_lock:
            if len(self.records) >= MAX_EVENTS:
                raise JobError("Too many kernel events; reduce print/display frequency.")
            if self.event_bytes + size <= 0 or self.event_bytes + size > MAX_TOTAL_EVENT_BYTES:
                raise JobError("Kernel text output exceeded its persisted event budget.")
            event["seq"] = len(self.records) + 1
            self.records.append(event)
            self.event_bytes += size
            self.save()
        # Condition.wait()/notify always share this condition's actual lock.
        async with self.condition:
            self.condition.notify_all()

    async def progress_message(self, message: str) -> None:
        if self.progress != message:
            self.progress = message
            await self.event("progress", {"message": message})

    async def output(self, output: dict[str, Any]) -> None:
        from colab_remote_mcp.outputs import output_events

        for kind, payload in output_events(output, self):
            await self.event(kind, payload)

    def _assert_files_root(self) -> None:
        if self.directory.is_symlink() or self.files.is_symlink():
            raise JobError("Artifact storage refuses symbolic links.")
        private_directory(self.directory)
        private_directory(self.files)

    def _staging_path(self) -> Path:
        self._assert_files_root()
        return self.files / f".download-{uuid.uuid4().hex}"

    def _remaining_bytes(self) -> int:
        return MAX_TOTAL_BYTES - sum(item["size"] for item in self.artifacts.values())

    def _remote_mime(self, remote: str) -> str:
        suffix = PurePosixPath(remote).name
        suffix = Path(suffix).suffix.lower()
        default = mimetypes.guess_type(PurePosixPath(remote).name)[0]
        return {
            ".csv": "text/csv",
            ".html": "text/html",
            ".json": "application/json",
            ".md": "text/markdown",
            ".pdf": "application/pdf",
            ".svg": "image/svg+xml",
            ".tsv": "text/tab-separated-values",
            ".txt": "text/plain",
        }.get(suffix, default or "application/octet-stream")

    def _register(self, path: Path, mime: str | None = None) -> dict[str, Any]:
        if (
            path.parent != self.files
            or path.name.startswith(".")
            or path.is_symlink()
            or not path.is_file()
        ):
            raise JobError("Captured output must be a regular non-hidden artifact file.")
        try:
            with path.open("rb") as stream:
                size = os.fstat(stream.fileno()).st_size
                previous_bytes = self.artifacts.get(path.name, {}).get("size", 0)
                if size > MAX_FILE_BYTES or size - previous_bytes > self._remaining_bytes():
                    raise JobError(
                        "Captured files exceed the 64 MiB per-file or 128 MiB total limit."
                    )
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        except Exception:
            path.unlink(missing_ok=True)
            raise
        path.chmod(0o600)
        record = {
            "name": path.name,
            "size": size,
            "mime_type": mime or mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            "sha256": checksum,
            "resource_uri": f"col.file://{self.id}/{path.name}",
        }
        if path.name in self.artifacts:
            old = self.artifacts[path.name]
            if old["size"] != size or old["sha256"] != checksum:
                raise JobError("An existing captured artifact cannot be silently overwritten.")
            return old
        if len(self.artifacts) >= MAX_FILES:
            raise JobError("The job has reached its 64-file artifact limit.")
        self.artifacts[path.name] = record
        return record

    def _check_staging(self, path: Path) -> None:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES or size > self._remaining_bytes():
            raise JobError("Captured files exceed the 64 MiB per-file or 128 MiB total limit.")

    def capture_image(self, data: bytes, mime: str) -> dict[str, Any]:
        suffixes = {
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "image/gif": ".gif",
            "application/pdf": ".pdf",
        }
        if mime not in suffixes or len(data) > MAX_BINARY_BYTES:
            raise JobError("Inline binary output must be PNG, JPEG, GIF or PDF, at most 8 MiB.")
        path = self._staging_path()
        destination = self.files / f"output-{len(self.artifacts) + 1:04d}{suffixes[mime]}"
        try:
            with path.open("xb") as stream:
                stream.write(data)
            self._check_staging(path)
            os.replace(path, destination)
            return self._register(destination, mime)
        finally:
            path.unlink(missing_ok=True)

    def export_path(self, request: ExportRequest) -> Path:
        self._assert_files_root()
        if len(self.artifacts) >= MAX_FILES or (self.files / request.name).exists():
            raise JobError("The job cannot capture another file with this name.")
        return self._staging_path()

    def finish_export(
        self, request: ExportRequest, staging: Path, mime: str | None = None
    ) -> dict[str, Any]:
        try:
            self._check_staging(staging)
            destination = self.files / request.name
            os.replace(staging, destination)
            # A separate metadata write cannot expose a partial download; staged
            # names are excluded on restart until their artifact event exists.
            return self._register(destination, mime or self._remote_mime(request.remote))
        finally:
            staging.unlink(missing_ok=True)

    async def export_file(self, contents: Any, request: ExportRequest) -> None:
        staging = self.export_path(request)
        try:
            await asyncio.to_thread(contents.download, request.remote, str(staging))
            artifact = self.finish_export(request, staging)
            await self.event("artifact", {"artifact": artifact, "source": request.remote})
        finally:
            staging.unlink(missing_ok=True)

    def read_file(self, filename: str) -> tuple[bytes, str]:
        if filename != Path(filename).name or filename not in self.artifacts:
            raise FileNotFoundError("Unknown captured output file.")
        path = self.files / filename
        expected = self.artifacts[filename]
        try:
            with path.open("rb") as stream:
                stat = os.fstat(stream.fileno())
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or stat.st_size != expected["size"]
                    or stat.st_size > MAX_FILE_BYTES
                ):
                    raise FileNotFoundError("Captured output file no longer matches its artifact.")
                data = stream.read(MAX_FILE_BYTES + 1)
            if hashlib.sha256(data).hexdigest() != expected["sha256"]:
                raise FileNotFoundError("Captured output file failed its SHA-256 integrity check.")
        except OSError as error:
            raise FileNotFoundError("Captured output file is no longer available.") from error
        return data, expected["mime_type"]

    def public(self) -> dict[str, Any]:
        """Data safe for an authorized tool response; never includes owner."""
        return {
            "job_id": self.id,
            "status": self.status,
            "accelerator": self.accelerator,
            "progress": self.progress,
            "created_at": self.created_at,
            "last_event_seq": len(self.records),
            "error": self.error,
            "cleanup": self.cleanup,
        }

    def persisted(self) -> dict[str, Any]:
        # Restore needs this namespace internally; it is never sent by public().
        return {
            **self.public(),
            "owner": self.owner,
            "event_log_sha256": self._event_log_digest,
        }

    async def response(
        self, after: int = 0, limit: int = 100, wait_seconds: float = 15.0
    ) -> dict[str, Any]:
        if (
            not isinstance(after, int)
            or isinstance(after, bool)
            or after < 0
            or after > len(self.records)
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 500
            or isinstance(wait_seconds, bool)
            or not isinstance(wait_seconds, int | float)
        ):
            raise JobError("Invalid output cursor or limit (1..500).")
        if not math.isfinite(wait_seconds) or not 0 <= wait_seconds <= 30:
            raise JobError("wait_seconds must be between 0 and 30.")
        if after == len(self.records) and self.status not in TERMINAL and wait_seconds:
            try:
                await asyncio.wait_for(self.condition.wait(), timeout=wait_seconds)
            except TimeoutError:
                pass
        cursor = min(after + limit, len(self.records))
        return {
            **self.public(),
            "events": list(self.records[after:cursor]),
            "next_cursor": cursor,
            "has_more": cursor < len(self.records),
        }

    def save(self) -> None:
        """Atomically checkpoint the event prefix that fsync actually made durable."""
        # The first metadata write describes only the previously durable prefix;
        # never promise the event being appended before its own fsync succeeds.
        current_events = self.records
        self.records = current_events[: self._persisted_events]
        try:
            private_write(
                self.directory / "job.json", json.dumps(self.persisted(), separators=(",", ":"))
            )
        finally:
            self.records = current_events
        if len(self.records) == self._persisted_events:
            return
        if self.event_path.is_symlink() or (
            self.event_path.exists() and not self.event_path.is_file()
        ):
            raise JobError("Refusing an unsafe job event log.")
        if len(self.records) != self._persisted_events + 1:
            raise JobError("Event persistence must append exactly one event.")
        descriptor = os.open(
            self.event_path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            0o600,
        )
        try:
            data = (json.dumps(self.records[-1], ensure_ascii=False) + "\n").encode()
            written = os.write(descriptor, data)
            if written != len(data):
                raise OSError("Event log append was incomplete.")
            os.fsync(descriptor)
            # Publish the cursor and hash only after their complete event prefix
            # is durable. A crash before this write leaves a dropable log suffix.
            self._persisted_events = len(self.records)
            self._event_log_digest = hashlib.sha256(self.event_path.read_bytes()).hexdigest()
        finally:
            os.close(descriptor)
        private_write(
            self.directory / "job.json", json.dumps(self.persisted(), separators=(",", ":"))
        )


class JobManager:
    def __init__(self, data: Path, executor: Any) -> None:
        self.root = data / "jobs"
        private_directory(self.root)
        self.executor = executor
        self.jobs: dict[str, Job] = {}
        self.lock = asyncio.Lock()
        self._restore()

    def _restore(self) -> None:
        for directory in sorted(self.root.iterdir()):
            metadata = directory / "job.json"
            if (
                not directory.is_dir()
                or directory.is_symlink()
                or metadata.is_symlink()
                or not metadata.is_file()
            ):
                continue
            try:
                if metadata.stat().st_mode & 0o077:
                    continue
                data = json.loads(metadata.read_text(encoding="utf-8"))
                job = Job(data["job_id"], directory, data["owner"], data["accelerator"])
                if job.id != directory.name or data["status"] not in TERMINAL | {
                    "queued",
                    "assigning",
                    "running",
                }:
                    raise JobError("Invalid persisted job state.")
                self._restore_events(
                    job,
                    data["last_event_seq"],
                    data.get("event_log_sha256"),
                )
                private_directory(job.files)
                referenced = {
                    event["artifact"]["name"]: event["artifact"]
                    for event in job.records
                    if event.get("kind") == "artifact" and isinstance(event.get("artifact"), dict)
                }
                for path in sorted(job.files.iterdir()):
                    if not path.is_file() or path.is_symlink():
                        continue
                    previous = referenced.get(path.name)
                    if previous is None:
                        path.unlink()  # unannounced partial/tampered file, never expose it
                        continue
                    record = job._register(path, previous.get("mime_type"))
                    if record["sha256"] != previous.get("sha256") or record["size"] != previous.get(
                        "size"
                    ):
                        del job.artifacts[path.name]
                        path.unlink()
                job.status = data["status"]
                job.progress = str(data.get("progress", "Restored"))[:256]
                job.created_at = float(data["created_at"])
                job.error = data.get("error")
                job.cleanup = data.get("cleanup")
                if job.status not in TERMINAL:
                    job.status = "failed"
                    job.error = (
                        "MCP restarted during execution; remote cleanup could not be resumed."
                    )
                    job.cleanup = {
                        "unassigned": False,
                        "reason": "The ephemeral runtime handle was not persisted.",
                    }
                private_write(metadata, json.dumps(job.persisted(), separators=(",", ":")))
                self.jobs[job.id] = job
            except (OSError, ValueError, TypeError, KeyError, UnicodeDecodeError):
                continue

    @staticmethod
    def _restore_events(job: Job, expected_events: Any, expected_digest: Any = None) -> None:
        if not job.event_path.exists():
            if expected_events:
                raise JobError("Event log missing.")
            return
        if (
            job.event_path.is_symlink()
            or not job.event_path.is_file()
            or job.event_path.stat().st_mode & 0o077
        ):
            raise JobError("Invalid event log.")
        digest = hashlib.sha256()
        with job.event_path.open("rb") as stream:
            for encoded in stream:
                try:
                    line = encoded.decode("utf-8")
                    event = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    # Only a missing final newline means a torn append. A corrupt
                    # complete line invalidates the whole event prefix instead.
                    if encoded.endswith(b"\n"):
                        raise JobError("Corrupt complete event log line.") from None
                    break
                else:
                    if not encoded.endswith(b"\n"):
                        raise JobError("Complete JSON without event terminator is unsafe.")
                if (
                    not isinstance(event, dict)
                    or event.get("seq") != len(job.records) + 1
                    or len(job.records) >= MAX_EVENTS
                ):
                    raise JobError("Invalid contiguous event log.")
                size = len(json.dumps(event, ensure_ascii=False).encode())
                if size > MAX_EVENT_TEXT_BYTES or job.event_bytes + size > MAX_TOTAL_EVENT_BYTES:
                    raise JobError("Event log exceeds its budget.")
                job.records.append(event)
                job.event_bytes += size
                digest.update(encoded)
        if not isinstance(expected_events, int) or isinstance(expected_events, bool):
            raise JobError("Invalid persisted event cursor.")
        if expected_events != len(job.records):
            raise JobError("Job metadata and event cursor are inconsistent.")
        if expected_digest is not None and (
            not isinstance(expected_digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", expected_digest)
            or expected_digest != digest.hexdigest()
        ):
            raise JobError("Event log digest mismatch; remote status is uncertain.")
        # The digest commits only complete events, never a trailing partial write.
        # Remove that ignored suffix now so a post-restart append remains valid.
        encoded_prefix = "".join(
            json.dumps(event, ensure_ascii=False) + "\n" for event in job.records
        ).encode()
        with job.event_path.open("r+b") as stream:
            if stream.read(len(encoded_prefix)) != encoded_prefix:
                raise JobError("Persisted events differ from their canonical encoding.")
            stream.truncate(len(encoded_prefix))
            stream.flush()
            os.fsync(stream.fileno())
        job._event_log_digest = hashlib.sha256(encoded_prefix).hexdigest()
        job._persisted_events = len(job.records)

    async def start(
        self, owner: str | None, code: str, accelerator: str, **options: Any
    ) -> dict[str, Any]:
        if not owner or accelerator not in {"cpu", "gpu"}:
            raise JobError("An authenticated owner and accelerator=cpu or gpu are required.")
        validate_run(code, options.get("requirements"))
        exports = [
            ExportRequest(index, path)
            for index, path in enumerate(options.get("client_exports") or [], 1)
        ]
        if len(exports) > MAX_FILES:
            raise JobError("At most 64 explicit exports are allowed.")
        timeout = options.get("idle_timeout_seconds", 1800)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 0 <= timeout <= 86400:
            raise JobError("idle_timeout_seconds must be an integer from 0 to 86400.")
        async with self.lock:
            if any(job.status not in TERMINAL for job in self.jobs.values()):
                raise JobError("This single-owner server already has an active Colab job.")
            job_id = uuid.uuid4().hex
            directory = self.root / job_id
            directory.mkdir(mode=0o700)
            job = Job(job_id, directory, owner, accelerator)
            private_directory(job.files)
            self.jobs[job.id] = job
            await job.event("status", {"status": "queued"})
            job.task = asyncio.create_task(
                self.executor.run(job, code, **options), name=f"colab-{job_id}"
            )
            return job.public()

    def authorized(self, owner: str | None, job_id: str) -> Job:
        job = self.jobs.get(job_id)
        if not owner or job is None or job.owner != owner:
            raise JobError("Job or captured output was not found for this MCP client.")
        return job

    async def output(self, owner: str | None, job_id: str, **kwargs: Any) -> dict[str, Any]:
        job = self.authorized(owner, job_id)
        async with job.condition:
            return await job.response(**kwargs)

    def list_artifacts(self, owner: str | None) -> list[dict[str, Any]]:
        return [
            {**artifact, "job_id": job.id}
            for job in self.jobs.values()
            if job.owner == owner
            for artifact in job.artifacts.values()
        ]

    def read_file(self, owner: str | None, job_id: str, filename: str) -> tuple[bytes, str]:
        return self.authorized(owner, job_id).read_file(filename)

    async def cancel(self, owner: str | None, job_id: str) -> dict[str, Any]:
        job = self.authorized(owner, job_id)
        if job.status in TERMINAL:
            return job.public()
        await self.executor.request_cancel(job)
        return job.public()

    async def stop_all(self) -> None:
        active = [job for job in self.jobs.values() if job.status not in TERMINAL]
        for job in active:
            await self.executor.request_cancel(job)
            if job.task is not None:
                # request_cancel closes the remote transport where possible;
                # task cancellation also releases purely local waiters. The
                # production supervisor shields and awaits its cleanup work.
                job.task.cancel()
        await asyncio.gather(
            *(job.task for job in self.jobs.values() if job.task is not None),
            return_exceptions=True,
        )
