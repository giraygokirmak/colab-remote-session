"""Convert each normalized Colab kernel output into bounded MCP job events."""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Protocol

MAX_TEXT = 256 * 1024
MAX_BINARY = 8 * 1024 * 1024
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class ImageCollector(Protocol):
    def capture_image(self, data: bytes, mime: str) -> dict[str, Any]: ...


def text(data: Any, limit: int = MAX_TEXT) -> str:
    value = data if isinstance(data, str) else json.dumps(_jsonable(data), ensure_ascii=False)
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    return encoded[: limit - 48].decode("utf-8", errors="ignore") + "\n[MCP text output truncated]"


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, list | tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return "[omitted non-JSON kernel output]"


def decode_base64(value: Any) -> bytes | None:
    if isinstance(value, list):
        value = "".join(str(part) for part in value)
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def output_events(
    output: dict[str, Any], collector: ImageCollector
) -> list[tuple[str, dict[str, Any]]]:
    kind = output.get("output_type")
    if kind == "stream":
        return [
            (
                "stderr" if output.get("name") == "stderr" else "stdout",
                {"text": text(output.get("text", ""))},
            )
        ]
    if kind == "error":
        trace = output.get("traceback")
        trace_text = (
            "\n".join(str(line) for line in trace) if isinstance(trace, list) else str(trace or "")
        )
        if not trace_text:
            trace_text = f"{output.get('ename', 'ExecutionError')}: {output.get('evalue', '')}"
        ename = str(output.get("ename", "ExecutionError"))[:128]
        return [("error", {"ename": ename, "text": text(ANSI.sub("", trace_text))})]
    if kind not in {"display_data", "execute_result"}:
        return []
    data = output.get("data")
    if not isinstance(data, dict):
        return [("display", {"mime_type": "text/plain", "text": text(data)})]
    events: list[tuple[str, dict[str, Any]]] = []
    for mime, value in data.items():
        if mime in {"image/png", "image/jpeg", "image/gif", "application/pdf"}:
            decoded = decode_base64(value)
            if decoded is None:
                events.append(
                    (
                        "display",
                        {"mime_type": mime, "text": "[Invalid inline binary output omitted]"},
                    )
                )
            elif len(decoded) > MAX_BINARY:
                events.append(
                    (
                        "display",
                        {
                            "mime_type": mime,
                            "text": "[Inline output exceeds 8 MiB and was omitted]",
                        },
                    )
                )
            else:
                events.append(
                    (
                        "artifact",
                        {"artifact": collector.capture_image(decoded, mime), "output_type": kind},
                    )
                )
        elif mime in {
            "text/plain",
            "text/html",
            "text/markdown",
            "application/json",
            "image/svg+xml",
        }:
            if isinstance(value, list):
                value = "".join(str(part) for part in value)
            events.append(
                ("display", {"mime_type": mime, "text": text(value), "output_type": kind})
            )
        else:
            events.append(
                ("display", {"mime_type": "text/plain", "text": text({"unsupported_mime": mime})})
            )
    return events
