"""Last-resort redaction. Never log request/response/config objects themselves."""

from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"(?i)(Bearer\s+)[^\s,;'\"]+"),
    re.compile(
        r"""(?ix)((?:refresh_token|access_token|client_secret|code_verifier|password)["'\s:=\\&]{1,8})([^\s,&;'\"}]+)"""
    ),
    re.compile(r"\b\d{12}-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com\b"),
]


def redact(text: object) -> str:
    value = str(text)
    for pattern in _PATTERNS:
        value = pattern.sub(lambda match: match.group(1) + "[REDACTED]", value)
    return value.replace("\r", "\\r").replace("\n", "\\n")


class RedactingFormatter(__import__("logging").Formatter):
    def format(self, record: __import__("logging").LogRecord) -> str:
        return redact(super().format(record))
