"""Input sanitization helpers for local/static plugin data."""

from __future__ import annotations

import os
import re
from typing import Any, Tuple


MAX_IMPORT_BYTES = 4 * 1024 * 1024
MAX_EDIT_CHARS = 1_200_000
MAX_PARSE_CHARS = 1_200_000
MAX_PROMPT_FIELD_CHARS = 12_000
MAX_LABEL_CHARS = 120

CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
COMMENT_PREFIX_RE = re.compile(r"(?im)^\s*(system|assistant|developer)\s*:\s*")


def normalize_newlines(value: Any) -> str:
    return str(value or "").replace("\r\n", "\n").replace("\r", "\n")


def sanitize_text(value: Any, max_chars: int = MAX_EDIT_CHARS, collapse_ws: bool = False) -> str:
    text = normalize_newlines(value)
    text = ANSI_ESCAPE_RE.sub("", text)
    text = CONTROL_CHARS_RE.sub("", text)
    if collapse_ws:
        text = re.sub(r"\s+", " ", text).strip()
    if max_chars and len(text) > max_chars:
        text = text[: max(0, max_chars - 80)].rstrip()
        text += "\n[truncated by Monstey sanitization: %d char limit]" % max_chars
    return text


def sanitize_prompt_text(value: Any, max_chars: int = MAX_PROMPT_FIELD_CHARS) -> str:
    text = sanitize_text(value, max_chars=max_chars, collapse_ws=False).strip()
    return COMMENT_PREFIX_RE.sub(lambda m: "quoted_%s: " % m.group(1).lower(), text)


def sanitize_label(value: Any, max_chars: int = MAX_LABEL_CHARS) -> str:
    text = sanitize_text(value, max_chars=max_chars, collapse_ws=True)
    text = re.sub(r"[^A-Za-z0-9 _.,:+\\/@#()[\]{}=<>?*!|'-]+", "_", text)
    return text[:max_chars].strip() or "unknown"


def sanitize_evidence_kind(value: Any, allowed: set, default: str = "note") -> str:
    text = sanitize_label(value, 64).lower().replace("-", "_").replace(" ", "_")
    return text if text in allowed else default


def read_text_file_safely(path: str, max_bytes: int = MAX_IMPORT_BYTES) -> Tuple[str, bool]:
    file_path = os.path.abspath(path)
    try:
        size = os.path.getsize(file_path)
    except Exception:
        size = 0
    truncated = bool(size and size > max_bytes)
    with open(file_path, "rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        data = data[:max_bytes]
        truncated = True
    text = data.decode("utf-8", errors="replace")
    text = sanitize_text(text, max_chars=MAX_EDIT_CHARS)
    if truncated:
        text = text.rstrip() + "\n# [Monstey import truncated to %d bytes from %s]\n" % (max_bytes, file_path)
    return text, truncated


def append_block(existing: Any, header: Any, block: Any, max_chars: int = MAX_EDIT_CHARS) -> str:
    current = sanitize_text(existing, max_chars=max_chars).rstrip()
    safe_header = "# " + sanitize_label(str(header).lstrip("# "), 220)
    safe_block = sanitize_text(block, max_chars=max_chars).strip()
    combined = (current + "\n\n" if current else "") + safe_header + "\n" + safe_block + "\n"
    return sanitize_text(combined, max_chars=max_chars)
