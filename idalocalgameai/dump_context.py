"""User-provided dump/process context saved locally per IDB input."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

from .config import config_dir
from .sanitize import sanitize_prompt_text, sanitize_text


def safe_key(value: Any) -> str:
    text = str(value or "default").strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    text = text.strip("._-")
    return text[:96] or "default"


def context_dir() -> str:
    root = os.path.join(config_dir(), "dump_contexts")
    os.makedirs(root, exist_ok=True)
    return root


def database_key(database: Optional[Dict[str, Any]]) -> str:
    db = database or {}
    return safe_key(db.get("root_filename") or db.get("input_file") or "default")


def dump_context_path(database: Optional[Dict[str, Any]]) -> str:
    return os.path.join(context_dir(), "%s.md" % database_key(database))


def load_dump_context(database: Optional[Dict[str, Any]]) -> str:
    path = dump_context_path(database)
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return sanitize_text(fh.read())
    except Exception:
        return ""


def save_dump_context(database: Optional[Dict[str, Any]], text: str) -> str:
    path = dump_context_path(database)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(sanitize_text(text).strip() + "\n")
    return path


def dump_context_payload(database: Optional[Dict[str, Any]], text: str) -> Dict[str, Any]:
    text = sanitize_prompt_text(text, max_chars=12000).strip()
    return {
        "path": dump_context_path(database),
        "user_notes": text[:12000],
        "present": bool(text),
        "priority": "analyst-provided dump/process context; use as background hypothesis, not proof",
    }
