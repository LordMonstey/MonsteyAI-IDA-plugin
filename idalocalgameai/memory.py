"""Local per-IDB game map memory."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from .config import config_dir
from .sanitize import sanitize_label, sanitize_prompt_text, sanitize_text


def utc_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def safe_key(value: Any) -> str:
    text = sanitize_label(value or "default", 120).strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    text = text.strip("._-")
    return text[:80] or "default"


def map_key(context: Optional[Dict[str, Any]] = None) -> str:
    db = (context or {}).get("database") or {}
    return safe_key(db.get("root_filename") or db.get("input_file") or "default")


def maps_dir() -> str:
    root = os.path.join(config_dir(), "game_maps")
    os.makedirs(root, exist_ok=True)
    return root


def game_map_path(context: Optional[Dict[str, Any]] = None) -> str:
    return os.path.join(maps_dir(), "%s.json" % map_key(context))


def empty_game_map(context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    db = (context or {}).get("database") or {}
    return {
        "version": 1,
        "created_at": utc_now(),
        "updated_at": None,
        "database": db,
        "engine_hints": {},
        "functions": {},
        "feedback": {},
    }


def load_game_map(context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    path = game_map_path(context)
    if not os.path.isfile(path):
        return empty_game_map(context)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return empty_game_map(context)
        data.setdefault("version", 1)
        data.setdefault("database", (context or {}).get("database") or {})
        data.setdefault("engine_hints", {})
        data.setdefault("functions", {})
        data.setdefault("feedback", {})
        return data
    except Exception:
        return empty_game_map(context)


def save_game_map(data: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> str:
    data["updated_at"] = utc_now()
    path = game_map_path(context)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    return path


def as_list(value: Any, limit: int = 8) -> List[Any]:
    if not isinstance(value, list):
        return []
    return value[:limit]


def first_strings(items: Iterable[Dict[str, Any]], key: str, limit: int = 16) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        value = item.get(key)
        if not value:
            continue
        text = sanitize_prompt_text(value, 240)
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def increment_hints(data: Dict[str, Any], hints: Iterable[Any]) -> None:
    bucket = data.setdefault("engine_hints", {})
    for hint in hints:
        text = sanitize_label(hint, 160)
        if not text:
            continue
        bucket[text] = int(bucket.get(text, 0)) + 1


def upsert_analysis(context: Dict[str, Any], analysis: Dict[str, Any]) -> str:
    data = load_game_map(context)
    data["database"] = context.get("database") or data.get("database") or {}
    start = str(context.get("start_ea") or "unknown")
    previous = (data.get("functions") or {}).get(start) or {}
    xrefs = context.get("xrefs") or {}
    entry = {
        "address": start,
        "end_ea": context.get("end_ea"),
        "original_name": sanitize_label(context.get("function_name"), 160) if context.get("function_name") else "",
        "suggested_name": sanitize_label(analysis.get("suggested_function_name"), 160) if analysis.get("suggested_function_name") else "",
        "mode": analysis.get("mode") or context.get("mode"),
        "region_kind": context.get("region_kind"),
        "summary": sanitize_prompt_text(analysis.get("summary") or "", 900),
        "confidence": analysis.get("confidence") or 0.0,
        "behavior": as_list(analysis.get("behavior"), 8),
        "game_relevance": as_list(analysis.get("game_relevance"), 8),
        "engine_hints": as_list(analysis.get("engine_hints"), 8),
        "risks": as_list(analysis.get("risks"), 6),
        "callees": first_strings(xrefs.get("callees") or [], "name", 20),
        "strings": first_strings(xrefs.get("strings") or [], "value", 20),
        "updated_at": utc_now(),
    }
    if isinstance(previous, dict) and previous.get("feedback"):
        entry["feedback"] = previous.get("feedback")
    data.setdefault("functions", {})[start] = entry
    increment_hints(data, context.get("engine_hints_from_ida") or [])
    increment_hints(data, analysis.get("engine_hints") or [])
    save_game_map(data, context)
    return game_map_path(context)


def upsert_feedback(context: Dict[str, Any], feedback: Dict[str, Any]) -> str:
    data = load_game_map(context)
    data["database"] = context.get("database") or data.get("database") or {}
    start = str(context.get("start_ea") or feedback.get("address") or "unknown")
    entry = {}
    for key, value in dict(feedback or {}).items():
        if key in ("corrected_name", "corrected_role", "usefulness", "strategy", "function_name", "address"):
            entry[key] = sanitize_label(value, 160) if value not in (None, "") else ""
        else:
            entry[key] = sanitize_prompt_text(value, 1200)
    entry["address"] = start
    entry["function_name"] = context.get("function_name") or entry.get("function_name")
    entry["updated_at"] = utc_now()
    data.setdefault("feedback", {})[start] = entry
    funcs = data.setdefault("functions", {})
    func = funcs.get(start)
    if not isinstance(func, dict):
        func = {
            "address": start,
            "end_ea": context.get("end_ea"),
                "original_name": sanitize_label(context.get("function_name"), 160) if context.get("function_name") else "",
                "suggested_name": sanitize_label(entry.get("corrected_name"), 160) if entry.get("corrected_name") else "",
            "mode": context.get("mode"),
            "region_kind": context.get("region_kind"),
            "summary": "",
            "confidence": 0.0,
            "updated_at": utc_now(),
        }
        funcs[start] = func
    func["feedback"] = entry
    if entry.get("corrected_name"):
        func["suggested_name"] = entry.get("corrected_name")
    func["updated_at"] = utc_now()
    save_game_map(data, context)
    return game_map_path(context)


def sorted_functions(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    funcs = data.get("functions") or {}
    if not isinstance(funcs, dict):
        return []
    rows = [value for value in funcs.values() if isinstance(value, dict)]
    rows.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
    return rows


def prompt_memory(data: Dict[str, Any], limit: int = 12) -> Dict[str, Any]:
    hints = data.get("engine_hints") or {}
    top_hints = sorted(hints.items(), key=lambda item: int(item[1]), reverse=True)[:12]
    funcs = []
    for item in sorted_functions(data)[:limit]:
        funcs.append(
            {
                "address": item.get("address"),
                "name": item.get("suggested_name") or item.get("original_name"),
                "summary": sanitize_prompt_text(item.get("summary"), 700),
                "engine_hints": as_list(item.get("engine_hints"), 4),
                "confidence": item.get("confidence"),
                "feedback": item.get("feedback") or {},
            }
        )
    feedback_rows = []
    feedback = data.get("feedback") or {}
    if isinstance(feedback, dict):
        rows = [value for value in feedback.values() if isinstance(value, dict)]
        rows.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
        for item in rows[:8]:
            feedback_rows.append({
                "address": item.get("address"),
                "function_name": item.get("function_name"),
                "corrected_name": item.get("corrected_name"),
                "corrected_role": item.get("corrected_role"),
                "usefulness": item.get("usefulness"),
                "strategy": item.get("strategy"),
                "notes": sanitize_prompt_text(item.get("notes"), 900),
                "updated_at": item.get("updated_at"),
            })
    return {
        "known_engine_hints": [{"hint": key, "count": count} for key, count in top_hints],
        "recent_function_findings": funcs,
        "recent_feedback": feedback_rows,
    }


def render_game_map(data: Dict[str, Any], limit: int = 40) -> str:
    db = data.get("database") or {}
    funcs = sorted_functions(data)
    hints = data.get("engine_hints") or {}
    feedback = data.get("feedback") or {}
    top_hints = sorted(hints.items(), key=lambda item: int(item[1]), reverse=True)[:12]
    lines = [
        "Database: %s" % sanitize_label(db.get("root_filename") or db.get("input_file") or "unknown", 160),
        "Functions analyzed: %d" % len(funcs),
        "User corrections: %d" % (len(feedback) if isinstance(feedback, dict) else 0),
        "Updated: %s" % (data.get("updated_at") or "-"),
    ]
    if top_hints:
        lines.append("Engine hints: %s" % ", ".join("%s x%s" % (key, count) for key, count in top_hints))
    lines.append("")
    if not funcs:
        lines.append("No local game map entries yet.")
        return "\n".join(lines)
    for item in funcs[:limit]:
        name = sanitize_label(item.get("suggested_name") or item.get("original_name") or "-", 160)
        lines.append("%s  %s  confidence=%.2f  mode=%s" % (
            item.get("address") or "-",
            name,
            float(item.get("confidence") or 0.0),
            item.get("mode") or "-",
        ))
        if item.get("summary"):
            lines.append("  %s" % sanitize_text(item.get("summary"), max_chars=900, collapse_ws=True))
        if item.get("engine_hints"):
            lines.append("  hints: %s" % ", ".join(str(x) for x in as_list(item.get("engine_hints"), 5)))
        if item.get("strings"):
            lines.append("  strings: %s" % " | ".join(str(x) for x in as_list(item.get("strings"), 3)))
        fb = item.get("feedback") or {}
        if isinstance(fb, dict) and fb:
            bits = []
            for key in ("corrected_name", "corrected_role", "usefulness", "strategy"):
                value = str(fb.get(key) or "").strip()
                if value:
                    bits.append("%s=%s" % (key, value))
            notes = str(fb.get("notes") or "").strip()
            if bits:
                lines.append("  feedback: %s" % ", ".join(bits))
            if notes:
                lines.append("  note: %s" % notes[:180])
        lines.append("")
    return "\n".join(lines).rstrip()
