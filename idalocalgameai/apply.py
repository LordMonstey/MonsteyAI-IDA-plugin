"""Apply reviewed LLM suggestions to IDA."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import ida_bytes
import ida_name
import idaapi
import idc

from .schemas import validate_function_name


def parse_ea(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text, 16)


def current_function_name(start_ea: int) -> str:
    try:
        name = ida_name.get_name(start_ea)
        if name:
            return str(name)
    except Exception:
        pass
    return str(idc.get_func_name(start_ea) or "")


def is_ida_default_function_name(name: Any) -> bool:
    text = str(name or "").strip()
    if not text:
        return True
    patterns = (
        r"^sub_[0-9A-Fa-f]+$",
        r"^j_sub_[0-9A-Fa-f]+$",
        r"^nullsub_\d+$",
        r"^loc_[0-9A-Fa-f]+$",
        r"^locret_[0-9A-Fa-f]+$",
        r"^unknown_libname_\d+$",
    )
    return any(re.match(pattern, text) for pattern in patterns)


def apply_function_name(start_ea: int, analysis: Dict[str, Any], only_if_default: bool = False) -> Dict[str, Any]:
    name = validate_function_name(analysis.get("suggested_function_name"))
    if not name:
        return {"ok": False, "message": "No valid suggested_function_name to apply"}
    old_name = current_function_name(start_ea)
    if only_if_default and not is_ida_default_function_name(old_name):
        return {
            "ok": False,
            "skipped": True,
            "message": "Skipped auto rename: current name %s is not an IDA default sub_ name" % (old_name or "unknown"),
        }
    ok = ida_name.set_name(start_ea, name, ida_name.SN_CHECK | ida_name.SN_NOWARN)
    if ok:
        return {"ok": True, "old_name": old_name, "new_name": name, "message": "Renamed %s to %s" % ("0x%X" % start_ea, name)}
    return {"ok": False, "message": "IDA rejected name %s" % name}


def apply_comments(analysis: Dict[str, Any], max_comments: int = 12) -> List[Dict[str, Any]]:
    results = []
    comments = analysis.get("comments") or []
    if not isinstance(comments, list):
        return [{"ok": False, "message": "comments is not a list"}]
    for item in comments[:max_comments]:
        if not isinstance(item, dict):
            continue
        try:
            ea = parse_ea(item.get("address"))
        except Exception:
            continue
        text = str(item.get("text") or "").strip()
        if not text:
            continue
        if len(text) > 900:
            text = text[:900] + "..."
        ok = idc.set_cmt(ea, "AI: " + text, 0)
        results.append({"ok": bool(ok), "message": "Comment %s" % ("0x%X" % ea)})
    return results


def rgb(r: int, g: int, b: int) -> int:
    """IDA item colors use COLORREF/BGR ordering."""
    return (int(b) << 16) | (int(g) << 8) | int(r)


KIND_ITEM_COLORS = {
    "asm": rgb(48, 72, 96),
    "call": rgb(43, 92, 58),
    "xref": rgb(72, 54, 104),
    "string": rgb(92, 74, 36),
    "import": rgb(42, 88, 82),
    "pseudocode": rgb(46, 68, 104),
    "constant": rgb(92, 48, 72),
    "candidate": rgb(38, 92, 54),
    "experiment": rgb(42, 78, 96),
    "structure": rgb(92, 48, 72),
    "note": rgb(62, 66, 70),
}

REVIEW_COLOR = rgb(58, 86, 116)


def confidence_color(confidence: Any) -> int:
    try:
        value = float(confidence)
    except Exception:
        value = 0.0
    if value >= 0.72:
        return rgb(38, 92, 54)
    if value >= 0.45:
        return rgb(96, 78, 36)
    return rgb(92, 48, 48)


def set_item_color(ea: int, color: int) -> bool:
    try:
        ida_bytes.set_color(ea, ida_bytes.CIC_ITEM, color)
        return True
    except Exception:
        try:
            idc.set_color(ea, idc.CIC_ITEM, color)
            return True
        except Exception:
            return False


def merge_ai_comment(ea: int, new_text: str) -> str:
    existing = idc.get_cmt(ea, 0) or ""
    ai_text = "AI: " + new_text.strip()
    if not existing:
        return ai_text
    lines = [line for line in existing.splitlines() if not line.strip().startswith("AI:")]
    lines.append(ai_text)
    return "\n".join(line for line in lines if line.strip())


def set_ai_comment(ea: int, text: str) -> bool:
    text = str(text or "").strip()
    if not text:
        return False
    if len(text) > 900:
        text = text[:900] + "..."
    return bool(idc.set_cmt(ea, merge_ai_comment(ea, text), 0))


def mark_review_item(ea: int, note: str = "") -> Dict[str, Any]:
    text = str(note or "").strip()
    if not text:
        text = "Monstey review point: inspect this focus, trace XREFs, and decide whether it is a hook/map candidate."
    ok_comment = set_ai_comment(ea, text)
    ok_color = set_item_color(ea, REVIEW_COLOR)
    return {
        "ok": bool(ok_comment or ok_color),
        "message": "Marked review point %s" % ("0x%X" % int(ea)),
    }


def apply_colored_annotations(
    analysis: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None,
    max_comments: int = 16,
    max_evidence: int = 36,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    context = context or {}

    start = context.get("start_ea")
    if start:
        try:
            ea = parse_ea(start)
            summary = str(analysis.get("summary") or "").strip()
            if summary:
                ok_comment = set_ai_comment(ea, "Summary: " + summary)
                ok_color = set_item_color(ea, confidence_color(analysis.get("confidence")))
                results.append({"ok": bool(ok_comment or ok_color), "message": "Summary annotation %s" % ("0x%X" % ea)})
        except Exception:
            pass

    comments = analysis.get("comments") or []
    if isinstance(comments, list):
        for item in comments[:max_comments]:
            if not isinstance(item, dict):
                continue
            try:
                ea = parse_ea(item.get("address"))
            except Exception:
                continue
            text = str(item.get("text") or "").strip()
            if not text:
                continue
            ok_comment = set_ai_comment(ea, text)
            ok_color = set_item_color(ea, confidence_color(item.get("confidence")))
            results.append({"ok": bool(ok_comment or ok_color), "message": "Comment/color %s" % ("0x%X" % ea)})

    evidence = analysis.get("evidence") or []
    if isinstance(evidence, list):
        for item in evidence[:max_evidence]:
            if not isinstance(item, dict):
                continue
            try:
                ea = parse_ea(item.get("address"))
            except Exception:
                continue
            kind = str(item.get("kind") or "note").lower()
            color = KIND_ITEM_COLORS.get(kind, KIND_ITEM_COLORS["note"])
            text = str(item.get("text") or item.get("value") or item.get("reason") or "").strip()
            ok_color = set_item_color(ea, color)
            ok_comment = False
            if text:
                ok_comment = set_ai_comment(ea, "Evidence [%s]: %s" % (kind, text))
            results.append({"ok": bool(ok_color or ok_comment), "message": "Evidence color %s %s" % (kind, "0x%X" % ea)})

    return results or [{"ok": False, "message": "No AI annotations to apply"}]


def refresh_ida() -> None:
    try:
        idaapi.refresh_idaview_anyway()
    except Exception:
        pass
    try:
        import ida_kernwin

        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass
        for name in ("IWID_DISASMS", "IWID_NAMES", "IWID_FUNCS", "IWID_PSEUDOCODE"):
            try:
                ida_kernwin.request_refresh(getattr(ida_kernwin, name))
            except Exception:
                pass
    except Exception:
        pass
