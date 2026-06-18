"""Static external evidence bridge for Monstey analyses.

The plugin should not have to embed every external reverse-engineering tool.
Instead, tools can export small facts here: diff results, rule matches,
deobfuscation notes, structure recovery hints, signatures, and analyst notes.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .dump_context import safe_key
from .sanitize import MAX_PARSE_CHARS, sanitize_evidence_kind, sanitize_label, sanitize_prompt_text, sanitize_text


ADDRESS_RE = re.compile(r"\b0x[0-9A-Fa-f]{4,}\b")
KIND_ALIASES = {
    "diaphora": "diff",
    "bindiff": "diff",
    "diff": "diff",
    "pseudo_diff": "diff",
    "capa": "capability",
    "rule": "capability",
    "yara": "signature",
    "findcrypt": "crypto_signature",
    "crypto": "crypto_signature",
    "d810": "deobf",
    "deobf": "deobf",
    "hexrayspytools": "structure",
    "struct": "structure",
    "structure": "structure",
    "vtable": "structure",
    "sig": "signature",
    "signature": "signature",
    "xref": "xref",
    "string": "string",
    "note": "note",
    "coverage": "coverage",
    "trace": "trace",
    "hook": "hook_log",
    "log": "hook_log",
}

STATIC_KINDS = {
    "diff",
    "capability",
    "signature",
    "crypto_signature",
    "deobf",
    "structure",
    "xref",
    "string",
    "note",
}

ALLOWED_KINDS = STATIC_KINDS | {"coverage", "trace", "hook_log"}


def _clean(value: Any, limit: int = 500) -> str:
    return sanitize_text(value, max_chars=limit, collapse_ws=True)


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value in (None, "", "-"):
        return []
    return [value]


def _parse_ea(value: Any) -> Optional[int]:
    try:
        text = str(value or "").strip()
        if not text:
            return None
        return int(text, 16 if text.lower().startswith("0x") else 10)
    except Exception:
        return None


def _fmt_ea(value: Any) -> str:
    ea = _parse_ea(value)
    return "0x%X" % ea if ea is not None else ""


def external_evidence_dir() -> str:
    root = os.path.join(os.path.expanduser("~"), ".monstey-ai-plugin", "external_evidence")
    os.makedirs(root, exist_ok=True)
    return root


def external_evidence_path(database: Dict[str, Any]) -> str:
    root_name = safe_key(
        _as_dict(database).get("root_filename")
        or _as_dict(database).get("input_file")
        or "unknown_dump"
    )
    return os.path.join(external_evidence_dir(), "%s.external_evidence.txt" % root_name)


def load_external_evidence(database: Dict[str, Any]) -> str:
    path = external_evidence_path(database)
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return sanitize_text(handle.read())
    except Exception:
        pass
    return ""


def save_external_evidence(database: Dict[str, Any], text: str) -> str:
    path = external_evidence_path(database)
    with open(path, "w", encoding="utf-8", errors="replace") as handle:
        handle.write(sanitize_text(text))
    return path


def template_text() -> str:
    return """# Monstey static evidence sources
# Paste JSON, JSONL, or simple lines.
# Supported static kinds: diff, capability, signature, crypto_signature, deobf, structure, xref, string, note.
#
# Simple line format:
# kind 0xADDRESS text...
#
# Examples:
diff 0x140123456 changed constant from 100.0 to 85.0 in new dump; likely balance/tuning candidate
capability 0x140222000 capa: reads/writes packed data and references network-style strings
crypto_signature 0x140330010 FindCrypt: FNV/Murmur-like constants near string hash routine
deobf 0x140440000 D-810: removed opaque predicates; inspect simplified pseudocode before naming
structure 0x140550000 HexRaysPyTools: vtable/field pattern suggests PlayerState-like object, fields +0x28 +0x30
signature 0x140660000 local sig matched old dump function accumulate_damage_modifiers confidence=0.82
note 0x140770000 static analyst note: caller path suggests inventory stack clamp, not direct damage
"""


def _normalize_kind(value: Any) -> str:
    key = sanitize_label(value or "note", 64).lower().replace("-", "_").replace(" ", "_")
    return sanitize_evidence_kind(KIND_ALIASES.get(key, key or "note"), ALLOWED_KINDS, "note")


def _extract_address_from_text(text: str) -> str:
    match = ADDRESS_RE.search(text or "")
    return match.group(0) if match else ""


def _item_from_mapping(item: Dict[str, Any], default_source: str = "manual") -> Dict[str, Any]:
    kind = _normalize_kind(item.get("kind") or item.get("type") or item.get("source_kind") or default_source)
    source = sanitize_label(item.get("source") or item.get("tool") or default_source, 80)
    address = (
        item.get("address")
        or item.get("ea")
        or item.get("function")
        or item.get("function_address")
        or item.get("from")
        or item.get("to")
        or _extract_address_from_text(str(item))
    )
    text = (
        item.get("text")
        or item.get("summary")
        or item.get("description")
        or item.get("rule")
        or item.get("name")
        or item.get("value")
        or json.dumps(item, sort_keys=True)
    )
    tags = item.get("tags") or item.get("labels") or []
    if not isinstance(tags, list):
        tags = [tags]
    try:
        confidence = float(item.get("confidence"))
    except Exception:
        confidence = 0.55
    return {
        "kind": kind,
        "source": source,
        "address": _fmt_ea(address),
        "text": sanitize_prompt_text(text, 700),
        "confidence": max(0.0, min(1.0, confidence)),
        "tags": [sanitize_label(tag, 40) for tag in tags[:8] if sanitize_label(tag, 40)],
        "static": kind in STATIC_KINDS,
        "raw": item,
    }


def _item_from_line(line: str) -> Optional[Dict[str, Any]]:
    text = str(line or "").strip()
    if not text or text.startswith("#"):
        return None
    parts = text.split(None, 2)
    if len(parts) >= 2 and ADDRESS_RE.match(parts[1]):
        kind = _normalize_kind(parts[0])
        address = parts[1]
        body = parts[2] if len(parts) >= 3 else ""
        source = parts[0]
    else:
        address = _extract_address_from_text(text)
        first = parts[0] if parts else "note"
        kind = _normalize_kind(first)
        source = first if first.lower() in KIND_ALIASES else "manual"
        body = text
    if not address and kind != "note":
        return None
    return {
        "kind": kind,
        "source": sanitize_label(source, 80),
        "address": _fmt_ea(address),
        "text": sanitize_prompt_text(body, 700),
        "confidence": 0.6 if kind in STATIC_KINDS else 0.45,
        "tags": [],
        "static": kind in STATIC_KINDS,
        "raw": text,
    }


def parse_external_evidence(text: str) -> List[Dict[str, Any]]:
    raw = sanitize_text(text, max_chars=MAX_PARSE_CHARS).strip()
    if not raw:
        return []
    items: List[Dict[str, Any]] = []
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            source = _clean(obj.get("source") or obj.get("tool") or "json", 80)
            rows = obj.get("items") or obj.get("evidence") or obj.get("matches") or obj.get("results") or []
            if isinstance(rows, dict):
                rows = list(rows.values())
            if not isinstance(rows, list):
                rows = [obj]
            for row in rows:
                if isinstance(row, dict):
                    items.append(_item_from_mapping(row, default_source=source))
                else:
                    parsed = _item_from_line(str(row))
                    if parsed:
                        parsed["source"] = source
                        items.append(parsed)
            return items[:500]
        if isinstance(obj, list):
            for row in obj:
                if isinstance(row, dict):
                    items.append(_item_from_mapping(row, default_source="json"))
                else:
                    parsed = _item_from_line(str(row))
                    if parsed:
                        items.append(parsed)
            return items[:500]
    except Exception:
        pass

    for line in raw.splitlines():
        parsed = _item_from_line(line)
        if parsed:
            items.append(parsed)
    return items[:500]


def _context_range(context: Dict[str, Any]) -> Tuple[Optional[int], Optional[int]]:
    start = _parse_ea(_as_dict(context).get("start_ea"))
    end = _parse_ea(_as_dict(context).get("end_ea"))
    return start, end


def _item_matches_context(item: Dict[str, Any], context: Dict[str, Any]) -> bool:
    address = _parse_ea(item.get("address"))
    if address is None:
        return True
    start, end = _context_range(context)
    if start is not None and end is not None and start <= address < end:
        return True
    current = _parse_ea(context.get("current_ea"))
    if current is not None and address == current:
        return True
    focus = _as_dict(context.get("focus"))
    focus_ea = _parse_ea(focus.get("item_head") or focus.get("ea"))
    return bool(focus_ea is not None and address == focus_ea)


def _rank_item(item: Dict[str, Any], context: Dict[str, Any]) -> int:
    rank = 0
    if _item_matches_context(item, context):
        rank += 100
    kind = item.get("kind")
    if kind in ("diff", "deobf", "structure", "signature", "crypto_signature", "capability"):
        rank += 20
    if item.get("address"):
        rank += 8
    return rank


def evidence_summary(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_kind: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    static_count = 0
    for item in items:
        kind = str(item.get("kind") or "note")
        source = str(item.get("source") or "manual")
        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_source[source] = by_source.get(source, 0) + 1
        if item.get("static"):
            static_count += 1
    return {
        "total": len(items),
        "static_count": static_count,
        "by_kind": by_kind,
        "by_source": by_source,
    }


def render_external_evidence_text(payload: Dict[str, Any], limit: int = 120) -> str:
    items = _as_list(payload.get("items"))
    summary = _as_dict(payload.get("summary"))
    lines = [
        "External Evidence Sources",
        "total=%s static=%s" % (summary.get("total", 0), summary.get("static_count", 0)),
        "kinds=%s" % ", ".join("%s:%s" % (k, v) for k, v in sorted(_as_dict(summary.get("by_kind")).items())),
        "",
    ]
    for item in items[:limit]:
        lines.append(
            "%s %-16s %-18s %s"
            % (
                _clean(item.get("source"), 14),
                _clean(item.get("kind"), 16),
                _clean(item.get("address") or "-", 18),
                _clean(item.get("text"), 220),
            )
        )
    if len(items) > limit:
        lines.append("... %d more item(s)" % (len(items) - limit))
    return "\n".join(lines)


def external_evidence_payload(database: Dict[str, Any], text: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    context = context or {}
    items = parse_external_evidence(text)
    ranked = sorted(items, key=lambda row: _rank_item(row, context), reverse=True)
    matched = [item for item in ranked if _item_matches_context(item, context)]
    selected = (matched or ranked)[:80]
    payload = {
        "present": bool(items),
        "path": external_evidence_path(database),
        "policy": "static-first external evidence for dumps; treat as analyst/tool facts to verify against current IDB context",
        "updated_at": round(time.time(), 3),
        "summary": evidence_summary(items),
        "matched_count": len(matched),
        "items": selected,
    }
    payload["analysis_text"] = build_static_analysis_text(payload, context)
    return payload


def build_static_analysis_text(payload: Dict[str, Any], context: Dict[str, Any] = None) -> List[str]:
    items = _as_list(payload.get("items"))
    out: List[str] = []
    if not items:
        return out
    by_kind = _as_dict(_as_dict(payload.get("summary")).get("by_kind"))
    out.append(
        "Static evidence loaded: %d selected item(s), %d item(s) match the current focus/function."
        % (len(items), int(payload.get("matched_count") or 0))
    )
    if by_kind.get("diff"):
        out.append("Diff evidence is present: prioritize changed constants, calls, offsets, and renamed matches when porting hooks between dumps.")
    if by_kind.get("deobf"):
        out.append("Deobfuscation evidence is present: compare simplified/deobfuscated claims before trusting raw red/ASM control flow.")
    if by_kind.get("structure"):
        out.append("Structure/class evidence is present: use recovered fields, vtables, and object names to improve argument and offset naming.")
    if by_kind.get("capability"):
        out.append("Capability/rule evidence is present: use rule matches as subsystem labels, not as proof of exact gameplay behavior.")
    if by_kind.get("crypto_signature"):
        out.append("Crypto/hash signatures are present: avoid mistaking hash/checksum/string-id routines for gameplay value handlers.")
    if by_kind.get("signature"):
        out.append("Signature matches are present: compare old known names with current local bytes/XREFs before auto-renaming.")
    if any(not item.get("static") for item in items):
        out.append("Runtime-style evidence was imported, but this workflow is dump/static-first; treat those rows as offline notes unless reproduced.")
    return out[:12]


def _append_unique(items: List[Any], value: Any, limit: int = 16) -> None:
    text = _clean(value, 700)
    if not text:
        return
    seen = {_clean(item, 700).lower() for item in items}
    if text.lower() in seen:
        return
    items.append(text)
    del items[limit:]


def _trainer_dict(analysis: Dict[str, Any]) -> Dict[str, Any]:
    trainer = analysis.get("trainer_assessment")
    if not isinstance(trainer, dict):
        trainer = {}
        analysis["trainer_assessment"] = trainer
    for key, default in (
        ("what_happens_if_hooked", []),
        ("values_to_log_first", []),
        ("candidate_trainer_features", []),
        ("recommended_experiments", []),
        ("not_useful_for", []),
        ("stability_notes", []),
    ):
        if not isinstance(trainer.get(key), list):
            trainer[key] = [] if trainer.get(key) in (None, "", "-") else [trainer.get(key)]
    return trainer


def apply_external_evidence_to_analysis(analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(context.get("external_evidence"))
    items = _as_list(payload.get("items"))
    if not items:
        return analysis
    notes = build_static_analysis_text(payload, context)
    analysis["external_evidence_summary"] = {
        "present": True,
        "matched_count": payload.get("matched_count") or 0,
        "summary": payload.get("summary") or {},
        "analysis_text": notes,
    }
    evidence = analysis.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
        analysis["evidence"] = evidence
    for item in items[:18]:
        if not isinstance(item, dict):
            continue
        evidence.append({
            "kind": "external_%s" % _clean(item.get("kind") or "note", 40),
            "address": item.get("address") or "",
            "text": "[%s] %s" % (_clean(item.get("source") or "external", 40), _clean(item.get("text"), 500)),
        })

    relevance = analysis.get("game_relevance")
    if not isinstance(relevance, list):
        relevance = []
        analysis["game_relevance"] = relevance
    for note in notes[:6]:
        _append_unique(relevance, note, limit=14)

    risks = analysis.get("risks")
    if not isinstance(risks, list):
        risks = []
        analysis["risks"] = risks
    _append_unique(risks, "External evidence is imported from static tools/notes; verify it against the current dump before renaming or choosing a hook.", limit=12)

    trainer = _trainer_dict(analysis)
    kinds = {str(item.get("kind") or "") for item in items if isinstance(item, dict)}
    if "diff" in kinds:
        _append_unique(trainer["recommended_experiments"], "Use diff evidence to compare old/new constants, calls, field offsets, and control-flow around the current function.", 12)
        _append_unique(trainer["candidate_trainer_features"], "Version-porting report for old hooks: changed constants, moved offsets, renamed/signature-matched functions.", 12)
    if "deobf" in kinds:
        _append_unique(trainer["recommended_experiments"], "Compare raw ASM/pseudocode against deobfuscated notes before assigning behavior or hook surface.", 12)
    if "structure" in kinds:
        _append_unique(trainer["values_to_log_first"], "static structure fields/vtable hints from external evidence", 12)
        _append_unique(trainer["candidate_trainer_features"], "Structure-aware hook planning using recovered field names and offsets.", 12)
    if "crypto_signature" in kinds:
        _append_unique(trainer["not_useful_for"], "Direct gameplay mutation if the function is only a hash/checksum/string-id helper.", 12)
    if "signature" in kinds:
        _append_unique(trainer["recommended_experiments"], "Validate signature-matched old names against current bytes, XREFs, strings, and pseudocode before applying names.", 12)
    if _clean(trainer.get("usefulness")).lower() in ("", "-", "unknown"):
        trainer["usefulness"] = "medium" if kinds.intersection({"diff", "structure", "signature"}) else "low"
    if _clean(trainer.get("best_hook_strategy")).lower() in ("", "-", "unknown"):
        trainer["best_hook_strategy"] = "log_then_compare" if "diff" in kinds else "observe_only"
    return analysis
