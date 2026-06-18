"""Static integration adapters for external reverse-engineering evidence."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from typing import Any, Dict, Iterable, List, Optional

from .sanitize import MAX_PARSE_CHARS, sanitize_label, sanitize_prompt_text, sanitize_text


ADDRESS_RE = re.compile(r"\b0x[0-9A-Fa-f]{4,}\b")


INTEGRATION_PRESETS = [
    {
        "key": "diff",
        "title": "Diaphora / BinDiff",
        "kind": "diff",
        "source": "diff",
        "accent": "#ffd58a",
        "hint": "old/new matches, changed constants, changed calls, moved offsets",
    },
    {
        "key": "rules",
        "title": "capa / YARA",
        "kind": "capability",
        "source": "rules",
        "accent": "#9bd7ff",
        "hint": "capabilities, subsystem labels, custom game rules",
    },
    {
        "key": "crypto",
        "title": "FindCrypt",
        "kind": "crypto_signature",
        "source": "findcrypt",
        "accent": "#f0a7c6",
        "hint": "hash/checksum/string-id constants and routines",
    },
    {
        "key": "deobf",
        "title": "D-810",
        "kind": "deobf",
        "source": "d810",
        "accent": "#d2b6ff",
        "hint": "simplified branches, opaque predicate notes, deobf hints",
    },
    {
        "key": "structure",
        "title": "Structures / VTables",
        "kind": "structure",
        "source": "structure",
        "accent": "#b8d6ff",
        "hint": "field offsets, object names, vtables, HexRaysPyTools notes",
    },
    {
        "key": "signature",
        "title": "Signature Packs",
        "kind": "signature",
        "source": "signature",
        "accent": "#98f0df",
        "hint": "old dump names, function fingerprints, local sig matches",
    },
    {
        "key": "notes",
        "title": "Analyst Notes",
        "kind": "note",
        "source": "analyst",
        "accent": "#d7dde5",
        "hint": "manual static notes anchored to addresses",
    },
]


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


def _preset(source_key: str) -> Dict[str, Any]:
    key = sanitize_label(source_key or "", 64).lower()
    for preset in INTEGRATION_PRESETS:
        if preset["key"] == key:
            return preset
    return INTEGRATION_PRESETS[-1]


def _fmt_ea(value: Any) -> str:
    try:
        text = sanitize_label(value, 80)
        if not text:
            return ""
        if text.lower().startswith("0x"):
            return "0x%X" % int(text, 16)
        if re.fullmatch(r"[0-9A-Fa-f]{5,}", text):
            return "0x%X" % int(text, 16)
        return "0x%X" % int(text, 10)
    except Exception:
        match = ADDRESS_RE.search(str(value or ""))
        return match.group(0) if match else ""


def _extract_address(value: Any) -> str:
    if isinstance(value, dict):
        for key in (
            "address",
            "ea",
            "va",
            "rva",
            "function",
            "function_address",
            "function_ea",
            "new_address",
            "old_address",
            "match_address",
            "addr",
            "from",
            "to",
        ):
            address = _fmt_ea(value.get(key))
            if address:
                return address
        return _extract_address(json.dumps(value, sort_keys=True, default=str))
    match = ADDRESS_RE.search(sanitize_text(value, max_chars=2000))
    return match.group(0) if match else ""


def _row_text(row: Dict[str, Any], source_key: str) -> str:
    preset = _preset(source_key)
    interesting = []
    preferred_keys = (
        "name",
        "old_name",
        "new_name",
        "matched_name",
        "rule",
        "namespace",
        "capability",
        "description",
        "summary",
        "text",
        "comment",
        "change",
        "type",
        "confidence",
        "score",
        "ratio",
        "old_address",
        "new_address",
        "bytes",
        "constant",
        "string",
        "field",
        "offset",
    )
    for key in preferred_keys:
        value = row.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True, default=str)
        interesting.append("%s=%s" % (sanitize_label(key, 40), sanitize_prompt_text(value, 180)))
    if interesting:
        return "%s: %s" % (preset["source"], "; ".join(interesting))
    return "%s: %s" % (preset["source"], _clean(json.dumps(row, sort_keys=True, default=str), 500))


def _rows_from_json(obj: Any) -> List[Any]:
    if isinstance(obj, list):
        return obj
    if not isinstance(obj, dict):
        return [obj]
    for key in ("items", "evidence", "matches", "results", "functions", "rules", "capabilities"):
        rows = obj.get(key)
        if isinstance(rows, list):
            return rows
        if isinstance(rows, dict):
            return list(rows.values())
    return [obj]


def _parse_csv_rows(text: str) -> List[Dict[str, Any]]:
    sample = sanitize_text(text, max_chars=MAX_PARSE_CHARS)
    if "," not in sample or "\n" not in sample:
        return []
    try:
        reader = csv.DictReader(io.StringIO(sample))
        rows = [dict(row) for row in reader if any(str(value or "").strip() for value in row.values())]
        if rows and any(_extract_address(row) for row in rows[:8]):
            return rows
    except Exception:
        pass
    return []


def normalize_integration_text(source_key: str, text: str, context: Optional[Dict[str, Any]] = None) -> str:
    """Convert external plugin output into Evidence Sources line format."""
    preset = _preset(source_key)
    raw = sanitize_text(text, max_chars=MAX_PARSE_CHARS).strip()
    if not raw:
        return ""
    lines: List[str] = []
    rows: List[Any] = []

    try:
        rows = _rows_from_json(json.loads(raw))
    except Exception:
        rows = _parse_csv_rows(raw)

    if rows:
        for row in rows[:500]:
            if isinstance(row, dict):
                address = _extract_address(row)
                body = _row_text(row, source_key)
            else:
                address = _extract_address(row)
                body = "%s: %s" % (preset["source"], sanitize_prompt_text(row, 500))
            if address:
                lines.append("%s %s %s" % (preset["kind"], address, body))
            else:
                lines.append("note %s" % body)
        return "\n".join(lines)

    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        address = _extract_address(line)
        if address:
            body = ADDRESS_RE.sub("", line, count=1).strip(" :-")
            lines.append("%s %s %s: %s" % (preset["kind"], address, preset["source"], sanitize_prompt_text(body, 520)))
        else:
            lines.append("note %s: %s" % (preset["source"], sanitize_prompt_text(line, 520)))
    return "\n".join(lines)


def integration_template_text(source_key: str) -> str:
    preset = _preset(source_key)
    key = preset["key"]
    if key == "diff":
        return (
            "0x140123456 old_name=player_damage_calc new_name=sub_140223456 "
            "change=constant 100.0 -> 85.0 score=0.91"
        )
    if key == "rules":
        return "0x140123456 rule=game.bitstream_reader capability=Reads packed fields and updates output structure"
    if key == "crypto":
        return "0x140123456 FindCrypt: Murmur/FNV-like constants near string-id hash loop"
    if key == "deobf":
        return "0x140123456 D-810: opaque predicate removed; simplified branch reaches value clamp"
    if key == "structure":
        return "0x140123456 HexRaysPyTools: PlayerState-like object, fields +0x28 +0x30 +0x74"
    if key == "signature":
        return "0x140123456 old dump matched accumulate_damage_modifiers confidence=0.82 bytesig=48 89 5C 24 ??"
    return "0x140123456 analyst note: caller path suggests mapper/helper, inspect consumers before naming"


def render_integration_preview(source_key: str, text: str, context: Optional[Dict[str, Any]] = None) -> str:
    preset = _preset(source_key)
    normalized = normalize_integration_text(source_key, text, context)
    count = len([line for line in normalized.splitlines() if line.strip()])
    return (
        "%s\nkind=%s source=%s rows=%d\n\n%s"
        % (preset["title"], preset["kind"], preset["source"], count, normalized or "-")
    )


def _context_lines(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in _as_list(_as_dict(context.get("assembly")).get("lines")):
        if isinstance(item, dict):
            out.append(item)
    for item in _as_list(_as_dict(context.get("decompiler")).get("lines")):
        if isinstance(item, dict):
            out.append(item)
    return out


def build_structure_scout_text(context: Dict[str, Any]) -> str:
    ctx = _as_dict(context)
    cues = _as_dict(ctx.get("semantic_cues"))
    start = ctx.get("start_ea") or ctx.get("current_ea") or ""
    lines: List[str] = []

    for item in _as_list(cues.get("structure_reads"))[:24]:
        item = _as_dict(item)
        address = item.get("address") or start
        text = "local structure scout: read base=%s offset=%s line=%s" % (
            item.get("base") or "?",
            item.get("offset") or "?",
            _clean(item.get("line"), 240),
        )
        lines.append("structure %s %s" % (address, text))

    for item in _as_list(cues.get("output_layout_writes"))[:24]:
        item = _as_dict(item)
        address = item.get("address") or start
        text = "local structure scout: output write base=%s slot=%s line=%s" % (
            item.get("base") or "?",
            item.get("offset_or_index") or "?",
            _clean(item.get("line"), 240),
        )
        lines.append("structure %s %s" % (address, text))

    for item in _context_lines(ctx)[:240]:
        text = str(item.get("text") or "")
        low = text.lower()
        if "vftable" not in low and "vtable" not in low and "::`vftable'" not in low:
            continue
        address = item.get("address") or start
        lines.append("structure %s local structure scout: vtable hint line=%s" % (address, _clean(text, 260)))
        if len(lines) >= 64:
            break

    if not lines:
        lines.append("note local structure scout: no strong field/vtable evidence in current bounded context")
    return "\n".join(lines[:80])


def build_signature_scout_text(context: Dict[str, Any]) -> str:
    ctx = _as_dict(context)
    start = ctx.get("start_ea") or ctx.get("current_ea") or ""
    function_name = _clean(ctx.get("function_name") or "unknown", 120)
    asm_lines = _as_list(_as_dict(ctx.get("assembly")).get("lines"))
    xrefs = _as_dict(ctx.get("xrefs"))
    semantic = _as_dict(ctx.get("semantic_cues"))
    text_lines = []
    mnemonics = []

    for item in asm_lines[:180]:
        item = _as_dict(item)
        text = str(item.get("text") or "")
        text_lines.append(re.sub(r"0x[0-9A-Fa-f]+", "0xADDR", text))
        match = re.search(r"\b([a-z][a-z0-9]{1,8})\b", text.lower())
        if match:
            mnemonics.append(match.group(1))

    digest = hashlib.sha1("\n".join(text_lines).encode("utf-8", "replace")).hexdigest()[:16]
    callees = []
    for item in _as_list(xrefs.get("callees"))[:12]:
        item = _as_dict(item)
        value = item.get("name") or item.get("to")
        if value:
            callees.append(str(value))
    strings = []
    for item in _as_list(xrefs.get("strings"))[:10] + _as_list(semantic.get("string_anchors"))[:10]:
        item = _as_dict(item)
        value = item.get("value") or item.get("string")
        if value and str(value) not in strings:
            strings.append(str(value))

    lines = [
        "signature %s local signature scout: name=%s asm_fingerprint=%s asm_lines=%d mnemonic_shape=%s"
        % (start, function_name, digest, len(asm_lines), ",".join(mnemonics[:24])),
    ]
    if callees:
        lines.append("signature %s local signature scout: callee_shape=%s" % (start, ", ".join(callees[:12])))
    if strings:
        lines.append("signature %s local signature scout: string_anchors=%s" % (start, " | ".join(_clean(s, 120) for s in strings[:8])))
    return "\n".join(lines)


def build_all_local_scouts_text(context: Dict[str, Any]) -> str:
    return "\n".join(
        part
        for part in (
            build_structure_scout_text(context),
            build_signature_scout_text(context),
        )
        if str(part or "").strip()
    )
