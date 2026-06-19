"""Local post-processing for sparse LLM analysis results.

The LLM is useful for synthesis, but IDA already extracted hard local clues.
This module turns those clues into readable fallback fields when the model
returns sparse or generic JSON.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional


BLANK_STRINGS = {"", "-", "unknown", "none", "n/a", "null"}

GENERIC_TRAINER_LINES = (
    "hooking should mostly confirm call frequency",
    "whether this helper sits on a useful path",
    "confirm call frequency, arguments",
    "run observe-only logging: call count",
    "fast triage: call frequency",
)


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _clean(value: Any, limit: int = 300) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) > limit:
        return text[: max(0, limit - 3)].rstrip() + "..."
    return text


def _blankish(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in BLANK_STRINGS
    if isinstance(value, list):
        return not [item for item in value if not _blankish(item)]
    if isinstance(value, dict):
        return not any(not _blankish(item) for item in value.values())
    return False


def _append_unique(items: List[Any], value: Any, limit: int = 24) -> bool:
    if _blankish(value):
        return False
    text = _clean(value, 700)
    existing = {_clean(item, 700) for item in items}
    if text in existing:
        return False
    items.append(text)
    if len(items) > limit:
        del items[limit:]
    return True


def _is_generic_trainer_line(value: Any) -> bool:
    text = _clean(value, 700).lower()
    if not text:
        return True
    return any(pattern in text for pattern in GENERIC_TRAINER_LINES)


def _replace_generic_items(items: List[Any]) -> List[Any]:
    return [item for item in items if not _is_generic_trainer_line(item)]


def _first_cue_line(cues: Dict[str, Any], key: str, limit: int = 150) -> str:
    for item in _as_list(cues.get(key)):
        if isinstance(item, dict):
            line = item.get("line") or item.get("text") or item.get("value") or item.get("meaning") or ""
            if line:
                return _clean(line, limit)
        elif item:
            return _clean(item, limit)
    return ""


def _slot_labels(cues: Dict[str, Any], max_items: int = 3) -> str:
    labels: List[str] = []
    for item in _as_list(cues.get("output_layout_writes")):
        if not isinstance(item, dict):
            continue
        base = _clean(item.get("base") or "out", 32)
        offset = _clean(item.get("offset_or_index") or item.get("offset") or "?", 32)
        label = "%s[%s]" % (base, offset)
        if label not in labels:
            labels.append(label)
        if len(labels) >= max_items:
            break
    return ", ".join(labels)


def _caller_hint(context: Dict[str, Any]) -> str:
    xrefs = _as_dict(context.get("xrefs"))
    callers = [item for item in _as_list(xrefs.get("callers")) if isinstance(item, dict)]
    if not callers:
        return ""
    first = callers[0]
    return _clean(first.get("function") or first.get("address") or "", 96)


def _specific_hook_effects(
    category: str,
    cues: Dict[str, Any],
    context: Dict[str, Any],
    readers: bool,
    output_writes: bool,
    numeric_ops: bool,
    mode_checks: bool,
    dirty_masks: bool,
    bitwise: bool,
) -> List[str]:
    hint = _hint_text(context)
    caller = _caller_hint(context)
    slots = _slot_labels(cues)
    out: List[str] = []
    if category == "identity":
        out.append("Hooking should show identity/name parsing and output structure population; use XREF consumers to connect parsed identity to runtime entities.")
        out.append("Changing data here is more likely to break identity/state parsing than produce a trainer-facing stat change.")
    elif readers:
        reader_line = _first_cue_line(cues, "likely_reader_calls")
        detail = (" around `%s`" % reader_line) if reader_line else ""
        out.append("Hooking should reveal structured stream reads%s and the exact output fields populated from the stream." % detail)
        out.append("The useful result is a field map; mutate only after a caller or consumer proves which parsed field affects gameplay.")
    elif output_writes and numeric_ops:
        slot_text = slots or "the detected output slots"
        op_line = _first_cue_line(cues, "numeric_ops")
        out.append("Hooking should expose numeric values before they land in %s%s." % (slot_text, ("; cue: `%s`" % op_line) if op_line else ""))
        out.append("If the caller consumes %s directly, a gated post-original write is the first mutation surface to test." % slot_text)
    elif category == "damage" and numeric_ops:
        op_line = _first_cue_line(cues, "numeric_ops")
        out.append("Hooking should correlate calls with controlled damage received/done events and reveal which argument/return/nearby float changes%s." % (("; cue: `%s`" % op_line) if op_line else ""))
        out.append("Separate callers before mutation so received-damage and dealt-damage paths are not mixed.")
    elif output_writes:
        slot_text = slots or "the detected output fields"
        out.append("Hooking should show when %s are populated and whether the caller reads them immediately after the call." % slot_text)
    elif dirty_masks:
        mask_line = _first_cue_line(cues, "dirty_masks")
        out.append("Hooking should show state/update-mask transitions%s; the valuable target is probably the code that reacts to the dirty flag." % (("; cue: `%s`" % mask_line) if mask_line else ""))
    elif mode_checks:
        mode_line = _first_cue_line(cues, "mode_checks")
        out.append("Hooking should let you group behavior by selector/mode%s, then map which mode means replace/add/multiply/clamp." % (("; cue: `%s`" % mode_line) if mode_line else ""))
    elif bitwise:
        bit_line = _first_cue_line(cues, "bitwise_or_checksum_ops")
        out.append("Hooking should validate whether the bitwise path is decoding, hashing, or sanity checking%s before treating it as gameplay logic." % (("; cue: `%s`" % bit_line) if bit_line else ""))
    else:
        target = caller or _clean(context.get("function_name") or context.get("start_ea") or "this helper", 96)
        hint_suffix = (" against your hint `%s`" % _clean(hint, 80)) if hint else ""
        out.append("Hooking should classify `%s`%s: log caller, arguments, return, and touched memory to decide whether to move up to the caller or down to a callee." % (target, hint_suffix))
    if caller and not any(caller.lower() in item.lower() for item in out):
        out.append("Prioritize caller `%s` when interpreting logs; it is the nearest evidence for the gameplay contract." % caller)
    return out


def _has_generic_only(items: Any) -> bool:
    values = [_clean(item).lower() for item in _as_list(items)]
    if not values:
        return True
    concrete_tokens = ("0x", "a1", "a2", "a3", "offset", "+", "[", "]", "field", "mask", "float")
    return not any(any(token in value for token in concrete_tokens) for value in values)


def _type_from_line(line: str, offset: str = "") -> str:
    low = line.lower()
    if "_oword" in low or "oword" in low:
        return "oword"
    if "_qword" in low or " qword" in low:
        return "qword"
    if "_dword" in low or " dword" in low:
        return "dword"
    if "_word" in low or " word" in low:
        return "word"
    if "_byte" in low or " byte" in low:
        return "byte"
    if "float" in low or "xmm" in low or offset == "float":
        return "float"
    if "[" in str(offset):
        return "array_entry"
    return "unknown"


def _offset_entry(base: str, offset: str, line: str, address: str, meaning: str, confidence: float) -> Dict[str, Any]:
    return {
        "base": base or "unknown",
        "offset": str(offset or "0"),
        "type": _type_from_line(line, str(offset or "")),
        "meaning": meaning,
        "evidence": ("%s %s" % (address or "", _clean(line, 220))).strip(),
        "confidence": confidence,
    }


def _cue_text(item: Any) -> str:
    if not isinstance(item, dict):
        return _clean(item)
    line = item.get("line") or item.get("value") or item.get("text") or item.get("meaning") or ""
    address = item.get("address") or item.get("from") or ""
    if address:
        return "%s: %s" % (address, _clean(line, 240))
    return _clean(line, 240)


def _priority_strings(cues: Dict[str, Any]) -> List[Dict[str, Any]]:
    strings = []
    for item in _as_list(cues.get("string_anchors")):
        if isinstance(item, dict) and item.get("priority"):
            strings.append(item)
    return strings


def _process_name(context: Dict[str, Any]) -> str:
    game = _as_dict(context.get("game_context"))
    return _clean(game.get("process_display") or game.get("process_name") or game.get("selected_candidate") or "process", 80)


def _hint_text(context: Dict[str, Any]) -> str:
    analyst = _as_dict(context.get("analyst_context"))
    return _clean(analyst.get("user_hypothesis") or context.get("analyst_hint") or "", 1000)


def _name_from_hint(hint: str, cues: Dict[str, Any]) -> Optional[str]:
    low = hint.lower()
    output_writes = _as_list(cues.get("output_layout_writes"))
    numeric_ops = _as_list(cues.get("numeric_ops"))
    readers = _as_list(cues.get("likely_reader_calls"))
    priority_strings = _priority_strings(cues)
    string_text = " ".join(_clean(item.get("value"), 80).lower() for item in priority_strings)

    if readers and ("player" in string_text or "name" in string_text or "bungie" in string_text):
        return "deserialize_player_identity"
    if readers:
        return "parse_structured_bitstream"
    if output_writes and numeric_ops:
        if any(token in low for token in ("damage", "health", "hit")):
            return "accumulate_damage_modifiers"
        if any(token in low for token in ("stat", "modifier", "stack")):
            return "accumulate_stat_modifiers"
        return "accumulate_float_modifiers"
    if numeric_ops:
        if any(token in low for token in ("damage", "health", "hit", "received", "done")):
            return "trace_damage_modifier_math"
        if any(token in low for token in ("stat", "modifier", "stack")):
            return "trace_stat_modifier_math"
    if output_writes:
        return "populate_output_structure"
    return None


def _context_has_token(context: Dict[str, Any], tokens: Iterable[str]) -> bool:
    wanted = [token.lower() for token in tokens if len(token) >= 4]
    if not wanted:
        return False
    chunks: List[str] = []
    cues = _as_dict(context.get("semantic_cues"))
    for key in (
        "string_anchors",
        "reader_call_evidence",
        "structure_reads",
        "output_layout_writes",
        "dirty_masks",
        "numeric_ops",
        "mode_checks",
        "bitwise_or_checksum_ops",
    ):
        for item in _as_list(cues.get(key))[:24]:
            chunks.append(_cue_text(item))
    decompiler = _as_dict(context.get("decompiler"))
    chunks.extend(str(line) for line in _as_list(decompiler.get("lines"))[:180])
    hay = "\n".join(chunks).lower()
    return any(token in hay for token in wanted)


def _ensure_comments(analysis: Dict[str, Any], context: Dict[str, Any], notes: List[str]) -> None:
    comments = analysis.get("comments")
    if not isinstance(comments, list):
        comments = []
        analysis["comments"] = comments
    if comments:
        return
    start = str(context.get("start_ea") or context.get("current_ea") or "0x0")
    summary = _clean(analysis.get("summary"), 620)
    if summary:
        comments.append({"address": start, "text": "Summary: %s" % summary, "confidence": analysis.get("confidence") or 0.3})
    cues = _as_dict(context.get("semantic_cues"))
    for key, label in (
        ("output_layout_writes", "output write"),
        ("structure_reads", "structure read"),
        ("numeric_ops", "numeric op"),
        ("mode_checks", "mode check"),
        ("dirty_masks", "dirty mask"),
        ("string_anchors", "string"),
    ):
        for item in _as_list(cues.get(key))[:2]:
            if not isinstance(item, dict):
                continue
            address = str(item.get("address") or item.get("from") or start)
            text = "%s: %s" % (label, _cue_text(item))
            comments.append({"address": address, "text": text[:700], "confidence": 0.45})
            if len(comments) >= 8:
                notes.append("added local IDA comment suggestions from semantic cues")
                return


def _ensure_evidence(analysis: Dict[str, Any], context: Dict[str, Any], notes: List[str]) -> None:
    evidence = analysis.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
        analysis["evidence"] = evidence
    start = str(context.get("start_ea") or context.get("current_ea") or "0x0")
    existing = {_clean(item.get("text") if isinstance(item, dict) else item, 300) for item in evidence}
    cues = _as_dict(context.get("semantic_cues"))
    count_before = len(evidence)
    for key, kind in (
        ("output_layout_writes", "pseudocode"),
        ("structure_reads", "pseudocode"),
        ("numeric_ops", "pseudocode"),
        ("mode_checks", "pseudocode"),
        ("dirty_masks", "pseudocode"),
        ("bitwise_or_checksum_ops", "asm"),
        ("string_anchors", "string"),
    ):
        for item in _as_list(cues.get(key))[:5]:
            if not isinstance(item, dict):
                continue
            text = _cue_text(item)
            key_text = _clean(text, 300)
            if not key_text or key_text in existing:
                continue
            existing.add(key_text)
            evidence.append({
                "address": item.get("address") or item.get("from") or start,
                "kind": kind,
                "text": text,
            })
            if len(evidence) >= 26:
                break
        if len(evidence) >= 26:
            break
    if len(evidence) > count_before:
        notes.append("added local evidence rows from semantic cues")


def _ensure_bitstream(analysis: Dict[str, Any], cues: Dict[str, Any], notes: List[str]) -> None:
    bitstream = analysis.get("bitstream_deserialization")
    if not isinstance(bitstream, dict):
        bitstream = {}
        analysis["bitstream_deserialization"] = bitstream
    local_likelihood = str(cues.get("bitstream_or_structured_reader_likelihood") or "none")
    current = str(bitstream.get("likelihood") or "none").lower()
    if current in BLANK_STRINGS or current == "none" or (current == "low" and local_likelihood in ("medium", "high")):
        bitstream["likelihood"] = local_likelihood
    if not _as_list(bitstream.get("reader_calls")):
        bitstream["reader_calls"] = [
            "%s(%s, widths=%s)" % (item.get("call"), item.get("stream_arg"), item.get("widths"))
            for item in _as_list(cues.get("likely_reader_calls"))[:8]
            if isinstance(item, dict)
        ]
    if not _as_list(bitstream.get("output_layout")):
        bitstream["output_layout"] = [
            "%s[%s] <- %s" % (item.get("base"), item.get("offset_or_index"), _clean(item.get("line"), 140))
            for item in _as_list(cues.get("output_layout_writes"))[:8]
            if isinstance(item, dict)
        ]
    if not _as_list(bitstream.get("dirty_masks")):
        bitstream["dirty_masks"] = [
            "%s |= %s" % (item.get("target"), item.get("mask"))
            for item in _as_list(cues.get("dirty_masks"))[:8]
            if isinstance(item, dict)
        ]
    if not _as_list(bitstream.get("sanity_checks")):
        bitstream["sanity_checks"] = [
            "%s %s" % (item.get("operator"), item.get("value"))
            for item in _as_list(cues.get("bounds_checks"))[:8]
            if isinstance(item, dict)
        ]
    if not _as_list(bitstream.get("bitwise_checks")):
        bitstream["bitwise_checks"] = [_cue_text(item) for item in _as_list(cues.get("bitwise_or_checksum_ops"))[:8]]
    if not _as_list(bitstream.get("string_anchors")):
        bitstream["string_anchors"] = [
            "%s %s" % (item.get("address") or item.get("from") or "", _clean(item.get("value"), 180))
            for item in _as_list(cues.get("string_anchors"))[:8]
            if isinstance(item, dict)
        ]
    if local_likelihood and local_likelihood != "none":
        notes.append("merged local bitstream/structured-parse cues")


def _ensure_structure_offsets(analysis: Dict[str, Any], cues: Dict[str, Any], notes: List[str]) -> None:
    rows = analysis.get("structure_offsets")
    if not isinstance(rows, list):
        rows = []
        analysis["structure_offsets"] = rows
    before = len(rows)
    if before >= 6:
        return
    seen = {
        (str(item.get("base")), str(item.get("offset")))
        for item in rows
        if isinstance(item, dict)
    }
    for item in _as_list(cues.get("output_layout_writes"))[:12]:
        if not isinstance(item, dict):
            continue
        base = str(item.get("base") or "")
        offset = str(item.get("offset_or_index") or "0")
        key = (base, offset)
        if key in seen:
            continue
        seen.add(key)
        rows.append(_offset_entry(
            base,
            offset,
            str(item.get("line") or ""),
            str(item.get("address") or ""),
            "output field/array slot written by this function",
            0.55,
        ))
    for item in _as_list(cues.get("structure_reads"))[:12]:
        if len(rows) >= 20:
            break
        if not isinstance(item, dict):
            continue
        base = str(item.get("base") or "")
        offset = str(item.get("offset") or "0")
        key = (base, offset)
        if key in seen:
            continue
        seen.add(key)
        rows.append(_offset_entry(
            base,
            offset,
            str(item.get("line") or ""),
            str(item.get("address") or ""),
            "input object/temporary field read",
            0.42,
        ))
    if len(rows) > before:
        notes.append("built structure offset table from local reads/writes")


def _ensure_dataflow(analysis: Dict[str, Any], cues: Dict[str, Any], notes: List[str]) -> None:
    dataflow = analysis.get("dataflow")
    if not isinstance(dataflow, list):
        dataflow = []
        analysis["dataflow"] = dataflow
    before = len(dataflow)
    should_add_concrete = _has_generic_only(dataflow)
    if _as_list(cues.get("structure_reads")) and should_add_concrete:
        for item in _as_list(cues.get("structure_reads"))[:6]:
            if isinstance(item, dict):
                _append_unique(
                    dataflow,
                    "reads %s+%s -> %s" % (item.get("base"), item.get("offset"), _clean(item.get("line"), 180)),
                )
    if _as_list(cues.get("output_layout_writes")):
        for item in _as_list(cues.get("output_layout_writes"))[:8]:
            if isinstance(item, dict):
                _append_unique(
                    dataflow,
                    "writes %s[%s] <- %s" % (item.get("base"), item.get("offset_or_index"), _clean(item.get("line"), 180)),
                )
    if _as_list(cues.get("numeric_ops")):
        for item in _as_list(cues.get("numeric_ops"))[:5]:
            _append_unique(dataflow, "numeric transform: %s" % _cue_text(item))
    if _as_list(cues.get("mode_checks")):
        for item in _as_list(cues.get("mode_checks"))[:5]:
            if isinstance(item, dict):
                _append_unique(
                    dataflow,
                    "mode branch %s %s %s -> changes how the value is applied"
                    % (item.get("selector"), item.get("operator"), item.get("value")),
                )
    if _as_list(cues.get("dirty_masks")):
        for item in _as_list(cues.get("dirty_masks"))[:4]:
            if isinstance(item, dict):
                _append_unique(dataflow, "marks update/dirty flag: %s |= %s" % (item.get("target"), item.get("mask")))
    if len(dataflow) > before:
        notes.append("expanded concrete dataflow from local cues")


def _ensure_algorithm(analysis: Dict[str, Any], cues: Dict[str, Any], notes: List[str]) -> None:
    algorithm = analysis.get("algorithm")
    if not isinstance(algorithm, dict):
        algorithm = {"kind": "unknown", "description": _clean(algorithm)}
        analysis["algorithm"] = algorithm
    kind = _clean(algorithm.get("kind")).lower()
    description = _clean(algorithm.get("description"))
    if kind not in BLANK_STRINGS and kind not in {"unknown"} and description:
        return
    if _as_list(cues.get("likely_reader_calls")):
        algorithm["kind"] = "structured_parser"
        algorithm["description"] = "Repeated width-based reader calls suggest a structured bitstream/file/network parser; map fields before calling it a copy."
    elif _as_list(cues.get("output_layout_writes")) and _as_list(cues.get("numeric_ops")):
        algorithm["kind"] = "accumulator"
        algorithm["description"] = "The local code reads object fields, performs float/numeric transforms, and writes result slots in an output structure or array."
    elif _as_list(cues.get("output_layout_writes")):
        algorithm["kind"] = "structure_populator"
        algorithm["description"] = "The local code writes explicit output fields or array slots; treat it as structure population until stronger evidence names the gameplay system."
    elif _as_list(cues.get("bitwise_or_checksum_ops")):
        algorithm["kind"] = "validator"
        algorithm["description"] = "Bitwise operations/constants suggest validation, hashing, checksum, obfuscation, or packed-state handling."
    else:
        return
    notes.append("filled algorithm from local semantic cues")


def _ensure_summary_behavior(analysis: Dict[str, Any], context: Dict[str, Any], cues: Dict[str, Any], notes: List[str]) -> None:
    process = _process_name(context)
    hint = _hint_text(context)
    if _blankish(analysis.get("summary")):
        if _as_list(cues.get("output_layout_writes")) and _as_list(cues.get("numeric_ops")):
            summary = "Local pass: this function looks like a numeric accumulator/modifier for an output array or structure"
            if hint:
                summary += "; the analyst hint '%s' is plausible only if callers/strings tie those values to that system" % _clean(hint, 120)
            analysis["summary"] = summary + "."
        elif _as_list(cues.get("likely_reader_calls")):
            analysis["summary"] = "Local pass: repeated width-based reader calls make this look like structured parsing/deserialization, not a plain memory copy."
        elif _as_list(cues.get("output_layout_writes")):
            analysis["summary"] = "Local pass: this function writes explicit fields or array entries into an output object; the exact gameplay meaning is still unconfirmed."
        else:
            analysis["summary"] = "Local pass: sparse semantic evidence; use the focused pseudocode/assembly and XREFs before assigning a gameplay role."
        notes.append("filled empty summary from local cues")

    behavior = analysis.get("behavior")
    if not isinstance(behavior, list):
        behavior = []
        analysis["behavior"] = behavior
    if _has_generic_only(behavior):
        if _as_list(cues.get("numeric_ops")):
            _append_unique(behavior, "Performs float/numeric transforms such as min/max, add, multiply, or accumulator-style updates.")
        if _as_list(cues.get("mode_checks")):
            _append_unique(behavior, "Uses byte selector checks to choose how a value is applied to the output slot.")
        if _as_list(cues.get("output_layout_writes")):
            _append_unique(behavior, "Writes computed values into an output base/index rather than only returning a scalar.")
        if _as_list(cues.get("structure_reads")):
            _append_unique(behavior, "Reads several object fields through pointer offsets; map those offsets before naming the structure.")
        if len(behavior) > 0:
            notes.append("added concrete behavior bullets from local cues")

    relevance = analysis.get("game_relevance")
    if not isinstance(relevance, list):
        relevance = []
        analysis["game_relevance"] = relevance
    if _blankish(relevance):
        relevance.append(
            "For %s, this should be treated as local binary evidence first; process/web context can guide naming but cannot prove the gameplay role alone." % process
        )
        notes.append("filled process relevance with a conservative local-evidence note")


def _trainer_list(data: Dict[str, Any], key: str) -> List[Any]:
    value = data.get(key)
    if isinstance(value, list):
        return value
    value = [] if _blankish(value) else [str(value)]
    data[key] = value
    return value


def _ensure_trainer_assessment(analysis: Dict[str, Any], context: Dict[str, Any], cues: Dict[str, Any], notes: List[str]) -> None:
    trainer = analysis.get("trainer_assessment")
    if not isinstance(trainer, dict):
        trainer = {}
        analysis["trainer_assessment"] = trainer

    hint = _hint_text(context).lower()
    strings = " ".join(_clean(item.get("value"), 120).lower() for item in _as_list(cues.get("string_anchors")) if isinstance(item, dict))
    readers = bool(_as_list(cues.get("likely_reader_calls")))
    output_writes = bool(_as_list(cues.get("output_layout_writes")))
    numeric_ops = bool(_as_list(cues.get("numeric_ops")))
    mode_checks = bool(_as_list(cues.get("mode_checks")))
    dirty_masks = bool(_as_list(cues.get("dirty_masks")))
    bitwise = bool(_as_list(cues.get("bitwise_or_checksum_ops")))
    damage_hint = any(token in hint for token in ("damage", "health", "hit", "received", "done"))

    category = _clean(trainer.get("category")).lower()
    usefulness = _clean(trainer.get("usefulness")).lower()

    if category in BLANK_STRINGS or category == "unknown":
        if any(token in strings for token in ("bungie", "player-name", "player name", "identity", "account")):
            category = "identity"
        elif readers:
            category = "network"
        elif any(token in hint for token in ("damage", "health", "hit")) and numeric_ops:
            category = "damage"
        elif any(token in hint for token in ("inventory", "item", "stack")):
            category = "inventory"
        elif any(token in hint for token in ("input", "key", "button")):
            category = "input"
        elif numeric_ops and output_writes:
            category = "stat"
        elif bitwise:
            category = "telemetry"
        else:
            category = "unknown"
        trainer["category"] = category
    elif damage_hint and numeric_ops and category in ("stat", "unknown", "telemetry"):
        category = "damage"
        trainer["category"] = category
        notes.append("upgraded trainer category from analyst damage hint plus float/numeric evidence")

    if usefulness in BLANK_STRINGS or usefulness == "unknown":
        if category in ("identity", "network") or readers:
            usefulness = "low"
        elif category in ("damage", "stat", "inventory") and output_writes and numeric_ops:
            usefulness = "high"
        elif category in ("damage", "stat") and numeric_ops:
            usefulness = "medium"
        elif output_writes or dirty_masks:
            usefulness = "medium"
        elif bitwise:
            usefulness = "low"
        else:
            usefulness = "low"
        trainer["usefulness"] = usefulness
    elif damage_hint and numeric_ops and usefulness in ("low", "none"):
        usefulness = "medium"
        trainer["usefulness"] = usefulness
        notes.append("raised usefulness for damage/stat numeric accumulator hypothesis")

    if _blankish(trainer.get("usefulness_reason")):
        if category == "identity":
            trainer["usefulness_reason"] = (
                "Useful for mapping player identity/state serialization and confirming structure layout, "
                "but probably not a direct gameplay trainer hook."
            )
        elif category == "network":
            trainer["usefulness_reason"] = (
                "Useful as telemetry for structured parsing and field discovery; mutate only after caller/output semantics are proven."
            )
        elif usefulness == "high":
            trainer["usefulness_reason"] = (
                "This looks close to gameplay value production because it performs numeric transforms and writes output fields."
            )
        elif usefulness == "medium":
            if category == "damage" and numeric_ops:
                trainer["usefulness_reason"] = (
                    "The analyst hint says damage received/done and the local code performs float accumulator/modifier math; "
                    "treat it as a damage/stat candidate to validate through callers and logged values."
                )
            else:
                trainer["usefulness_reason"] = (
                    "This has useful output writes or update flags, but the exact gameplay effect needs caller-side validation."
                )
        elif category == "damage" and numeric_ops:
            trainer["usefulness_reason"] = (
                "The analyst hint says damage received/done and the local code performs float accumulator/modifier math; "
                "treat it as a damage/stat candidate to validate through callers and logged values."
            )
        else:
            trainer["usefulness_reason"] = (
                "Useful mainly for observation and mapping; current evidence does not show direct control over a trainer-facing value."
            )
    elif damage_hint and numeric_ops and "not directly" in str(trainer.get("usefulness_reason") or "").lower():
        trainer["usefulness_reason"] = (
            "The analyst hint says damage received/done and local float accumulator evidence supports a damage/stat modifier hypothesis. "
            "Validate by logging callers, arguments, return value, and output/argument values across known damage events."
        )

    current_strategy = _clean(trainer.get("best_hook_strategy")).lower()
    if _blankish(trainer.get("best_hook_strategy")) or (damage_hint and numeric_ops and current_strategy in ("not_recommended", "observe_only")):
        if category in ("identity", "network") or readers:
            trainer["best_hook_strategy"] = "observe_only"
        elif usefulness == "high" and output_writes:
            trainer["best_hook_strategy"] = "log_then_compare"
        elif output_writes:
            trainer["best_hook_strategy"] = "modify_output"
        elif category == "damage" and numeric_ops:
            trainer["best_hook_strategy"] = "log_then_compare"
        else:
            trainer["best_hook_strategy"] = "hook_caller"

    current_surface = _clean(trainer.get("modification_surface")).lower()
    if _blankish(trainer.get("modification_surface")) or (damage_hint and numeric_ops and current_surface in ("none", "unknown")):
        if output_writes:
            trainer["modification_surface"] = "output_buffer"
        elif dirty_masks:
            trainer["modification_surface"] = "field_write"
        elif readers:
            trainer["modification_surface"] = "event_stream"
        elif category == "damage" and numeric_ops:
            trainer["modification_surface"] = "argument_or_return_value"
        else:
            trainer["modification_surface"] = "none"

    hooked = _trainer_list(trainer, "what_happens_if_hooked")
    before_hooked = len(hooked)
    filtered_hooked = _replace_generic_items(hooked)
    if len(filtered_hooked) != len(hooked):
        hooked[:] = filtered_hooked
        notes.append("removed generic hook-effect wording")
    for line in _specific_hook_effects(
        category,
        cues,
        context,
        readers,
        output_writes,
        numeric_ops,
        mode_checks,
        dirty_masks,
        bitwise,
    ):
        _append_unique(hooked, line, 8)

    values = _trainer_list(trainer, "values_to_log_first")
    for item in _as_list(cues.get("output_layout_writes"))[:5]:
        if isinstance(item, dict):
            _append_unique(values, "output %s[%s] around: %s" % (item.get("base"), item.get("offset_or_index"), _clean(item.get("line"), 150)))
    for item in _as_list(cues.get("structure_reads"))[:5]:
        if isinstance(item, dict):
            _append_unique(values, "input field %s+%s from: %s" % (item.get("base"), item.get("offset"), _clean(item.get("line"), 150)))
    for item in _as_list(cues.get("likely_reader_calls"))[:4]:
        if isinstance(item, dict):
            _append_unique(values, "reader %s(%s) widths=%s" % (item.get("call"), item.get("stream_arg"), item.get("widths")))
    for item in _as_list(cues.get("mode_checks"))[:4]:
        if isinstance(item, dict):
            _append_unique(values, "mode selector %s %s %s" % (item.get("selector"), item.get("operator"), item.get("value")))

    features = _trainer_list(trainer, "candidate_trainer_features")
    if category == "identity":
        _append_unique(features, "Debug overlay/log that resolves player identity fields and validates output structure offsets.")
        _append_unique(features, "Trainer-side entity/player labeling once the caller connects identity data to runtime entities.")
    elif category in ("damage", "stat") and output_writes and numeric_ops:
        _append_unique(features, "Value clamp/freeze experiment on the computed output slot after logging baseline values.")
        _append_unique(features, "Multiplier experiment applied after the function computes the value but before the caller consumes it.")
        _append_unique(features, "Damage received/done telemetry: record caller, args, result slot and compare with in-game hit events.")
    elif category == "damage" and numeric_ops:
        _append_unique(features, "Damage received/done telemetry: log caller, args, return value and nearby float fields during controlled hit events.")
        _append_unique(features, "Candidate damage multiplier/clamp experiment after caller contract and value direction are proven.")
    elif category == "inventory":
        _append_unique(features, "Stack/count observation and controlled output-slot mutation after confirming the caller semantics.")
    elif readers:
        _append_unique(features, "Structured state/packet field mapper for later trainer feature discovery.")
    elif output_writes:
        _append_unique(features, "Output-field monitor to discover which downstream system consumes this structure.")

    experiments = _trainer_list(trainer, "recommended_experiments")
    filtered_experiments = _replace_generic_items(experiments)
    if len(filtered_experiments) != len(experiments):
        experiments[:] = filtered_experiments
        notes.append("removed generic experiment wording")
    if output_writes or numeric_ops or readers or mode_checks or dirty_masks:
        _append_unique(
            experiments,
            "Install a no-mutation hook and log the evidence-specific fields above; compare two controlled states before choosing caller/callee/output mutation.",
        )
    else:
        _append_unique(
            experiments,
            "Install a no-mutation hook only to classify this target, then move analysis to the caller/callee that owns the concrete value.",
        )
    if output_writes:
        _append_unique(experiments, "Log output buffer/field values before and after the original call; compare across two known in-game states.")
    if readers:
        _append_unique(experiments, "Log reader widths and output offsets together to build a field map before attempting mutation.")
    if mode_checks:
        _append_unique(experiments, "Group logs by mode selector value to identify which branch corresponds to add/multiply/replace behavior.")
    if category in ("identity", "network"):
        _append_unique(experiments, "Trace one caller up and one consumer down; this function is probably a mapper, not the final trainer target.")
    if category == "damage" and numeric_ops:
        _append_unique(experiments, "Trigger one known damage-received and one damage-done event; compare call count, caller address, args, return, and float deltas.")
        _append_unique(experiments, "Group logs by caller so received-damage and dealt-damage paths can be separated before mutation.")

    not_useful = _trainer_list(trainer, "not_useful_for")
    if category == "identity":
        _append_unique(not_useful, "Direct health/damage/ammo/resource modification.")
        _append_unique(not_useful, "Stable gameplay mutation without identifying the consumer/caller first.")
    elif readers:
        _append_unique(not_useful, "Blind mutation before the field layout and caller contract are mapped.")
    elif not output_writes and not numeric_ops:
        _append_unique(not_useful, "Direct value editing until a concrete output/global/return surface is found.")

    stability = _trainer_list(trainer, "stability_notes")
    if readers or category in ("identity", "network"):
        _append_unique(stability, "Parser/identity paths are sensitive to malformed output; prefer logging and caller tracing first.")
    if output_writes:
        _append_unique(stability, "Validate output pointer and slot bounds before reading or writing from a hook.")
    if bitwise:
        _append_unique(stability, "Bitwise validation/decode logic can make naive mutation produce inconsistent downstream state.")

    if len(hooked) > before_hooked or _blankish(analysis.get("trainer_assessment")):
        notes.append("filled trainer/modding assessment from local semantic cues")


def _ensure_hint_alignment(analysis: Dict[str, Any], context: Dict[str, Any], cues: Dict[str, Any], notes: List[str]) -> None:
    hint = _hint_text(context)
    if not hint:
        return
    alignment = analysis.get("user_context_alignment")
    if not isinstance(alignment, dict):
        alignment = {}
        analysis["user_context_alignment"] = alignment
    supports = alignment.get("supports_user_hint")
    if not isinstance(supports, list):
        supports = []
        alignment["supports_user_hint"] = supports
    contradicts = alignment.get("contradicts_user_hint")
    if not isinstance(contradicts, list):
        contradicts = []
        alignment["contradicts_user_hint"] = contradicts

    hint_tokens = re.findall(r"[A-Za-z0-9_]{4,}", hint.lower())
    direct_token_match = _context_has_token(context, hint_tokens)
    low_hint = hint.lower()
    numeric_support = bool(_as_list(cues.get("numeric_ops")) and _as_list(cues.get("output_layout_writes")))
    numeric_partial_support = bool(_as_list(cues.get("numeric_ops")))
    reader_support = bool(_as_list(cues.get("likely_reader_calls")))
    if direct_token_match:
        _append_unique(supports, "The hint's wording or related token appears in current local evidence.")
    if numeric_support and any(token in low_hint for token in ("damage", "health", "stat", "modifier", "stack")):
        _append_unique(
            supports,
            "Float/numeric accumulator plus output writes is compatible with a damage/stat/modifier hypothesis, but does not prove the gameplay name alone.",
        )
    elif numeric_partial_support and any(token in low_hint for token in ("damage", "health", "hit", "received", "done", "stat", "modifier")):
        _append_unique(
            supports,
            "Float add/sub/mul/max operations are compatible with a damage/stat modifier hypothesis; caller logs are needed to separate damage received from damage done.",
        )
    if reader_support and any(token in low_hint for token in ("network", "packet", "bitstream", "deserialize", "player", "name")):
        _append_unique(
            supports,
            "Repeated width-based reader calls support a structured parse/deserialization hypothesis.",
        )

    if supports:
        alignment["verdict"] = "confirmed" if direct_token_match else "plausible"
        note = "Used the analyst hint as the primary hypothesis, then checked it against local semantic cues."
    else:
        alignment["verdict"] = "weak"
        _append_unique(
            contradicts,
            "No local string, symbol, or concrete dataflow evidence directly names the hinted role yet.",
        )
        note = "Used the analyst hint, but current local cues only support the mechanical behavior; inspect callers/strings before renaming too specifically."
    alignment["used"] = True
    existing_notes = _clean(alignment.get("notes"), 700)
    if not existing_notes or "model did not explicitly" in existing_notes.lower():
        alignment["notes"] = note
    notes.append("forced explicit analyst-hint alignment")


def _ensure_semantic_cues_used(analysis: Dict[str, Any], cues: Dict[str, Any], notes: List[str]) -> None:
    used = analysis.get("semantic_cues_used")
    if not isinstance(used, list):
        used = []
        analysis["semantic_cues_used"] = used
    before = len(used)
    if _as_list(cues.get("likely_reader_calls")):
        _append_unique(used, "repeated reader calls with bit/field widths")
    if _as_list(cues.get("output_layout_writes")):
        _append_unique(used, "explicit output writes by base/offset/index")
    if _as_list(cues.get("structure_reads")):
        _append_unique(used, "structure/object field reads by offset")
    if _as_list(cues.get("numeric_ops")):
        _append_unique(used, "float/numeric accumulator operations")
    if _as_list(cues.get("mode_checks")):
        _append_unique(used, "byte selector operation-mode checks")
    if _as_list(cues.get("dirty_masks")):
        _append_unique(used, "dirty/update mask OR operations")
    if _as_list(cues.get("bitwise_or_checksum_ops")):
        _append_unique(used, "bitwise/hash/checksum-like operations")
    if _priority_strings(cues):
        _append_unique(used, "priority string anchors")
    if len(used) > before:
        notes.append("filled semantic_cues_used from local cue categories")


def _ensure_confidence_and_risks(analysis: Dict[str, Any], context: Dict[str, Any], cues: Dict[str, Any], notes: List[str]) -> None:
    try:
        confidence = float(analysis.get("confidence") or 0.0)
    except Exception:
        confidence = 0.0
    has_cues = any(
        _as_list(cues.get(key))
        for key in (
            "likely_reader_calls",
            "output_layout_writes",
            "structure_reads",
            "numeric_ops",
            "mode_checks",
            "dirty_masks",
            "bitwise_or_checksum_ops",
            "string_anchors",
        )
    )
    if confidence <= 0.01 and has_cues:
        confidence = 0.35
        if _priority_strings(cues) or (_as_list(cues.get("output_layout_writes")) and _as_list(cues.get("numeric_ops"))):
            confidence = 0.42
        analysis["confidence"] = confidence
        notes.append("raised zero confidence to conservative local-evidence confidence")

    risks = analysis.get("risks")
    if not isinstance(risks, list):
        risks = []
        analysis["risks"] = risks
    if _blankish(risks):
        risks.append("Gameplay name is still a hypothesis unless strings, callers, or known structures confirm it.")
        if context.get("mode") == "asm_fallback":
            risks.append("Hex-Rays pseudocode was unavailable or skipped; verify stack/register effects manually.")
        if _as_dict(context.get("performance_budget")).get("pseudocode_skipped"):
            risks.append("Analysis used bounded context because the function exceeded the performance budget.")
        notes.append("filled conservative risks")


def _ensure_name(analysis: Dict[str, Any], context: Dict[str, Any], cues: Dict[str, Any], notes: List[str]) -> None:
    current = _clean(analysis.get("suggested_function_name"), 120)
    hint = _hint_text(context)
    candidate = _name_from_hint(hint, cues)
    if not candidate:
        return
    if current and current.lower() not in BLANK_STRINGS:
        if (
            any(token in hint.lower() for token in ("damage", "health", "hit", "received", "done"))
            and current.lower() in ("stat_modifier_accumulator", "accumulate_stat_modifiers", "accumulate_float_modifiers")
            and candidate != current
        ):
            analysis["suggested_function_name"] = candidate
            notes.append("refined generic stat/modifier name using analyst damage hint plus local numeric evidence")
        return
    analysis["suggested_function_name"] = candidate
    notes.append("suggested conservative local name from mechanics and analyst hint")


def _is_data_artifact_context(context: Dict[str, Any]) -> bool:
    artifact = _as_dict(context.get("data_artifact"))
    return bool(context.get("mode") == "data" or artifact.get("kind"))


def _enrich_data_artifact_analysis(analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    artifact = _as_dict(context.get("data_artifact"))
    xrefs = _as_dict(context.get("xrefs"))
    kind = _clean(artifact.get("kind") or "data_item", 80)
    address = _clean(artifact.get("start_ea") or artifact.get("address") or context.get("start_ea"), 80)
    segment = _clean(artifact.get("segment"), 80)
    value = _clean(artifact.get("value"), 500)
    label = _clean(artifact.get("label") or context.get("function_name") or "data_artifact", 120)
    ref_count = len(_as_list(xrefs.get("callers"))) + len(_as_list(xrefs.get("data_refs")))
    display_value = '"%s"' % value if value else _clean(artifact.get("bytes"), 160)

    analysis["mode"] = "data"
    analysis["suggested_function_name"] = None
    analysis["confidence"] = max(float(analysis.get("confidence") or 0.0), 0.78 if value else 0.55)
    analysis["summary"] = (
        "Focused data artifact: %s at %s%s. This is not executable code; use it as a semantic/XREF anchor%s."
        % (
            display_value,
            address or "unknown address",
            (" in %s" % segment) if segment else "",
            (" with %d local reference(s)" % ref_count) if ref_count else "",
        )
    )
    analysis["behavior"] = [
        "Stores a literal data value%s." % ((" (%s)" % kind) if kind else ""),
        "Does not have function arguments, return value, control flow, or a hookable prologue.",
        "Its practical value is locating code that references this data item.",
    ]
    if ref_count:
        analysis["behavior"].append("IDA found references that can lead to the surrounding subsystem or caller logic.")
    analysis["game_relevance"] = [
        "For trainer/modding work, this is a mapping anchor: inspect XREF users to find the real code path.",
        "Do not treat this data item itself as a gameplay value mutation surface.",
    ]
    analysis["engine_hints"] = []
    analysis["dataflow"] = [
        "%s at %s -> referenced by %d local xref(s)" % (display_value or label, address or "-", ref_count),
    ]
    analysis["structure_offsets"] = []
    analysis["algorithm"] = {
        "kind": "data_artifact",
        "description": "Static data/string reference; no algorithm is executed at this address.",
    }
    analysis["trainer_assessment"] = {
        "usefulness": "low" if ref_count else "none",
        "category": "telemetry",
        "usefulness_reason": "Useful as an XREF/string anchor for finding the code that uses it; not a direct trainer hook point.",
        "what_happens_if_hooked": [
            "There is no function to hook at this data address.",
            "Hooking should be considered only on the code that references this item, after inspecting the XREF target.",
        ],
        "best_hook_strategy": "hook_caller" if ref_count else "not_recommended",
        "modification_surface": "none",
        "values_to_log_first": [
            "referencing function address",
            "instruction that loads or compares this data pointer/value",
            "caller path that reaches the referencing code",
        ],
        "candidate_trainer_features": [
            "Subsystem labeling through string/XREF anchors.",
            "Process map notes that connect this literal to referencing functions.",
        ],
        "recommended_experiments": [
            "Open each XREF to this data item and inspect the surrounding function before choosing any hook target.",
            "Rename/comment the referencing function, not the data string itself, once its role is clear.",
        ],
        "not_useful_for": [
            "Direct health/damage/ammo/resource mutation.",
            "Call/return experiments, because this address is data rather than code.",
        ],
        "stability_notes": [
            "Treat static data edits as high-risk until every reference and consumer is understood.",
        ],
    }
    evidence = []
    if value:
        evidence.append({"address": address, "kind": "string", "text": "%s: %s" % (kind, value)})
    else:
        evidence.append({"address": address, "kind": "data", "text": "%s bytes=%s" % (kind, artifact.get("bytes") or "")})
    for row in _as_list(xrefs.get("data_refs"))[:8]:
        if isinstance(row, dict):
            evidence.append({
                "address": row.get("from") or "",
                "kind": "xref",
                "text": "references %s%s" % (address, (" :: %s" % value) if value else ""),
            })
    for row in _as_list(xrefs.get("callers"))[:8]:
        if isinstance(row, dict):
            evidence.append({
                "address": row.get("address") or "",
                "kind": "xref",
                "text": "referencing function/context: %s" % _clean(row.get("function"), 180),
            })
    analysis["evidence"] = evidence[:18]
    analysis["comments"] = [{
        "address": address or str(context.get("current_ea") or "0x0"),
        "text": "AI: data/string anchor%s; inspect XREF users for behavior." % ((" %s" % display_value) if display_value else ""),
        "confidence": 0.82 if value else 0.62,
    }]
    analysis["semantic_cues_used"] = ["focused data/string artifact", "data XREFs", "literal bytes/string value"]
    analysis["bitstream_deserialization"] = {
        "likelihood": "none",
        "reader_calls": [],
        "output_layout": [],
        "dirty_masks": [],
        "sanity_checks": [],
        "bitwise_checks": [],
        "string_anchors": ["%s %s" % (address, value)] if value else [],
    }
    analysis["risks"] = [
        "This is a data artifact, so any function-like behavior would have to come from XREF users, not from this address.",
        "A string can name a subsystem or imported component, but it does not prove trainer usefulness without the referencing code.",
    ]
    analysis["next_questions"] = [
        "Which function references this data item?",
        "What does the nearest XREF user do with this pointer/value?",
    ]
    analysis["local_enrichment"] = {
        "applied": True,
        "notes": ["classified focused non-code item as data/string artifact", "disabled function/trainer hook interpretation for raw data"],
        "policy": "data artifacts are summarized through literal value and XREF users; no function behavior is inferred from db rows",
    }
    return analysis


def enrich_analysis_with_local_cues(analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    cues = _as_dict(context.get("semantic_cues"))
    notes: List[str] = []
    if _is_data_artifact_context(context):
        return _enrich_data_artifact_analysis(analysis, context)
    if not cues:
        return analysis

    _ensure_semantic_cues_used(analysis, cues, notes)
    _ensure_bitstream(analysis, cues, notes)
    _ensure_structure_offsets(analysis, cues, notes)
    _ensure_dataflow(analysis, cues, notes)
    _ensure_algorithm(analysis, cues, notes)
    _ensure_summary_behavior(analysis, context, cues, notes)
    _ensure_trainer_assessment(analysis, context, cues, notes)
    _ensure_hint_alignment(analysis, context, cues, notes)
    _ensure_confidence_and_risks(analysis, context, cues, notes)
    _ensure_evidence(analysis, context, notes)
    _ensure_comments(analysis, context, notes)
    _ensure_name(analysis, context, cues, notes)

    if notes:
        analysis["local_enrichment"] = {
            "applied": True,
            "notes": sorted(set(notes)),
            "policy": "local IDA semantic cues filled sparse or missing LLM fields; treat as evidence-backed hints, not proof",
        }
    else:
        analysis.setdefault("local_enrichment", {"applied": False, "notes": [], "policy": ""})
    return analysis
