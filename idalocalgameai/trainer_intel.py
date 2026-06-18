"""Local trainer/modding decision layer for Monstey analyses."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value in (None, "", "-"):
        return []
    return [value]


def _clean(value: Any, limit: int = 220) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) > limit:
        return text[: max(0, limit - 1)].rstrip() + "..."
    return text


def _append_unique(items: List[Any], value: Any, limit: int = 12) -> None:
    text = _clean(value, 400)
    if not text:
        return
    seen = {_clean(item, 400).lower() for item in items}
    if text.lower() in seen:
        return
    items.append(value)
    del items[limit:]


def _contains_any(text: str, tokens: Tuple[str, ...]) -> bool:
    low = text.lower()
    return any(token in low for token in tokens)


def _score_from_usefulness(usefulness: str) -> int:
    return {
        "high": 84,
        "medium": 62,
        "low": 38,
        "none": 12,
    }.get(str(usefulness or "").strip().lower(), 30)


def _role_from_text(text: str, fallback: str = "unknown") -> str:
    low = text.lower()
    if _contains_any(low, ("damage", "health", "hit", "armor", "shield")):
        return "damage/stat"
    if _contains_any(low, ("ammo", "bullet", "magazine", "clip", "reload")):
        return "ammo/resource"
    if _contains_any(low, ("inventory", "item", "stack", "resource", "currency")):
        return "inventory/resource"
    if _contains_any(low, ("cooldown", "timer", "stamina", "energy")):
        return "cooldown/resource"
    if _contains_any(low, ("input", "button", "key", "controller")):
        return "input"
    if _contains_any(low, ("player-name", "player name", "identity", "membership", "account", "profile")):
        return "identity/parser"
    if _contains_any(low, ("deserialize", "serialize", "bitstream", "packet", "network", "reader")):
        return "structured parser"
    if _contains_any(low, ("checksum", "hash", "xor", "rol", "validate", "sanity")):
        return "validator"
    if _contains_any(low, ("render", "shader", "camera", "ui", "hud")):
        return "render/ui"
    if _contains_any(low, ("update", "tick", "manager", "entity", "actor", "pawn")):
        return "system/caller"
    return fallback


def _strategy_label(strategy: str) -> str:
    labels = {
        "observe_only": "observe only",
        "log_then_compare": "log then compare",
        "modify_output": "modify output",
        "modify_argument": "modify argument",
        "hook_caller": "hook caller",
        "hook_callee": "hook callee",
        "not_recommended": "not recommended",
    }
    return labels.get(str(strategy or "").strip().lower(), strategy or "observe only")


def _candidate_from_block(block: Dict[str, Any], relation: str, center_name: str) -> Dict[str, Any]:
    name = _clean(block.get("function_name") or block.get("function") or block.get("name") or "unknown", 96)
    address = _clean(block.get("function_start") or block.get("address") or block.get("to") or block.get("from") or "", 64)
    snippets = [name, relation, _clean(block.get("callsite_disasm"), 180)]
    for item in _as_list(block.get("strings"))[:4]:
        if isinstance(item, dict):
            snippets.append(_clean(item.get("value"), 120))
        else:
            snippets.append(_clean(item, 120))
    for item in _as_list(block.get("callees"))[:4]:
        if isinstance(item, dict):
            snippets.append(_clean(item.get("name") or item.get("function_name") or item.get("to"), 120))
        else:
            snippets.append(_clean(item, 120))
    for row in _as_list(block.get("local_assembly"))[:8]:
        if isinstance(row, dict):
            snippets.append(_clean(row.get("disasm"), 140))
    hay = " ".join(snippets)
    role = _role_from_text(hay, "caller context" if relation == "caller" else "helper/callee")
    score = 44
    reasons = []
    if relation == "caller":
        score += 16
        reasons.append("caller can reveal the gameplay contract and live arguments")
    else:
        score += 6
        reasons.append("callee may expose the primitive operation behind the current function")
    if _contains_any(hay, ("damage", "health", "ammo", "inventory", "stack", "cooldown", "resource")):
        score += 24
        reasons.append("name/string/disasm tokens look trainer-facing")
    if _contains_any(hay, ("update", "tick", "manager", "entity", "player")):
        score += 12
        reasons.append("surrounding system may connect data to runtime entities")
    if _contains_any(hay, ("deserialize", "bitstream", "packet", "reader", "identity", "validate", "checksum")):
        score -= 10
        reasons.append("looks like parser/validator context; useful for mapping before mutation")
    if name and name != "unknown" and not name.startswith("sub_"):
        score += 8
        reasons.append("symbol/name is more semantic than a default sub_ label")
    score = max(5, min(99, score))
    next_action = "Inspect this caller next" if relation == "caller" else "Inspect this callee if the primitive operation is unclear"
    if role in ("structured parser", "identity/parser", "validator"):
        next_action = "Use for mapping/telemetry; trace consumers before mutation"
    return {
        "score": score,
        "function": name,
        "address": address,
        "relation": relation,
        "role": role,
        "strategy": "hook_caller" if relation == "caller" else "hook_callee",
        "evidence": reasons[:4],
        "next_action": next_action,
        "center": center_name,
    }


def _current_candidate(analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    trainer = _as_dict(analysis.get("trainer_assessment"))
    cues = _as_dict(context.get("semantic_cues"))
    xrefs = _as_dict(context.get("xrefs"))
    name = _clean(analysis.get("suggested_function_name") or context.get("function_name") or "current_function", 96)
    address = _clean(context.get("function_start") or context.get("start_ea") or "", 64)
    usefulness = _clean(trainer.get("usefulness") or "unknown").lower()
    category = _clean(trainer.get("category") or "unknown").lower()
    strategy = _clean(trainer.get("best_hook_strategy") or "observe_only")
    score = _score_from_usefulness(usefulness)
    reasons = []
    if _as_list(cues.get("numeric_ops")) and _as_list(cues.get("output_layout_writes")):
        score += 12
        reasons.append("numeric transforms write into an output slot")
    if _as_list(cues.get("dirty_masks")):
        score += 7
        reasons.append("dirty/update mask pattern can identify state changes")
    if _as_list(cues.get("likely_reader_calls")):
        score -= 10
        reasons.append("structured reader calls make this more parser-like")
    if _as_list(cues.get("string_anchors")):
        reasons.append("string anchors improve semantic confidence")
    if _as_list(xrefs.get("callers")):
        score += 5
        reasons.append("callers are available for tracing the gameplay contract")
    score = max(5, min(99, score))
    role = category if category and category != "unknown" else _role_from_text(" ".join(_as_list(analysis.get("behavior"))), "unknown")
    if role == "network":
        role = "structured parser"
    return {
        "score": score,
        "function": name,
        "address": address,
        "relation": "current",
        "role": role,
        "strategy": strategy,
        "evidence": reasons[:5] or [_clean(trainer.get("usefulness_reason"), 220) or "current function is the selected analysis target"],
        "next_action": _next_move_for(analysis, context),
        "center": name,
    }


def _next_move_for(analysis: Dict[str, Any], context: Dict[str, Any]) -> str:
    trainer = _as_dict(analysis.get("trainer_assessment"))
    cues = _as_dict(context.get("semantic_cues"))
    usefulness = _clean(trainer.get("usefulness") or "unknown").lower()
    strategy = _clean(trainer.get("best_hook_strategy") or "observe_only").lower()
    if usefulness == "high" and strategy in ("modify_output", "log_then_compare"):
        return "Build an observe-only hook, log output fields, then test one controlled output mutation."
    if _as_list(cues.get("likely_reader_calls")):
        return "Trace caller and consumer first; use this function for field mapping instead of direct mutation."
    if strategy == "hook_caller":
        return "Inspect the best caller and check whether it owns the gameplay value contract."
    if strategy == "hook_callee":
        return "Inspect the callee primitive before choosing the mutation surface."
    return "Run observe-only logging: call count, caller address, args, return, touched fields."


def _build_radar(analysis: Dict[str, Any], context: Dict[str, Any], candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    trainer = _as_dict(analysis.get("trainer_assessment"))
    cues = _as_dict(context.get("semantic_cues"))
    usefulness = _clean(trainer.get("usefulness") or "unknown").lower()
    category = _clean(trainer.get("category") or "unknown")
    strategy = _clean(trainer.get("best_hook_strategy") or "observe_only")
    surface = _clean(trainer.get("modification_surface") or "none")
    current = candidates[0] if candidates else _current_candidate(analysis, context)
    tags = []
    if usefulness in ("high", "medium"):
        tags.append("candidate")
    if category in ("identity", "network", "telemetry"):
        tags.append("mapping")
    if strategy in ("hook_caller", "hook_callee"):
        tags.append("trace-needed")
    if surface not in ("none", "unknown", ""):
        tags.append(surface)
    hook_effects = [_clean(item, 180) for item in _as_list(trainer.get("what_happens_if_hooked"))[:4]]
    log_first = [_clean(item, 180) for item in _as_list(trainer.get("values_to_log_first"))[:5]]
    good_for = [_clean(item, 180) for item in _as_list(trainer.get("candidate_trainer_features"))[:4]]
    not_for = [_clean(item, 180) for item in _as_list(trainer.get("not_useful_for"))[:4]]
    experiments = [_clean(item, 180) for item in _as_list(trainer.get("recommended_experiments"))[:4]]
    if not good_for:
        good_for = _fallback_good_for(usefulness, category, strategy, surface, cues, context)
    if not not_for:
        not_for = _fallback_not_good_for(usefulness, category, strategy, surface, cues)
    if not log_first:
        log_first = ["caller return address", "arguments", "return value", "output fields touched by this function"]
    if not experiments:
        experiments = ["Observe-only hook first; compare logs across two known in-game states."]
    return {
        "score": int(current.get("score") or _score_from_usefulness(usefulness)),
        "usefulness": usefulness,
        "category": category,
        "strategy": strategy,
        "strategy_label": _strategy_label(strategy),
        "modification_surface": surface,
        "verdict": _radar_verdict(usefulness, strategy, category),
        "reason": _clean(trainer.get("usefulness_reason"), 260),
        "next_move": _next_move_for(analysis, context),
        "tags": tags[:6],
        "hook_effect": hook_effects,
        "log_first": log_first,
        "good_for": good_for,
        "not_good_for": not_for,
        "experiments": experiments,
    }


def _radar_verdict(usefulness: str, strategy: str, category: str) -> str:
    if usefulness == "high":
        return "Strong trainer candidate after observe-only validation"
    if usefulness == "medium":
        return "Useful candidate, but validate caller/consumer before mutation"
    if category in ("identity", "network", "telemetry") or strategy == "observe_only":
        return "Mapping/telemetry target, not a direct trainer mutation point"
    if usefulness == "none":
        return "Poor trainer target"
    return "Needs more local evidence"


def _fallback_good_for(
    usefulness: str,
    category: str,
    strategy: str,
    surface: str,
    cues: Dict[str, Any],
    context: Dict[str, Any],
) -> List[str]:
    category_low = str(category or "").lower()
    strategy_low = str(strategy or "").lower()
    surface_low = str(surface or "").lower()
    out: List[str] = []
    if _as_list(cues.get("output_layout_writes")):
        out.append("Mapping output fields/slots and comparing them across known gameplay states.")
    if _as_list(cues.get("numeric_ops")):
        out.append("Finding stat/modifier math candidates before choosing a mutation point.")
    if _as_list(cues.get("structure_reads")):
        out.append("Building input object structure knowledge from fixed field reads.")
    if _as_list(cues.get("likely_reader_calls")) or category_low in ("identity", "network", "telemetry", "parser", "structured parser"):
        out.append("Telemetry and field mapping; trace the consumer/caller to find the real gameplay mutation target.")
    if _as_list(cues.get("dirty_masks")):
        out.append("Identifying update/dirty-mask flags that connect this function to state propagation.")
    if usefulness in ("high", "medium") or strategy_low in ("modify_output", "modify_argument", "log_then_compare"):
        out.append("Observe-only hook prototype with log-first validation before a controlled mutation.")
    if surface_low in ("return_value", "argument", "output_buffer", "global_state", "field_write"):
        out.append("Validating the %s surface as a trainer-facing control point." % surface_low)
    if _as_list(_as_dict(context.get("xrefs")).get("callers")):
        out.append("Ranking callers to find the gameplay-level function that owns the useful value.")
    if not out:
        out = [
            "Fast triage: call frequency, caller map, arguments, return value, and touched fields.",
            "Deciding whether this function is a hook target or only a helper to trace through.",
        ]
    deduped: List[str] = []
    for item in out:
        _append_unique(deduped, item, 4)
    return deduped


def _fallback_not_good_for(
    usefulness: str,
    category: str,
    strategy: str,
    surface: str,
    cues: Dict[str, Any],
) -> List[str]:
    category_low = str(category or "").lower()
    strategy_low = str(strategy or "").lower()
    out: List[str] = []
    if usefulness in ("low", "none") or strategy_low in ("observe_only", "not_recommended"):
        out.append("Direct value mutation before a caller/consumer is identified.")
    if _as_list(cues.get("likely_reader_calls")) or category_low in ("identity", "network", "telemetry", "parser"):
        out.append("Stable gameplay stat modification without tracing downstream consumers first.")
    if str(surface or "").lower() in ("none", "unknown", ""):
        out.append("Blind patching; no concrete mutation surface is proven yet.")
    deduped: List[str] = []
    for item in out:
        _append_unique(deduped, item, 4)
    return deduped


def _build_candidates(analysis: Dict[str, Any], context: Dict[str, Any]) -> List[Dict[str, Any]]:
    center = _clean(analysis.get("suggested_function_name") or context.get("function_name") or "current_function", 96)
    candidates = [_current_candidate(analysis, context)]
    expansion = _as_dict(context.get("xref_expansion"))
    for block in _as_list(expansion.get("callers"))[:6]:
        if isinstance(block, dict):
            candidates.append(_candidate_from_block(block, "caller", center))
    for block in _as_list(expansion.get("callees"))[:6]:
        if isinstance(block, dict):
            candidates.append(_candidate_from_block(block, "callee", center))
    xrefs = _as_dict(context.get("xrefs"))
    if len(candidates) <= 1:
        for item in _as_list(xrefs.get("callers"))[:6]:
            if isinstance(item, dict):
                candidates.append(_candidate_from_block(item, "caller", center))
        for item in _as_list(xrefs.get("callees"))[:6]:
            if isinstance(item, dict):
                block = {
                    "function_name": item.get("name"),
                    "function_start": item.get("to"),
                    "callsite_disasm": "%s -> %s" % (item.get("from"), item.get("to")),
                }
                candidates.append(_candidate_from_block(block, "callee", center))
    deduped = []
    seen = set()
    for item in candidates:
        key = (item.get("relation"), item.get("address"), item.get("function"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return sorted(deduped, key=lambda row: (row.get("relation") != "current", -int(row.get("score") or 0)))[:10]


def _build_xref_graph(analysis: Dict[str, Any], context: Dict[str, Any], candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    center_name = _clean(analysis.get("suggested_function_name") or context.get("function_name") or "current_function", 96)
    center_addr = _clean(context.get("function_start") or context.get("start_ea") or "", 64)
    nodes = [{
        "id": "current",
        "label": center_name,
        "address": center_addr,
        "role": "current",
        "score": candidates[0].get("score") if candidates else 0,
    }]
    edges = []
    for idx, item in enumerate(candidates[1:9], 1):
        node_id = "%s_%d" % (item.get("relation") or "xref", idx)
        nodes.append({
            "id": node_id,
            "label": item.get("function") or "unknown",
            "address": item.get("address") or "",
            "role": item.get("relation") or "xref",
            "score": item.get("score") or 0,
        })
        if item.get("relation") == "caller":
            edges.append({"from": node_id, "to": "current", "label": "calls"})
        else:
            edges.append({"from": "current", "to": node_id, "label": "calls"})
    next_targets = [
        {
            "function": item.get("function"),
            "address": item.get("address"),
            "reason": item.get("next_action"),
            "score": item.get("score"),
        }
        for item in sorted(candidates[1:], key=lambda row: int(row.get("score") or 0), reverse=True)[:4]
    ]
    return {
        "center": {"name": center_name, "address": center_addr},
        "nodes": nodes,
        "edges": edges,
        "next_targets": next_targets,
    }


def _field_type_from_line(line: str) -> str:
    low = line.lower()
    if "float" in low or "xmm" in low or "ss" in low:
        return "float"
    if "_byte" in low or " byte " in low:
        return "uint8_t"
    if "_word" in low or "word ptr" in low:
        return "uint16_t"
    if "_dword" in low or "dword ptr" in low or "int" in low:
        return "uint32_t"
    if "_qword" in low or "qword ptr" in low or "__int64" in low:
        return "uint64_t"
    return "uintptr_t"


def _build_structure_hypotheses(analysis: Dict[str, Any], context: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for item in _as_list(analysis.get("structure_offsets")):
        if isinstance(item, dict):
            rows.append({
                "base": _clean(item.get("base") or "unknown", 40),
                "offset": _clean(item.get("offset") or item.get("offset_or_index") or "0", 40),
                "type": _clean(item.get("type") or "unknown", 40),
                "meaning": _clean(item.get("meaning") or "field", 120),
                "evidence": _clean(item.get("evidence") or "", 180),
            })
    cues = _as_dict(context.get("semantic_cues"))
    for item in _as_list(cues.get("output_layout_writes"))[:12]:
        if isinstance(item, dict):
            rows.append({
                "base": _clean(item.get("base") or "out", 40),
                "offset": _clean(item.get("offset_or_index") or "0", 40),
                "type": _field_type_from_line(str(item.get("line") or "")),
                "meaning": "output field/slot written here",
                "evidence": _clean(item.get("line"), 180),
            })
    for item in _as_list(cues.get("structure_reads"))[:12]:
        if isinstance(item, dict):
            rows.append({
                "base": _clean(item.get("base") or "in", 40),
                "offset": _clean(item.get("offset") or "0", 40),
                "type": _field_type_from_line(str(item.get("line") or "")),
                "meaning": "input field read here",
                "evidence": _clean(item.get("line"), 180),
            })
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    seen = set()
    for row in rows:
        key = (row["base"], row["offset"], row["meaning"])
        if key in seen:
            continue
        seen.add(key)
        grouped.setdefault(row["base"], []).append(row)
    out = []
    for base, fields in grouped.items():
        ordered = fields[:18]
        struct_name = "monstey_%s_hypothesis_t" % re.sub(r"[^A-Za-z0-9_]+", "_", base or "object").strip("_")
        lines = ["struct %s {" % struct_name]
        for idx, field in enumerate(ordered):
            typename = field.get("type") or "uintptr_t"
            offset = field.get("offset") or "0"
            member = "field_%s" % re.sub(r"[^A-Za-z0-9A-Fa-f]+", "_", str(offset)).strip("_")
            if not member or member == "field_":
                member = "field_%02d" % idx
            lines.append("    %-10s %-18s; // %s %s" % (typename, member, offset, field.get("meaning") or ""))
        lines.append("};")
        out.append({
            "base": base,
            "name": struct_name,
            "fields": ordered,
            "cpp_preview": "\n".join(lines),
        })
    return out[:4]


def _build_hook_experiments(analysis: Dict[str, Any], context: Dict[str, Any], radar: Dict[str, Any]) -> List[Dict[str, Any]]:
    experiments = []
    log_first = radar.get("log_first") or []
    experiments.append({
        "title": "Observe-only hook",
        "intent": "Confirm call frequency, caller, live arguments, return value, and touched fields before modifying anything.",
        "steps": [
            "Install a MinHook __fastcall detour and immediately call the original.",
            "Log _ReturnAddress(), arguments, return value, and the first stable output fields.",
            "Compare logs across menu, idle gameplay, and one controlled state change.",
        ],
        "log": log_first[:6],
        "mutation_gate": "No mutation until pointer validity and field meaning are confirmed.",
    })
    strategy = _clean(radar.get("strategy") or "").lower()
    if strategy in ("modify_output", "log_then_compare") or radar.get("modification_surface") == "output_buffer":
        experiments.append({
            "title": "Output mutation probe",
            "intent": "Test whether the caller consumes the computed output directly.",
            "steps": [
                "Log output fields before and after the original call.",
                "Pick one low-risk numeric output field with stable bounds.",
                "Apply one small controlled change after the original call and compare downstream behavior.",
            ],
            "log": log_first[:6],
            "mutation_gate": "Only mutate after two baseline captures prove the field is stable and trainer-facing.",
        })
    if strategy == "hook_caller":
        experiments.append({
            "title": "Caller contract trace",
            "intent": "Find the gameplay-level function that owns the useful value contract.",
            "steps": [
                "Open the top caller from Trainer candidates.",
                "Check what arguments it passes into the current function.",
                "Log the caller before and after current function execution to find the consumer surface.",
            ],
            "log": ["caller address", "arguments passed to current function", "consumer writes after call"],
            "mutation_gate": "Prefer mutating the caller after the contract is clear.",
        })
    if _as_list(_as_dict(context.get("semantic_cues")).get("likely_reader_calls")):
        experiments.append({
            "title": "Field map capture",
            "intent": "Turn parser/bitstream behavior into structure knowledge for later trainer features.",
            "steps": [
                "Log reader widths, output offsets, and string anchors in the same record.",
                "Group records by caller and mode selector.",
                "Promote stable offsets into a structure hypothesis.",
            ],
            "log": ["reader widths", "output offsets", "mode selector", "strings", "caller"],
            "mutation_gate": "Treat as mapping/telemetry until consumers are known.",
        })
    return experiments[:4]


def _append_decision_evidence(analysis: Dict[str, Any]) -> None:
    evidence = analysis.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
        analysis["evidence"] = evidence
    seen = {
        (str(item.get("kind") or ""), str(item.get("address") or ""), str(item.get("text") or ""))
        for item in evidence
        if isinstance(item, dict)
    }
    for item in _as_list(analysis.get("trainer_candidates"))[:6]:
        if not isinstance(item, dict):
            continue
        text = "score=%s relation=%s role=%s strategy=%s next=%s" % (
            item.get("score"),
            item.get("relation"),
            item.get("role"),
            item.get("strategy"),
            item.get("next_action"),
        )
        row = {
            "kind": "candidate",
            "address": item.get("address") or "",
            "text": text,
        }
        key = (row["kind"], row["address"], row["text"])
        if key not in seen:
            evidence.append(row)
            seen.add(key)
    for item in _as_list(analysis.get("hook_experiments"))[:3]:
        if isinstance(item, dict):
            row = {
                "kind": "experiment",
                "address": "",
                "text": "%s: %s" % (item.get("title") or "Experiment", item.get("mutation_gate") or "observe first"),
            }
            key = (row["kind"], row["address"], row["text"])
            if key not in seen:
                evidence.append(row)
                seen.add(key)


def _build_data_artifact_intel(analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    artifact = _as_dict(context.get("data_artifact"))
    xrefs = _as_dict(context.get("xrefs"))
    address = _clean(artifact.get("start_ea") or artifact.get("address") or context.get("start_ea"), 64)
    value = _clean(artifact.get("value") or artifact.get("bytes") or artifact.get("label") or "data", 160)
    label = _clean(artifact.get("label") or context.get("function_name") or "data_artifact", 96)
    callers = [item for item in _as_list(xrefs.get("callers")) if isinstance(item, dict)]
    data_refs = [item for item in _as_list(xrefs.get("data_refs")) if isinstance(item, dict)]
    ref_count = len(callers) + len(data_refs)
    score = 34 if ref_count else 14
    radar = {
        "score": score,
        "usefulness": "low" if ref_count else "none",
        "category": "telemetry",
        "strategy": "hook_caller" if ref_count else "not_recommended",
        "strategy_label": "inspect XREF users" if ref_count else "not recommended",
        "modification_surface": "none",
        "verdict": "Data/string anchor; inspect referencing code" if ref_count else "Static data with no local references",
        "reason": "This is data, not a function. Its value is in guiding XREF navigation.",
        "next_move": "Open the nearest XREF user and analyze that function." if ref_count else "Search for references or related strings before spending LLM time here.",
        "tags": ["data", "string" if artifact.get("kind") == "ascii_string" else "data-item", "xref-anchor"][:3],
        "hook_effect": ["No function hook exists at this data address."],
        "log_first": ["referencing instruction", "referencing function", "caller chain around the XREF user"],
        "good_for": [
            "Finding and labeling the subsystem that references this literal.",
            "Choosing the next function to analyze through XREF navigation.",
        ],
        "not_good_for": [
            "Direct trainer value mutation.",
            "Call/return experiments on the data address.",
        ],
        "experiments": [
            "Jump to each XREF and analyze the surrounding function.",
            "Comment the data item as an anchor, then rename the referencing function when its behavior is proven.",
        ],
    }
    candidates = [{
        "score": score,
        "function": label,
        "address": address,
        "relation": "current",
        "role": "data/string anchor",
        "strategy": "hook_caller" if ref_count else "not_recommended",
        "evidence": ["literal value: %s" % value, "%d local reference(s)" % ref_count],
        "next_action": radar["next_move"],
    }]
    for item in callers[:8]:
        candidates.append({
            "score": 58,
            "function": _clean(item.get("function") or "xref_user", 96),
            "address": _clean(item.get("address"), 64),
            "relation": "caller",
            "role": "referencing code",
            "strategy": "hook_caller",
            "evidence": ["references focused data item %s" % address],
            "next_action": "Analyze this XREF user; it is the code, not the data string.",
        })
    nodes = [{
        "id": "current",
        "label": label,
        "address": address,
        "role": "data",
        "score": score,
    }]
    edges = []
    for idx, item in enumerate(callers[:8], 1):
        node_id = "xref_%d" % idx
        nodes.append({
            "id": node_id,
            "label": _clean(item.get("function") or "xref_user", 96),
            "address": _clean(item.get("address"), 64),
            "role": "xref_user",
            "score": 58,
        })
        edges.append({"from": node_id, "to": "current", "label": "references"})
    analysis["trainer_radar"] = radar
    analysis["trainer_candidates"] = candidates[:10]
    analysis["xref_graph"] = {
        "center": {"name": label, "address": address},
        "nodes": nodes,
        "edges": edges,
        "next_targets": [
            {
                "function": _clean(item.get("function") or "xref_user", 96),
                "address": _clean(item.get("address"), 64),
                "score": 58,
                "reason": "Analyze this XREF user to find behavior.",
            }
            for item in callers[:4]
        ],
    }
    analysis["structure_hypotheses"] = []
    analysis["hook_experiments"] = [{
        "title": "XREF trace",
        "intent": "Use the data/string anchor to locate the real executable code path.",
        "steps": [
            "Open the top XREF user.",
            "Analyze the surrounding function instead of the data address.",
            "Promote the reference into a comment/name only after the function role is clear.",
        ],
        "log": ["xref address", "referencing function", "surrounding instruction"],
        "mutation_gate": "No data mutation; choose a code hook only after the XREF user's behavior is understood.",
    }]
    _append_decision_evidence(analysis)
    return analysis


def build_trainer_intel(analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Attach deterministic trainer/modding intelligence to an analysis."""
    if not isinstance(analysis, dict):
        return analysis
    if context.get("mode") == "data" or _as_dict(context.get("data_artifact")).get("kind"):
        return _build_data_artifact_intel(analysis, context)
    candidates = _build_candidates(analysis, context)
    radar = _build_radar(analysis, context, candidates)
    analysis["trainer_radar"] = radar
    analysis["trainer_candidates"] = candidates
    analysis["xref_graph"] = _build_xref_graph(analysis, context, candidates)
    analysis["structure_hypotheses"] = _build_structure_hypotheses(analysis, context)
    analysis["hook_experiments"] = _build_hook_experiments(analysis, context, radar)
    _append_decision_evidence(analysis)
    return analysis
