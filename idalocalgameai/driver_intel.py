"""Defensive Windows driver IOCTL audit layer for Monstey analyses."""

from __future__ import annotations

import re
from typing import Any, Dict, List


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
    text = _clean(value, 420)
    if not text:
        return
    seen = {_clean(item, 420).lower() for item in items}
    if text.lower() in seen:
        return
    items.append(value)
    del items[limit:]


def _lines(cues: Dict[str, Any], key: str, limit: int = 5) -> List[str]:
    out: List[str] = []
    for item in _as_list(cues.get(key))[:limit]:
        if isinstance(item, dict):
            line = _clean(item.get("line") or item.get("value") or item.get("meaning") or "", 220)
            address = _clean(item.get("address") or item.get("from") or "", 64)
            if line:
                out.append(("%s: %s" % (address, line)).strip(": "))
        else:
            text = _clean(item, 220)
            if text:
                out.append(text)
    return out


def _first_address(context: Dict[str, Any]) -> str:
    return _clean(context.get("start_ea") or context.get("current_ea") or "", 64)


def _score_color_bucket(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 42:
        return "medium"
    if score >= 18:
        return "low"
    return "none"


def _strategy_for(score: int, cues: Dict[str, Any]) -> str:
    if _as_list(cues.get("ioctl_rw_primitives")):
        return "verify primitive"
    if _as_list(cues.get("ioctl_buffer_access")):
        return "audit buffers"
    if _as_list(cues.get("ioctl_code_checks")) or _as_list(cues.get("driver_api_calls")):
        return "map dispatch"
    if score <= 18:
        return "low priority"
    return "trace caller"


def _method_hint(cues: Dict[str, Any]) -> str:
    hay = " ".join(_lines(cues, "ioctl_method_hints", 12)).lower()
    if "method_neither" in hay or "type3inputbuffer" in hay or "userbuffer" in hay:
        return "METHOD_NEITHER"
    if "method_in_direct" in hay or "mdladdress" in hay:
        return "METHOD_IN_DIRECT"
    if "method_out_direct" in hay:
        return "METHOD_OUT_DIRECT"
    if "method_buffered" in hay or "systembuffer" in hay:
        return "METHOD_BUFFERED"
    buffer_text = " ".join(_lines(cues, "ioctl_buffer_access", 12)).lower()
    if "type3inputbuffer" in buffer_text or "userbuffer" in buffer_text:
        return "METHOD_NEITHER"
    if "mdladdress" in buffer_text:
        return "direct I/O / MDL"
    if "systembuffer" in buffer_text:
        return "METHOD_BUFFERED"
    return "unknown"


def _surface(cues: Dict[str, Any]) -> str:
    if _as_list(cues.get("ioctl_rw_primitives")):
        text = " ".join(_lines(cues, "ioctl_rw_primitives", 8)).lower()
        if "mmcopyvirtualmemory" in text or "pslookupprocess" in text:
            return "process_memory"
        if "map" in text or "physical" in text:
            return "mapped_memory"
        return "copy_path"
    if _as_list(cues.get("ioctl_code_checks")):
        return "ioctl_switch"
    if _as_list(cues.get("driver_api_calls")):
        return "dispatch_table"
    return "unknown"


def _risk_score(context: Dict[str, Any], cues: Dict[str, Any]) -> int:
    profile = str(context.get("analysis_profile") or "").lower()
    score = 12 if "driver" in profile or "ioctl" in profile else 0
    score += min(22, len(_as_list(cues.get("ioctl_code_checks"))) * 6)
    score += min(20, len(_as_list(cues.get("ioctl_buffer_access"))) * 6)
    score += min(18, len(_as_list(cues.get("driver_api_calls"))) * 3)
    score += min(34, len(_as_list(cues.get("ioctl_rw_primitives"))) * 14)
    score += 12 if _method_hint(cues) == "METHOD_NEITHER" else 0
    score += 8 if _as_list(cues.get("driver_strings")) else 0
    validation = len(_as_list(cues.get("ioctl_validation_checks")))
    if score >= 30 and validation == 0:
        score += 16
    elif validation:
        score -= min(12, validation * 3)
    likelihood = str(cues.get("driver_ioctl_likelihood") or "").lower()
    if likelihood == "high":
        score += 10
    elif likelihood == "medium":
        score += 5
    return max(0, min(100, score))


def _primary_evidence(cues: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for key in (
        "ioctl_code_checks",
        "ioctl_buffer_access",
        "ioctl_rw_primitives",
        "ioctl_validation_checks",
        "driver_api_calls",
        "driver_strings",
    ):
        for line in _lines(cues, key, 4):
            _append_unique(out, line, 14)
    return out


def _assessment(analysis: Dict[str, Any], context: Dict[str, Any], cues: Dict[str, Any], score: int) -> Dict[str, Any]:
    current = _as_dict(analysis.get("driver_ioctl_assessment"))
    risk = _clean(current.get("risk") or "").lower()
    if risk in ("", "unknown", "none"):
        risk = _score_color_bucket(score)
    method = _clean(current.get("transfer_method") or "")
    if not method or method == "unknown":
        method = _method_hint(cues)
    surface = _clean(current.get("ioctl_surface") or "")
    if not surface or surface == "unknown":
        surface = _surface(cues)

    buffer_sources = list(_as_list(current.get("buffer_sources")))
    for line in _lines(cues, "ioctl_buffer_access", 5):
        _append_unique(buffer_sources, line, 8)
    if method != "unknown":
        _append_unique(buffer_sources, "transfer method hint: %s" % method, 8)

    validation_gaps = list(_as_list(current.get("validation_gaps")))
    if _as_list(cues.get("ioctl_buffer_access")) and not _as_list(cues.get("ioctl_validation_checks")):
        _append_unique(validation_gaps, "No obvious ProbeForRead/ProbeForWrite or length/status validation cue appears in the focused context.", 8)
    if method == "METHOD_NEITHER":
        _append_unique(validation_gaps, "METHOD_NEITHER/user-buffer style access requires explicit user pointer probing and exception handling.", 8)
    if _as_list(cues.get("ioctl_rw_primitives")) and not _as_list(cues.get("ioctl_code_checks")):
        _append_unique(validation_gaps, "Memory primitive is visible, but the controlling IOCTL selector has not been mapped yet.", 8)

    rw_indicators = list(_as_list(current.get("rw_primitive_indicators")))
    for line in _lines(cues, "ioctl_rw_primitives", 6):
        _append_unique(rw_indicators, line, 10)

    verify = list(_as_list(current.get("values_to_verify")))
    for item in (
        "IoControlCode value and case target",
        "InputBufferLength and OutputBufferLength checks before every buffer read/write",
        "buffer pointer source: SystemBuffer, UserBuffer, Type3InputBuffer, or MDL",
        "address/size/pid fields read from user-controlled input",
        "NTSTATUS failure path for malformed length or null pointer",
    ):
        _append_unique(verify, item, 10)

    tests = list(_as_list(current.get("safe_test_plan")))
    for item in (
        "Map the dispatch switch statically and label each IOCTL case before running any dynamic test.",
        "Use controlled malformed-size requests in a lab VM only to verify graceful STATUS_INVALID_PARAMETER style failures.",
        "Confirm whether any address/size fields are trusted before a copy/map/process-memory helper is reached.",
    ):
        _append_unique(tests, item, 8)

    unknowns = list(_as_list(current.get("not_enough_evidence")))
    if not _as_list(cues.get("ioctl_code_checks")):
        _append_unique(unknowns, "Focused context does not yet show the IOCTL selector or switch/case value.", 8)
    if not _as_list(cues.get("ioctl_buffer_access")):
        _append_unique(unknowns, "Focused context does not yet show the request/response buffer layout.", 8)
    if not _as_list(cues.get("ioctl_rw_primitives")):
        _append_unique(unknowns, "No direct read/write/copy/map primitive is proven in this slice.", 8)

    stability = list(_as_list(current.get("stability_notes")))
    _append_unique(stability, "Driver IOCTL testing can crash the lab VM if pointer/length validation is wrong; keep tests minimal and reversible.", 8)

    reason = _clean(current.get("risk_reason"), 300)
    if not reason:
        reason = (
            "Driver IOCTL cues are present; risk depends on whether the buffer source, length checks, and any copy/map/process-memory primitive are safely validated."
            if score >= 35
            else "Current evidence is weak; treat this as driver triage until dispatch and buffer handling are mapped."
        )

    category = _clean(current.get("category") or "")
    if not category or category == "unknown":
        category = "arbitrary_read_write" if rw_indicators else "buffer_validation" if buffer_sources else "ioctl_dispatch" if score else "unknown"

    return {
        "risk": risk,
        "category": category,
        "risk_reason": reason,
        "ioctl_surface": surface,
        "transfer_method": method,
        "buffer_sources": buffer_sources[:8],
        "validation_gaps": validation_gaps[:8],
        "rw_primitive_indicators": rw_indicators[:10],
        "values_to_verify": verify[:10],
        "safe_test_plan": tests[:8],
        "not_enough_evidence": unknowns[:8],
        "stability_notes": stability[:8],
    }


def _candidate_from_block(block: Dict[str, Any], relation: str) -> Dict[str, Any]:
    name = _clean(block.get("function_name") or block.get("function") or block.get("name") or "unknown", 96)
    address = _clean(block.get("function_start") or block.get("address") or block.get("to") or block.get("from") or "", 64)
    hay = " ".join([
        name,
        _clean(block.get("callsite_disasm"), 180),
        " ".join(_clean(x.get("value"), 120) for x in _as_list(block.get("strings")) if isinstance(x, dict)),
        " ".join(_clean(x.get("name") or x.get("to"), 120) for x in _as_list(block.get("callees")) if isinstance(x, dict)),
        " ".join(_clean(x.get("disasm"), 120) for x in _as_list(block.get("local_assembly")) if isinstance(x, dict)),
    ]).lower()
    score = 42 + (12 if relation == "caller" else 6)
    role = "helper"
    evidence: List[str] = []
    if any(token in hay for token in ("deviceiocontrol", "iocontrolcode", "ioctl", "irp_mj_device_control")):
        score += 24
        role = "dispatch"
        evidence.append("IOCTL/dispatch tokens appear in nearby context")
    if any(token in hay for token in ("systembuffer", "type3inputbuffer", "userbuffer", "inputbufferlength", "outputbufferlength")):
        score += 18
        role = "copy" if role == "helper" else role
        evidence.append("IRP/buffer fields appear in nearby context")
    if any(token in hay for token in ("mmcopyvirtualmemory", "mmmapiospace", "pslookupprocess", "kestackattach", "rtlcopy", "memcpy")):
        score += 24
        role = "copy"
        evidence.append("copy/map/process-memory primitive tokens appear nearby")
    if any(token in hay for token in ("probeforread", "probeforwrite", "status_invalid_parameter", "buffer_too_small")):
        score += 8
        role = "validation" if role == "helper" else role
        evidence.append("validation/status tokens appear nearby")
    score = max(5, min(99, score))
    risk = _score_color_bucket(score)
    next_action = "Open this function and map the IOCTL/buffer contract." if relation != "callee" else "Inspect this helper to confirm whether it validates or performs the sensitive operation."
    return {
        "score": score,
        "function": name,
        "address": address,
        "relation": relation,
        "role": role,
        "risk": risk,
        "evidence": evidence[:4] or ["nearby XREF context may explain the focused driver path"],
        "next_action": next_action,
    }


def _candidates(analysis: Dict[str, Any], context: Dict[str, Any], cues: Dict[str, Any], score: int) -> List[Dict[str, Any]]:
    current_name = _clean(analysis.get("suggested_function_name") or context.get("function_name") or "current_function", 96)
    current = {
        "score": score,
        "function": current_name,
        "address": _first_address(context),
        "relation": "current",
        "role": _surface(cues),
        "risk": _score_color_bucket(score),
        "evidence": _primary_evidence(cues)[:5] or ["selected focus is the current audit target"],
        "next_action": "Map IOCTL selector, buffer layout, validation, and primitive path in this function.",
    }
    out = [current]
    expansion = _as_dict(context.get("xref_expansion"))
    for block in _as_list(expansion.get("callers"))[:5]:
        if isinstance(block, dict):
            out.append(_candidate_from_block(block, "caller"))
    for block in _as_list(expansion.get("callees"))[:5]:
        if isinstance(block, dict):
            out.append(_candidate_from_block(block, "callee"))
    xrefs = _as_dict(context.get("xrefs"))
    if len(out) == 1:
        for item in _as_list(xrefs.get("callers"))[:5]:
            if isinstance(item, dict):
                out.append(_candidate_from_block(item, "caller"))
        for item in _as_list(xrefs.get("callees"))[:5]:
            if isinstance(item, dict):
                out.append(_candidate_from_block(item, "callee"))
    seen = set()
    deduped = []
    for item in out:
        key = (item.get("relation"), item.get("address"), item.get("function"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return sorted(deduped, key=lambda row: (row.get("relation") != "current", -int(row.get("score") or 0)))[:10]


def _radar(assessment: Dict[str, Any], candidates: List[Dict[str, Any]], cues: Dict[str, Any]) -> Dict[str, Any]:
    score = int(candidates[0].get("score") if candidates else 0)
    risk = assessment.get("risk") or _score_color_bucket(score)
    tags: List[str] = ["driver", "ioctl"]
    method = assessment.get("transfer_method")
    if method and method != "unknown":
        tags.append(str(method).lower().replace("method_", "method-"))
    if assessment.get("rw_primitive_indicators"):
        tags.append("rw-primitive")
    if assessment.get("validation_gaps"):
        tags.append("validation-gap")
    strategy = _strategy_for(score, cues)
    if risk in ("critical", "high"):
        verdict = "High-priority IOCTL audit candidate"
    elif risk == "medium":
        verdict = "Promising IOCTL audit lead, needs validation"
    elif risk == "low":
        verdict = "Low-confidence driver lead"
    else:
        verdict = "No concrete IOCTL risk proven yet"
    return {
        "score": score,
        "risk": risk,
        "category": assessment.get("category"),
        "verdict": verdict,
        "strategy": strategy,
        "strategy_label": strategy,
        "ioctl_surface": assessment.get("ioctl_surface"),
        "transfer_method": assessment.get("transfer_method"),
        "next_move": "Verify selector, buffer source, lengths, and primitive path before naming a vulnerability.",
        "tags": tags[:8],
        "why_it_matters": [
            "If user-controlled address/size fields reach a copy/map/process-memory primitive without strict validation, this can become an arbitrary read/write class issue.",
            "If METHOD_NEITHER or raw user pointers are used, pointer probing and exception handling are the first audit priority.",
        ][:2],
        "evidence": _primary_evidence(cues)[:8],
        "verify_first": assessment.get("values_to_verify") or [],
        "safe_tests": assessment.get("safe_test_plan") or [],
    }


def _experiments(assessment: Dict[str, Any], radar: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "title": "Map IOCTL contract",
            "intent": "Understand which request code reaches this path and what structure layout it expects.",
            "steps": [
                "Label the IoControlCode selector and each case target.",
                "Map input/output length checks before the first buffer dereference.",
                "Promote stable request fields into a local structure hypothesis.",
            ],
            "verify": radar.get("verify_first")[:6],
            "stop_condition": "Stop if no IOCTL selector or request buffer reaches the focused function.",
        },
        {
            "title": "Primitive verification",
            "intent": "Decide whether the path is only a helper or a real read/write/copy/map risk.",
            "steps": [
                "Trace from user-controlled fields to copy/map/process-memory helpers.",
                "Confirm every address, size, pid, and direction field is bounded and checked.",
                "Classify the path as validated, partially validated, or not enough evidence.",
            ],
            "verify": assessment.get("rw_primitive_indicators")[:6] or ["copy/map/process-memory helper reachability"],
            "stop_condition": "Do not claim R/W if the sensitive helper is unreachable from user-controlled IOCTL data.",
        },
        {
            "title": "Safe malformed-size lab check",
            "intent": "Validate graceful rejection behavior without building a weaponized request.",
            "steps": [
                "Use a lab VM snapshot and issue only minimal malformed length/null-buffer checks.",
                "Expect clean NTSTATUS failure paths, not bugcheck or uncontrolled memory access.",
                "Compare static validation expectations with observed status codes.",
            ],
            "verify": ["status code", "length gate", "pointer gate", "exception path"],
            "stop_condition": "Stop on crash, inconsistent status, or any unclear pointer path; return to static mapping.",
        },
    ]


def _append_evidence(analysis: Dict[str, Any], radar: Dict[str, Any], candidates: List[Dict[str, Any]]) -> None:
    evidence = analysis.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
        analysis["evidence"] = evidence
    seen = {
        (str(item.get("kind") or ""), str(item.get("address") or ""), str(item.get("text") or ""))
        for item in evidence
        if isinstance(item, dict)
    }
    for line in _as_list(radar.get("evidence"))[:8]:
        row = {"kind": "ioctl", "address": "", "text": line}
        key = (row["kind"], row["address"], row["text"])
        if key not in seen:
            evidence.append(row)
            seen.add(key)
    for item in candidates[:5]:
        if not isinstance(item, dict):
            continue
        row = {
            "kind": "driver_candidate",
            "address": item.get("address") or "",
            "text": "score=%s risk=%s role=%s next=%s"
            % (item.get("score"), item.get("risk"), item.get("role"), item.get("next_action")),
        }
        key = (row["kind"], row["address"], row["text"])
        if key not in seen:
            evidence.append(row)
            seen.add(key)


def build_driver_ioctl_intel(analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Attach defensive IOCTL audit intelligence when the profile or cues warrant it."""
    if not isinstance(analysis, dict):
        return analysis
    cues = _as_dict(context.get("semantic_cues"))
    profile = str(context.get("analysis_profile") or "").lower()
    likelihood = str(cues.get("driver_ioctl_likelihood") or "none").lower()
    cue_count = sum(len(_as_list(cues.get(key))) for key in (
        "driver_api_calls",
        "ioctl_code_checks",
        "ioctl_buffer_access",
        "ioctl_validation_checks",
        "ioctl_rw_primitives",
        "ioctl_method_hints",
        "driver_strings",
    ))
    if "driver" not in profile and "ioctl" not in profile and likelihood == "none" and cue_count == 0:
        return analysis

    score = _risk_score(context, cues)
    assessment = _assessment(analysis, context, cues, score)
    candidates = _candidates(analysis, context, cues, score)
    radar = _radar(assessment, candidates, cues)
    analysis["driver_ioctl_assessment"] = assessment
    analysis["driver_ioctl_candidates"] = candidates
    analysis["driver_ioctl_radar"] = radar
    analysis["ioctl_experiments"] = _experiments(assessment, radar)

    if not _clean(analysis.get("suggested_function_name")) and score >= 45:
        surface = str(assessment.get("ioctl_surface") or "")
        if surface == "process_memory":
            analysis["suggested_function_name"] = "audit_ioctl_process_memory_path"
        elif surface in ("copy_path", "mapped_memory"):
            analysis["suggested_function_name"] = "audit_ioctl_memory_primitive"
        elif surface == "ioctl_switch":
            analysis["suggested_function_name"] = "driver_ioctl_dispatch"
        else:
            analysis["suggested_function_name"] = "driver_ioctl_audit_target"
    if not _clean(analysis.get("summary")) or str(analysis.get("summary")).strip() == "-":
        analysis["summary"] = "Defensive IOCTL audit target: map request code, buffer source, validation gates, and any memory primitive before claiming a vulnerability."
    used = analysis.get("semantic_cues_used")
    if not isinstance(used, list):
        used = []
    for item in ("driver_ioctl_likelihood", "ioctl_code_checks", "ioctl_buffer_access", "ioctl_validation_checks", "ioctl_rw_primitives"):
        if _as_list(cues.get(item)) or item == "driver_ioctl_likelihood":
            _append_unique(used, item, 16)
    analysis["semantic_cues_used"] = used
    _append_evidence(analysis, radar, candidates)
    return analysis
