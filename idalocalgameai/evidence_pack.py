"""Shared evidence pack and claim board for multi-agent analysis."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _clean(value: Any, limit: int = 500) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _addr(value: Any) -> str:
    text = str(value or "").strip()
    return text if text else ""


def _pack_id(seed: Dict[str, Any]) -> str:
    raw = json.dumps(seed, sort_keys=True, default=str).encode("utf-8", "replace")
    return hashlib.sha1(raw).hexdigest()[:12]


class _Builder:
    def __init__(self) -> None:
        self.facts: List[Dict[str, Any]] = []
        self.claims: List[Dict[str, Any]] = []

    def fact(
        self,
        kind: str,
        text: Any,
        address: Any = "",
        source: str = "ida",
        strength: str = "medium",
        meta: Optional[Dict[str, Any]] = None,
    ) -> str:
        text = _clean(text, 700)
        if not text:
            return ""
        fact_id = "F%03d" % (len(self.facts) + 1)
        item = {
            "id": fact_id,
            "kind": _clean(kind, 80),
            "address": _addr(address),
            "text": text,
            "source": _clean(source, 120),
            "strength": _clean(strength, 40),
        }
        if meta:
            item["meta"] = meta
        self.facts.append(item)
        return fact_id

    def claim(
        self,
        statement: Any,
        evidence_ids: Optional[List[str]] = None,
        confidence: float = 0.5,
        status: str = "open",
        category: str = "role",
        owner: str = "local_scout",
    ) -> str:
        statement = _clean(statement, 700)
        if not statement:
            return ""
        claim_id = "C%03d" % (len(self.claims) + 1)
        try:
            conf = max(0.0, min(1.0, float(confidence)))
        except Exception:
            conf = 0.5
        self.claims.append({
            "id": claim_id,
            "statement": statement,
            "status": status,
            "category": category,
            "confidence": conf,
            "evidence_ids": [eid for eid in (evidence_ids or []) if eid],
            "owner": owner,
        })
        return claim_id


def _fact_text(item: Dict[str, Any], keys: List[str]) -> str:
    parts = []
    for key in keys:
        value = item.get(key)
        if value is None or value == "":
            continue
        parts.append("%s=%s" % (key, value))
    return ", ".join(parts)


def build_evidence_pack(context: Dict[str, Any]) -> Dict[str, Any]:
    """Build a compact, shared, source-addressed pack all agents must use."""
    ctx = _as_dict(context)
    b = _Builder()
    xrefs = _as_dict(ctx.get("xrefs"))
    xref_expansion = _as_dict(ctx.get("xref_expansion"))
    cues = _as_dict(ctx.get("semantic_cues"))
    focus = _as_dict(ctx.get("focus"))
    decompiler = _as_dict(ctx.get("decompiler"))
    game_ctx = _as_dict(ctx.get("game_context"))
    dump_ctx = _as_dict(ctx.get("dump_context"))
    external = _as_dict(ctx.get("external_evidence"))
    performance = _as_dict(ctx.get("performance_budget"))

    subject = {
        "function_name": ctx.get("function_name"),
        "start_ea": ctx.get("start_ea"),
        "end_ea": ctx.get("end_ea"),
        "mode": ctx.get("mode"),
        "analysis_profile": ctx.get("analysis_profile"),
        "region_kind": ctx.get("region_kind"),
        "process": game_ctx.get("process_display") or game_ctx.get("process_name") or game_ctx.get("selected_candidate"),
    }

    b.fact(
        "focus",
        "focus source=%s ea=%s item=%s line=%s"
        % (
            focus.get("source") or "-",
            focus.get("ea") or "-",
            focus.get("item_head") or "-",
            _clean(focus.get("mouse_or_cursor_line"), 240),
        ),
        address=focus.get("item_head") or focus.get("ea") or ctx.get("current_ea"),
        source="navigation",
        strength="high",
    )
    trainer_req = b.fact(
        "trainer_requirement",
        "Final analysis must preserve local game-modding/trainer purpose: what happens if hooked, usefulness, modification surface, values to log first, candidate trainer features, and safe validation experiments.",
        source="plugin.policy",
        strength="high",
    )
    b.claim(
        "Council output must include a concrete Trainer Lab assessment, not only generic reverse-engineering semantics.",
        [trainer_req],
        0.95,
        category="trainer_requirement",
        owner="plugin_policy",
    )

    if ctx.get("analyst_hint"):
        fid = b.fact("analyst_hint", ctx.get("analyst_hint"), source="user", strength="high")
        b.claim("User hypothesis must be explicitly verified against IDB evidence.", [fid], 0.75, category="analyst_context")

    if dump_ctx.get("present") and dump_ctx.get("user_notes"):
        b.fact("dump_context", dump_ctx.get("user_notes"), source="dump_context", strength="medium")

    external_facts = []
    if external.get("present"):
        for note in _as_list(external.get("analysis_text"))[:8]:
            fid = b.fact("external_static_note", note, source="external_evidence", strength="medium")
            if fid:
                external_facts.append(fid)
        for item in _as_list(external.get("items"))[:28]:
            item = _as_dict(item)
            kind = _clean(item.get("kind") or "note", 80)
            source = _clean(item.get("source") or "external", 80)
            strength = "high" if item.get("static") and item.get("address") else "medium"
            text = "[%s] %s" % (source, item.get("text") or "")
            fid = b.fact(
                "external_%s" % kind,
                text,
                address=item.get("address"),
                source="external_evidence.%s" % source,
                strength=strength,
                meta={
                    "kind": kind,
                    "confidence": item.get("confidence"),
                    "tags": item.get("tags") or [],
                    "static": bool(item.get("static")),
                },
            )
            if fid:
                external_facts.append(fid)
        if external_facts:
            b.claim(
                "Static external evidence should guide dump analysis only after it is checked against current bytes, names, XREFs, strings, and pseudocode.",
                external_facts[:12],
                0.78,
                category="external_static_evidence",
                owner="external_scout",
            )

    if performance.get("pseudocode_skipped"):
        fid = b.fact("budget", "pseudocode skipped: %s" % performance.get("skip_reason"), source="performance_budget", strength="high")
        b.claim("Analysis is bounded and should prefer focused ASM/local evidence over broad decompiler assumptions.", [fid], 0.85, category="scope")

    pseudo_focus = _as_dict(decompiler.get("focus"))
    if pseudo_focus.get("line"):
        b.fact("pseudocode_focus", pseudo_focus.get("line"), source="hexrays", strength="high")

    for item in _as_list(xrefs.get("strings"))[:20]:
        item = _as_dict(item)
        fid = b.fact(
            "string",
            item.get("value"),
            address=item.get("address") or item.get("from"),
            source="xref.string",
            strength="high",
        )
        if fid:
            b.claim("Hardcoded string anchor influences function semantics: %s" % _clean(item.get("value"), 180), [fid], 0.72, category="semantic_anchor")

    for item in _as_list(xrefs.get("data_refs"))[:16]:
        item = _as_dict(item)
        text = _fact_text(item, ["from", "to", "string", "name", "segment", "type_hint", "value_hint", "bytes"])
        strength = "high" if item.get("string") or item.get("name") else "medium"
        b.fact("data_ref", text, address=item.get("from"), source="xref.data", strength=strength)

    for item in _as_list(xrefs.get("callers"))[:10]:
        item = _as_dict(item)
        b.fact("caller", _fact_text(item, ["address", "function"]), address=item.get("address"), source="xref.caller", strength="medium")

    for item in _as_list(xrefs.get("callees"))[:16]:
        item = _as_dict(item)
        b.fact("callee", _fact_text(item, ["from", "to", "name"]), address=item.get("from"), source="xref.callee", strength="medium")

    expanded_evidence = []
    for role_name in ("callers", "callees"):
        for item in _as_list(xref_expansion.get(role_name))[:8]:
            item = _as_dict(item)
            strings = []
            for s in _as_list(item.get("strings"))[:3]:
                s = _as_dict(s)
                if s.get("value"):
                    strings.append(str(s.get("value")))
            callees = []
            for c in _as_list(item.get("callees"))[:4]:
                c = _as_dict(c)
                if c.get("name") or c.get("to"):
                    callees.append(str(c.get("name") or c.get("to")))
            text = (
                "role=%s function=%s start=%s callsite=%s incoming=%s outgoing=%s strings=%s callees=%s"
                % (
                    item.get("role") or role_name,
                    item.get("function_name"),
                    item.get("function_start"),
                    item.get("callsite_ea") or item.get("target_ea"),
                    item.get("incoming_ref_count"),
                    item.get("outgoing_call_count"),
                    strings,
                    callees,
                )
            )
            expanded_evidence.append(
                b.fact(
                    "xref_expansion_%s" % role_name.rstrip("s"),
                    text,
                    address=item.get("callsite_ea") or item.get("target_ea") or item.get("function_start"),
                    source="xref_expansion",
                    strength="medium",
                    meta={"strings": strings, "callees": callees},
                )
            )
    if expanded_evidence:
        b.claim(
            "XREF expansion should be used to connect this function to surrounding systems before deciding hook usefulness or final name.",
            expanded_evidence[:10],
            0.72,
            category="xref_context",
            owner="xref_scout",
        )

    for item in _as_list(cues.get("string_anchors"))[:18]:
        item = _as_dict(item)
        fid = b.fact("semantic_string_anchor", _fact_text(item, ["address", "from", "value", "priority"]), address=item.get("address") or item.get("from"), source="semantic_cues", strength="high")
        if fid:
            b.claim("String anchor should be treated as primary semantics: %s" % _clean(item.get("value"), 200), [fid], 0.78, category="semantic_anchor")

    likelihood = str(cues.get("bitstream_or_structured_reader_likelihood") or "").lower()
    if likelihood in ("high", "medium"):
        evidence = []
        for item in _as_list(cues.get("reader_call_evidence"))[:8]:
            item = _as_dict(item)
            evidence.append(b.fact("reader_call", _fact_text(item, ["call", "stream_arg", "bit_or_field_width", "address", "line"]), address=item.get("address"), source="semantic_cues", strength="high"))
        b.claim("Function may parse a structured stream/bitstream; do not misread repeated reader calls as memcpy.", evidence, 0.82 if likelihood == "high" else 0.62, category="algorithm")

    output_evidence = []
    for item in _as_list(cues.get("output_layout_writes"))[:18]:
        item = _as_dict(item)
        output_evidence.append(b.fact("output_write", _fact_text(item, ["base", "offset_or_index", "address", "line"]), address=item.get("address"), source="semantic_cues", strength="high"))
    if output_evidence:
        b.claim("Function writes explicit output fields/indices; model should map output layout before naming gameplay meaning.", output_evidence[:8], 0.78, category="dataflow")

    struct_evidence = []
    for item in _as_list(cues.get("structure_reads"))[:16]:
        item = _as_dict(item)
        struct_evidence.append(b.fact("structure_read", _fact_text(item, ["base", "offset", "address", "line"]), address=item.get("address"), source="semantic_cues", strength="medium"))
    if struct_evidence:
        b.claim("Input arguments look like structured objects because fixed offsets are read.", struct_evidence[:8], 0.65, category="structure")

    dirty_evidence = []
    for item in _as_list(cues.get("dirty_masks"))[:10]:
        item = _as_dict(item)
        dirty_evidence.append(b.fact("dirty_mask", _fact_text(item, ["target", "mask", "address", "line", "meaning"]), address=item.get("address"), source="semantic_cues", strength="high"))
    if dirty_evidence:
        b.claim("Bitwise OR writes likely represent dirty/update mask flags.", dirty_evidence, 0.82, category="engine_pattern")

    bitwise_evidence = []
    for item in _as_list(cues.get("bitwise_or_checksum_ops"))[:12]:
        item = _as_dict(item)
        bitwise_evidence.append(b.fact("bitwise", _fact_text(item, ["address", "line", "meaning"]), address=item.get("address"), source="semantic_cues", strength="medium"))
    for item in _as_list(cues.get("magic_constants"))[:8]:
        item = _as_dict(item)
        bitwise_evidence.append(b.fact("magic_constant", _fact_text(item, ["constant", "decimal", "address", "line", "meaning"]), address=item.get("address"), source="semantic_cues", strength="medium"))
    if bitwise_evidence:
        b.claim("Bitwise/magic-constant loop may indicate hash/checksum/obfuscation/sanity logic.", bitwise_evidence[:10], 0.64, category="algorithm")

    numeric_evidence = []
    for item in _as_list(cues.get("numeric_ops"))[:12]:
        item = _as_dict(item)
        numeric_evidence.append(b.fact("numeric_op", _fact_text(item, ["address", "line", "meaning"]), address=item.get("address"), source="semantic_cues", strength="medium"))
    if numeric_evidence:
        b.claim("Numeric accumulator/modifier behavior should be described mechanically before assigning gameplay meaning.", numeric_evidence[:8], 0.68, category="algorithm")

    mode_evidence = []
    for item in _as_list(cues.get("mode_checks"))[:12]:
        item = _as_dict(item)
        mode_evidence.append(b.fact("mode_check", _fact_text(item, ["selector", "operator", "value", "address", "line"]), address=item.get("address"), source="semantic_cues", strength="medium"))
    if mode_evidence:
        b.claim("Byte/selector comparisons likely represent operation modes or variants.", mode_evidence[:8], 0.62, category="algorithm")

    ioctl_evidence = []
    for key, fact_kind, strength in (
        ("driver_api_calls", "driver_api", "medium"),
        ("ioctl_code_checks", "ioctl_code", "high"),
        ("ioctl_buffer_access", "ioctl_buffer", "high"),
        ("ioctl_validation_checks", "ioctl_validation", "medium"),
        ("ioctl_rw_primitives", "ioctl_rw_primitive", "high"),
        ("ioctl_method_hints", "ioctl_method", "medium"),
        ("driver_strings", "driver_string", "medium"),
    ):
        for item in _as_list(cues.get(key))[:10]:
            item = _as_dict(item)
            fid = b.fact(
                fact_kind,
                _fact_text(item, ["address", "from", "line", "value", "meaning"]),
                address=item.get("address") or item.get("from"),
                source="semantic_cues",
                strength=strength,
            )
            if fid:
                ioctl_evidence.append(fid)
    if ioctl_evidence:
        b.claim(
            "Driver IOCTL audit should map selector, buffer source, validation gates, transfer method, and any memory read/write primitive before claiming a vulnerability.",
            ioctl_evidence[:12],
            0.82,
            category="driver_ioctl",
            owner="ioctl_scout",
        )

    pack_seed = {
        "subject": subject,
        "fact_count": len(b.facts),
        "claim_count": len(b.claims),
        "first_facts": b.facts[:8],
    }
    pack = {
        "version": 1,
        "id": _pack_id(pack_seed),
        "created_unix": int(time.time()),
        "subject": subject,
        "policy": [
            "All agents must use this pack as shared context.",
            "Every important claim should cite fact ids from facts[].",
            "Claims without local evidence must remain hypothesis or be rejected.",
            "User/dump context can guide search, but binary evidence wins.",
            "External static tool evidence is useful for dump triage, but current IDB bytes/XREFs/names remain the source of truth.",
        ],
        "facts": b.facts[:90],
        "initial_claims": b.claims[:40],
        "open_questions": [
            "Which claim has the strongest local evidence?",
            "Which likely name is justified by facts rather than user hint?",
            "Is this a direct trainer hook point, telemetry target, or helper to trace through?",
        ],
    }
    return pack


def build_claim_board(evidence_pack: Dict[str, Any]) -> Dict[str, Any]:
    claims = []
    for item in _as_list(_as_dict(evidence_pack).get("initial_claims")):
        if isinstance(item, dict):
            claims.append(dict(item))
    return {
        "version": 1,
        "evidence_pack_id": _as_dict(evidence_pack).get("id"),
        "policy": "Shared board. Agents may support, weaken, contradict, or add claims, but final synthesis should prefer supported claims with fact ids.",
        "claims": claims,
        "agent_notes": [],
    }


def apply_agent_claim_updates(claim_board: Dict[str, Any], agent_name: str, agent_output: Dict[str, Any]) -> Dict[str, Any]:
    board = dict(claim_board or {})
    claims = [dict(item) for item in _as_list(board.get("claims")) if isinstance(item, dict)]
    by_id = {item.get("id"): item for item in claims if item.get("id")}

    updates = _as_list(agent_output.get("claim_updates"))
    new_claims = _as_list(agent_output.get("new_claims"))
    for update in updates:
        update = _as_dict(update)
        cid = update.get("claim_id") or update.get("id")
        target = by_id.get(cid)
        if not target:
            continue
        review = {
            "agent": agent_name,
            "verdict": _clean(update.get("verdict") or update.get("status"), 40),
            "confidence": update.get("confidence"),
            "reason": _clean(update.get("reason") or update.get("notes"), 500),
            "evidence_ids": update.get("evidence_ids") or [],
        }
        target.setdefault("reviews", []).append(review)
        verdict = str(review.get("verdict") or "").lower()
        if verdict in ("supported", "confirmed"):
            target["status"] = "supported"
        elif verdict in ("contradicted", "rejected"):
            target["status"] = "contradicted"
        elif verdict in ("weak", "unsupported") and target.get("status") == "open":
            target["status"] = "weak"
    for claim in new_claims:
        claim = _as_dict(claim)
        statement = _clean(claim.get("statement"), 700)
        if not statement:
            continue
        cid = "C%03d" % (len(claims) + 1)
        item = {
            "id": cid,
            "statement": statement,
            "status": _clean(claim.get("status") or "open", 40),
            "category": _clean(claim.get("category") or "agent", 80),
            "confidence": claim.get("confidence", 0.5),
            "evidence_ids": claim.get("evidence_ids") or [],
            "owner": agent_name,
        }
        claims.append(item)
        by_id[cid] = item
    notes = _as_list(board.get("agent_notes"))
    summary = _clean(agent_output.get("summary"), 700)
    if summary:
        notes.append({"agent": agent_name, "summary": summary})
    board["claims"] = claims[:70]
    board["agent_notes"] = notes[-20:]
    return board


def supported_claim_lines(claim_board: Dict[str, Any], limit: int = 12) -> List[str]:
    lines = []
    for claim in _as_list(_as_dict(claim_board).get("claims")):
        if not isinstance(claim, dict):
            continue
        status = str(claim.get("status") or "open")
        if status not in ("supported", "open", "weak"):
            continue
        lines.append("[%s %.2f] %s" % (status, float(claim.get("confidence") or 0.0), _clean(claim.get("statement"), 220)))
        if len(lines) >= limit:
            break
    return lines
