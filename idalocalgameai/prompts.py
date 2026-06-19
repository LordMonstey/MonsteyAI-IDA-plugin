"""Prompt templates for local reverse engineering analysis."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .game_profiles import prompt_for_profile
from .sanitize import sanitize_prompt_text


SYSTEM_PROMPT = """You are a local reverse-engineering assistant inside IDA Pro.
Your purpose is defensive analysis, game modding understanding, interoperability, documentation, and IDB annotation.
Do not provide anti-cheat bypass procedures, exploit payloads, persistence, evasion, or instructions to weaponize findings.

You must be evidence-first:
- cite addresses, strings, xrefs, imports, constants, call targets, and pseudocode/assembly lines;
- distinguish fact from hypothesis;
- prefer uncertainty over invention;
- output only a raw valid JSON object;
- do not wrap JSON in Markdown fences;
- do not include prose before or after the JSON object;
- escape all quotes inside strings;
- do not put raw newlines inside JSON string values.
"""

ACTION_SYSTEM_PROMPT = """You are a local reverse-engineering assistant inside IDA Pro.
Your purpose is defensive analysis, legitimate local game modding, interoperability, documentation, and IDB annotation.
Do not provide anti-cheat bypass procedures, stealth, exploit payloads, persistence, evasion, or instructions to weaponize findings.

Be evidence-first:
- cite addresses, strings, xrefs, imports, constants, call targets, and pseudocode/assembly lines;
- distinguish fact from hypothesis;
- prefer uncertainty over invention;
- give practical local debugging/modding steps;
- use concise Markdown and C++ code blocks when helpful.
"""

JSON_REPAIR_SYSTEM_PROMPT = """You repair invalid JSON produced by a local reverse-engineering assistant.
Return only one raw valid JSON object.
Do not add Markdown fences.
Do not add explanations.
Preserve the original meaning as much as possible.
If a field is malformed beyond repair, replace that field with an empty string, empty list, null, or a conservative object matching the schema.
All strings must be valid JSON strings with escaped quotes and escaped newlines.
"""


OUTPUT_SCHEMA = {
    "mode": "pseudocode|pseudocode_reconstructed|asm_fallback|mixed|data",
    "summary": "short analyst-friendly explanation",
    "behavior": ["observable behavior or likely logic"],
    "game_relevance": ["why this matters for game modding or engine mapping"],
    "engine_hints": ["engine-specific hints such as Unreal/Unity/Source/custom clues"],
    "suggested_function_name": "snake_case_name_or_null",
    "confidence": 0.0,
    "evidence": [{"address": "0x0", "kind": "string|call|xref|import|asm|pseudocode|constant", "text": "why it matters"}],
    "risks": ["ambiguities or weak assumptions"],
    "comments": [{"address": "0x0", "text": "IDA repeatable or regular comment suggestion", "confidence": 0.0}],
    "variables": [{"old": "v1", "new": "player_controller", "confidence": 0.0, "reason": "evidence"}],
    "structures": [{"name": "PlayerState", "reason": "field access pattern or xrefs"}],
    "dataflow": [
        "precise source -> transform -> destination facts, especially output parameters and loops"
    ],
    "structure_offsets": [
        {
            "base": "a1|a1->field|global|unknown",
            "offset": "0x0",
            "type": "qword|dword|float|byte|array_entry",
            "meaning": "likely field role",
            "evidence": "pseudocode/asm line or address",
            "confidence": 0.0,
        }
    ],
    "algorithm": {
        "kind": "accumulator|interpolator|dispatcher|wrapper|validator|unknown",
        "description": "what the code mechanically computes before assigning a game meaning",
    },
    "trainer_assessment": {
        "usefulness": "high|medium|low|none",
        "category": "stat|damage|inventory|identity|network|input|render|telemetry|unknown",
        "usefulness_reason": "why this function is or is not useful for a local trainer/modding lab",
        "what_happens_if_hooked": ["expected observable effects if this function is hooked"],
        "best_hook_strategy": "observe_only|log_then_compare|modify_output|modify_argument|hook_caller|hook_callee|not_recommended",
        "modification_surface": "return_value|argument|output_buffer|global_state|field_write|event_stream|none",
        "values_to_log_first": ["arguments, fields, offsets, return values, or globals to log before changing anything"],
        "candidate_trainer_features": ["trainer/modding ideas this function could support if evidence is strong"],
        "recommended_experiments": ["small local experiments to validate usefulness"],
        "not_useful_for": ["things this function probably will not control directly"],
        "stability_notes": ["crash/desync/state-corruption risks based on local evidence"],
    },
    "trainer_radar": {
        "score": 0,
        "verdict": "short trainer/modding decision",
        "strategy_label": "observe only|log then compare|modify output|hook caller|hook callee",
        "next_move": "single best next action",
        "tags": ["candidate|mapping|trace-needed|output_buffer"],
        "hook_effect": ["what happens if hooked"],
        "log_first": ["what to log before mutation"],
        "good_for": ["supported trainer/modding outcomes"],
        "not_good_for": ["unsupported outcomes"],
        "experiments": ["small validation experiments"],
    },
    "trainer_candidates": [
        {
            "score": 0,
            "function": "name",
            "address": "0x0",
            "relation": "current|caller|callee",
            "role": "damage/stat|identity/parser|structured parser|helper/callee|unknown",
            "strategy": "hook_caller|hook_callee|observe_only|modify_output",
            "evidence": ["why it is a candidate"],
            "next_action": "what to inspect next",
        }
    ],
    "hook_experiments": [
        {
            "title": "Observe-only hook",
            "intent": "why this experiment exists",
            "steps": ["concrete local lab steps"],
            "log": ["values to log"],
            "mutation_gate": "condition before changing anything",
        }
    ],
    "xref_graph": {
        "center": {"name": "function", "address": "0x0"},
        "nodes": [{"id": "current", "label": "function", "address": "0x0", "role": "current|caller|callee", "score": 0}],
        "edges": [{"from": "caller_1", "to": "current", "label": "calls"}],
        "next_targets": [{"function": "name", "address": "0x0", "score": 0, "reason": "why inspect next"}],
    },
    "structure_hypotheses": [
        {
            "base": "a1|a2|out",
            "name": "local_struct_hypothesis_t",
            "fields": [{"offset": "0x0", "type": "uint32_t|float|uintptr_t", "meaning": "field role", "evidence": "line"}],
            "cpp_preview": "struct preview",
        }
    ],
    "semantic_cues_used": ["local semantic cues that influenced the analysis"],
    "bitstream_deserialization": {
        "likelihood": "high|medium|low|none",
        "reader_calls": ["repeated getter/read calls and widths"],
        "output_layout": ["output structure offsets/indexes populated"],
        "dirty_masks": ["output masks or update flags"],
        "sanity_checks": ["sentinel/bounds checks such as read(width)-1 then 0xFF/<=max"],
        "bitwise_checks": ["xor/rol/ror/hash/checksum/obfuscation clues"],
        "string_anchors": ["important strings anchoring semantics"],
    },
    "user_context_alignment": {
        "used": False,
        "verdict": "confirmed|plausible|weak|contradicted",
        "supports_user_hint": ["evidence that supports the user's hypothesis"],
        "contradicts_user_hint": ["evidence that conflicts with the user's hypothesis"],
        "notes": "how the analyst-provided context changed or focused the analysis",
    },
    "multi_agent": {
        "mode": "Single|Duo|Council",
        "agents": [{"name": "local_scout|xref_context_scout|analyst|context_council_finalizer", "status": "ok|fallback|error", "summary": "what this agent contributed"}],
        "policy": "how the final answer used the shared evidence pack and claim board",
    },
    "claim_board": {
        "evidence_pack_id": "pack id",
        "claims": [{"id": "C001", "status": "supported|weak|contradicted|open", "statement": "claim", "evidence_ids": ["F001"], "confidence": 0.0}],
    },
    "next_questions": ["what the analyst should inspect next"],
}


AGENT_REVIEW_SCHEMA = {
    "agent": "critic",
    "summary": "short review summary",
    "claim_updates": [
        {
            "claim_id": "C001",
            "verdict": "supported|weak|contradicted|unsupported",
            "confidence": 0.0,
            "evidence_ids": ["F001"],
            "reason": "why this verdict follows from the evidence pack",
        }
    ],
    "new_claims": [
        {
            "statement": "new evidence-backed claim",
            "status": "open|supported|weak",
            "category": "role|algorithm|trainer|risk|name",
            "confidence": 0.0,
            "evidence_ids": ["F001"],
        }
    ],
    "risks": ["specific hallucination or weak-evidence risks"],
    "trainer_notes": ["what to log/hook/avoid based on evidence"],
}


HOOK_TEMPLATE_GUIDE = r"""
Expected C++ hook scaffold style:

#pragma once

#include <cstdint>
#include <Windows.h>

#include "../../util/globals.hpp"
#include "../../util/MinHook/minhook.h"
#include "../../util/notepad.h"

namespace Hk_FunctionName
{
    inline bool g_enabled = false;

    using fnTarget = ReturnType(__fastcall*)(ArgTypes...);
    inline fnTarget oTarget = nullptr;
    inline std::uintptr_t g_target_addr = 0;

    static ReturnType __fastcall hkTarget(ArgTypes... args)
    {
        if (!oTarget) return ReturnFallback;

        if (g_enabled)
        {
            // Validate pointers and modify only the intended values.
            // Log observations before changing behavior.
        }

        return oTarget(args...);
    }

    inline bool init()
    {
        g_target_addr = globals::TargetFunction;
        if (!g_target_addr) return false;
        if (MH_CreateHook((LPVOID)g_target_addr, &hkTarget, (LPVOID*)&oTarget) != MH_OK) return false;
        if (MH_EnableHook((LPVOID)g_target_addr) != MH_OK) return false;
        return true;
    }

    inline void remove()
    {
        if (g_target_addr) MH_DisableHook((LPVOID)g_target_addr);
    }
}
"""


CALL_TEMPLATE_GUIDE = r"""
Expected C++ fastcall call scaffold style:

using fnTarget = ReturnType(__fastcall*)(ArgTypes...);
inline fnTarget Target = reinterpret_cast<fnTarget>(globals::TargetFunction);

inline ReturnType call_target(ArgTypes... args)
{
    if (!Target) return ReturnFallback;
    return Target(args...);
}
"""


def _clip(value: Any, limit: int = 600) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _prompt_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _compact_dict(item: Any, keys: List[str], text_limit: int = 500) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {"text": _clip(item, text_limit)}
    out: Dict[str, Any] = {}
    for key in keys:
        if key not in item:
            continue
        value = item.get(key)
        if isinstance(value, str):
            out[key] = _clip(value, text_limit)
        elif isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
        else:
            out[key] = value
    return out


def _compact_rows(items: Any, keys: List[str], limit: int, text_limit: int = 500) -> List[Dict[str, Any]]:
    return [_compact_dict(item, keys, text_limit) for item in _list(items)[: max(0, limit)]]


def _selected_lines(lines: Any, focus_line: Optional[int] = None, max_lines: int = 170, max_chars: int = 9000) -> List[str]:
    if not isinstance(lines, list):
        return []
    text_lines = [str(line) for line in lines]
    if len(text_lines) <= max_lines:
        selected = text_lines
    else:
        indices = set(range(0, min(55, len(text_lines))))
        if focus_line is not None and 0 <= focus_line < len(text_lines):
            start = max(0, focus_line - 55)
            end = min(len(text_lines), focus_line + 56)
            indices.update(range(start, end))
        indices.update(range(max(0, len(text_lines) - 35), len(text_lines)))
        ordered = sorted(indices)
        selected = []
        previous = None
        for idx in ordered[:max_lines]:
            if previous is not None and idx > previous + 1:
                selected.append("... %d pseudocode lines omitted ..." % (idx - previous - 1))
            selected.append(text_lines[idx])
            previous = idx
    out = []
    total = 0
    for line in selected:
        total += len(line) + 1
        if total > max_chars:
            out.append("... pseudocode compacted by prompt budget ...")
            break
        out.append(line)
    return out


def _compact_focus(focus: Dict[str, Any]) -> Dict[str, Any]:
    highlight = _dict(focus.get("highlight"))
    widget = _dict(focus.get("widget"))
    data_artifact = _dict(focus.get("data_artifact"))
    compact = {
        "source": focus.get("source"),
        "source_age_seconds": focus.get("source_age_seconds"),
        "ea": focus.get("ea"),
        "item_head": focus.get("item_head"),
        "segment": focus.get("segment"),
        "name": focus.get("name"),
        "mouse_or_cursor_line": _clip(focus.get("mouse_or_cursor_line"), 360),
        "highlight": {
            "text": _clip(highlight.get("text"), 180),
            "widget_title": _clip(highlight.get("widget_title"), 120),
        },
        "widget": {
            "title": _clip(widget.get("title"), 120),
            "type": _clip(widget.get("type"), 80),
        },
        "disasm": _clip(focus.get("disasm"), 360),
        "mnemonic": focus.get("mnemonic"),
        "bytes": focus.get("bytes"),
        "data_artifact": {
            "kind": data_artifact.get("kind"),
            "start_ea": data_artifact.get("start_ea"),
            "end_ea": data_artifact.get("end_ea"),
            "segment": data_artifact.get("segment"),
            "label": _clip(data_artifact.get("label"), 96),
            "value": _clip(data_artifact.get("value"), 260),
            "type_hint": data_artifact.get("type_hint"),
            "bytes": _clip(data_artifact.get("bytes"), 160),
        },
        "comment": _clip(focus.get("comment"), 300),
        "xrefs": {
            "code_from": _compact_rows(_dict(focus.get("xrefs")).get("code_from"), ["to", "name"], 8, 220),
            "code_to": _compact_rows(_dict(focus.get("xrefs")).get("code_to"), ["from", "function"], 8, 220),
            "data_from": _compact_rows(_dict(focus.get("xrefs")).get("data_from"), ["to", "string"], 8, 220),
            "data_to": _compact_rows(_dict(focus.get("xrefs")).get("data_to"), ["from", "function"], 8, 220),
        },
        "nearby_assembly": _compact_rows(
            focus.get("nearby_assembly"),
            ["address", "mnemonic", "disasm"],
            34,
            260,
        ),
    }
    return compact


def _compact_xref_expansion(expansion: Dict[str, Any]) -> Dict[str, Any]:
    def mini(item: Any) -> Dict[str, Any]:
        data = _dict(item)
        return {
            "role": data.get("role"),
            "function_start": data.get("function_start"),
            "function_name": data.get("function_name"),
            "target_ea": data.get("target_ea"),
            "callsite_ea": data.get("callsite_ea"),
            "callsite_disasm": _clip(data.get("callsite_disasm"), 260),
            "incoming_ref_count": data.get("incoming_ref_count"),
            "outgoing_call_count": data.get("outgoing_call_count"),
            "strings": _compact_rows(data.get("strings"), ["address", "from", "value"], 5, 220),
            "callees": _compact_rows(data.get("callees"), ["from", "to", "name"], 8, 220),
            "local_assembly": _compact_rows(data.get("local_assembly"), ["address", "mnemonic", "disasm"], 16, 240),
        }

    return {
        "policy": expansion.get("policy"),
        "callers": [mini(item) for item in _list(expansion.get("callers"))[:3]],
        "callees": [mini(item) for item in _list(expansion.get("callees"))[:3]],
    }


def _compact_game_context(game_context: Dict[str, Any]) -> Dict[str, Any]:
    lookup = _dict(game_context.get("online_lookup"))
    local = _dict(game_context.get("local_clues"))
    return {
        "identity_candidates": _list(game_context.get("identity_candidates"))[:6],
        "selected_candidate": game_context.get("selected_candidate"),
        "process_name": game_context.get("process_name"),
        "process_display": game_context.get("process_display"),
        "process_full_name": game_context.get("process_full_name"),
        "local_clues": {
            "path_candidates": _list(local.get("path_candidates"))[:6],
            "interesting_strings": [_clip(item, 220) for item in _list(local.get("interesting_strings"))[:18]],
            "function_strings": [_clip(item, 220) for item in _list(local.get("function_strings"))[:18]],
        },
        "online_lookup": {
            "enabled": lookup.get("enabled"),
            "used": lookup.get("used"),
            "cache_hit": lookup.get("cache_hit"),
            "query": lookup.get("query"),
            "heading": _clip(lookup.get("heading"), 160),
            "abstract": _clip(lookup.get("abstract"), 520),
            "url": _clip(lookup.get("url"), 220),
            "related": _compact_rows(lookup.get("related"), ["text", "url"], 3, 260),
            "error": _clip(lookup.get("error"), 160),
        },
    }


def _compact_semantic_cues(cues: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "policy": cues.get("policy"),
        "bitstream_or_structured_reader_likelihood": cues.get("bitstream_or_structured_reader_likelihood"),
        "likely_reader_calls": _compact_rows(cues.get("likely_reader_calls"), ["call", "stream_arg", "widths"], 12, 180),
        "reader_call_evidence": _compact_rows(cues.get("reader_call_evidence"), ["call", "stream_arg", "bit_or_field_width", "address", "line"], 18, 260),
        "structure_reads": _compact_rows(cues.get("structure_reads"), ["base", "offset", "address", "line"], 22, 260),
        "output_layout_writes": _compact_rows(cues.get("output_layout_writes"), ["base", "offset_or_index", "address", "line"], 24, 260),
        "dirty_masks": _compact_rows(cues.get("dirty_masks"), ["target", "mask", "address", "line", "meaning"], 16, 260),
        "numeric_ops": _compact_rows(cues.get("numeric_ops"), ["address", "line", "meaning"], 18, 260),
        "mode_checks": _compact_rows(cues.get("mode_checks"), ["selector", "operator", "value", "address", "line"], 16, 260),
        "bitwise_or_checksum_ops": _compact_rows(cues.get("bitwise_or_checksum_ops"), ["address", "line", "meaning"], 16, 260),
        "bounds_checks": _compact_rows(cues.get("bounds_checks"), ["operator", "value", "address", "line"], 16, 260),
        "sanitization_idioms": _compact_rows(cues.get("sanitization_idioms"), ["address", "line", "meaning"], 12, 260),
        "magic_constants": _compact_rows(cues.get("magic_constants"), ["constant", "decimal", "address", "line", "meaning"], 16, 260),
        "string_anchors": _compact_rows(cues.get("string_anchors"), ["address", "from", "value", "priority"], 24, 260),
        "anti_misread_notes": [_clip(item, 240) for item in _list(cues.get("anti_misread_notes"))[:6]],
    }


def _compact_evidence_pack(pack: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(pack, dict):
        return {}
    return {
        "version": pack.get("version"),
        "id": pack.get("id"),
        "subject": pack.get("subject") or {},
        "policy": _list(pack.get("policy"))[:6],
        "facts": _compact_rows(pack.get("facts"), ["id", "kind", "address", "text", "source", "strength"], 70, 420),
        "initial_claims": _compact_rows(pack.get("initial_claims"), ["id", "statement", "status", "category", "confidence", "evidence_ids", "owner"], 32, 420),
        "open_questions": [_clip(item, 220) for item in _list(pack.get("open_questions"))[:6]],
    }


def _compact_claim_board(board: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(board, dict):
        return {}
    return {
        "version": board.get("version"),
        "evidence_pack_id": board.get("evidence_pack_id"),
        "policy": _clip(board.get("policy"), 320),
        "claims": _compact_rows(board.get("claims"), ["id", "statement", "status", "category", "confidence", "evidence_ids", "owner", "reviews"], 45, 460),
        "agent_notes": _compact_rows(board.get("agent_notes"), ["agent", "summary"], 10, 360),
    }


def compact_analysis_context(context: Dict[str, Any]) -> Dict[str, Any]:
    decompiler = _dict(context.get("decompiler"))
    pseudo_focus = _dict(decompiler.get("focus"))
    focus_line = None
    try:
        focus_line = int(pseudo_focus.get("line_number"))
    except Exception:
        focus_line = None
    xrefs = _dict(context.get("xrefs"))
    data_artifact = _dict(context.get("data_artifact"))
    dump_context = _dict(context.get("dump_context"))
    performance = _dict(context.get("performance_budget"))
    metrics = _dict(performance.get("function_metrics"))
    known_map = _dict(context.get("known_game_map"))
    external = _dict(context.get("external_evidence"))
    toolchain_auto = _dict(context.get("toolchain_auto"))

    return {
        "compaction": {
            "policy": "bounded context for faster local LLM analysis; semantic_cues and focus are prioritized",
            "original_pseudocode_line_count": len(_list(decompiler.get("lines"))),
            "original_assembly_line_count": len(_list(context.get("assembly"))),
            "original_caller_count": len(_list(xrefs.get("callers"))),
            "original_callee_count": len(_list(xrefs.get("callees"))),
        },
        "mode": context.get("mode"),
        "region_kind": context.get("region_kind"),
        "current_ea": context.get("current_ea"),
        "screen_ea": context.get("screen_ea"),
        "start_ea": context.get("start_ea"),
        "end_ea": context.get("end_ea"),
        "function_name": context.get("function_name"),
        "has_function": context.get("has_function"),
        "data_artifact": {
            "kind": data_artifact.get("kind"),
            "address": data_artifact.get("address"),
            "start_ea": data_artifact.get("start_ea"),
            "end_ea": data_artifact.get("end_ea"),
            "focus_ea": data_artifact.get("focus_ea"),
            "segment": data_artifact.get("segment"),
            "name": _clip(data_artifact.get("name"), 120),
            "label": _clip(data_artifact.get("label"), 120),
            "value": _clip(data_artifact.get("value"), 520),
            "length": data_artifact.get("length"),
            "source": data_artifact.get("source"),
            "bytes": _clip(data_artifact.get("bytes"), 220),
            "type_hint": data_artifact.get("type_hint"),
        },
        "database": _compact_dict(_dict(context.get("database")), ["root_filename", "input_file", "imagebase"], 260),
        "game_context": _compact_game_context(_dict(context.get("game_context"))),
        "analyst_context": context.get("analyst_context") or {},
        "analyst_hint": _clip(context.get("analyst_hint"), 1800),
        "dump_context": {
            "present": dump_context.get("present"),
            "path": dump_context.get("path"),
            "priority": dump_context.get("priority"),
            "user_notes": _clip(dump_context.get("user_notes"), 4200),
        },
        "external_evidence": {
            "present": external.get("present"),
            "policy": _clip(external.get("policy"), 260),
            "matched_count": external.get("matched_count"),
            "summary": external.get("summary") or {},
            "analysis_text": [_clip(item, 300) for item in _list(external.get("analysis_text"))[:12]],
            "items": _compact_rows(
                external.get("items"),
                ["source", "kind", "address", "text", "confidence", "tags", "static"],
                45,
                520,
            ),
        },
        "toolchain_auto": {
            "enabled": toolchain_auto.get("enabled"),
            "status": toolchain_auto.get("status"),
            "scout": toolchain_auto.get("scout"),
            "reason": _clip(toolchain_auto.get("reason"), 360),
            "score": toolchain_auto.get("score"),
            "elapsed_seconds": toolchain_auto.get("elapsed_seconds"),
            "row_count": toolchain_auto.get("row_count"),
            "available_libraries": _list(toolchain_auto.get("available_libraries"))[:10],
            "error": _clip(toolchain_auto.get("error"), 260),
        },
        "focus": _compact_focus(_dict(context.get("focus"))),
        "decompiler": {
            "available": decompiler.get("available"),
            "synthetic": decompiler.get("synthetic"),
            "source": decompiler.get("source"),
            "error": _clip(decompiler.get("error"), 260),
            "truncated": decompiler.get("truncated"),
            "skipped_by_budget": decompiler.get("skipped_by_budget"),
            "focus": {
                "line_number": pseudo_focus.get("line_number"),
                "line": _clip(pseudo_focus.get("line"), 420),
                "nearby_lines": _compact_rows(pseudo_focus.get("nearby_lines"), ["line_number", "text"], 28, 360),
                "highlight": pseudo_focus.get("highlight") or {},
            },
            "lines": _selected_lines(decompiler.get("lines"), focus_line=focus_line),
        },
        "assembly": _compact_rows(context.get("assembly"), ["address", "mnemonic", "disasm", "bytes"], 150, 260),
        "xrefs": {
            "callers": _compact_rows(xrefs.get("callers"), ["address", "function"], 14, 240),
            "callees": _compact_rows(xrefs.get("callees"), ["from", "to", "name"], 24, 240),
            "data_refs": _compact_rows(
                xrefs.get("data_refs"),
                ["from", "to", "string", "name", "segment", "type_hint", "item_size", "value_hint", "bytes"],
                18,
                240,
            ),
            "strings": _compact_rows(xrefs.get("strings"), ["address", "from", "value"], 28, 260),
        },
        "xref_expansion": _compact_xref_expansion(_dict(context.get("xref_expansion"))),
        "semantic_cues": _compact_semantic_cues(_dict(context.get("semantic_cues"))),
        "existing_comments": _compact_rows(context.get("existing_comments"), ["address", "text"], 12, 260),
        "engine_hints_from_ida": _list(context.get("engine_hints_from_ida"))[:10],
        "known_game_map": {
            "known_engine_hints": _compact_rows(known_map.get("known_engine_hints"), ["hint", "count"], 8, 160),
            "recent_function_findings": _compact_rows(
                known_map.get("recent_function_findings"),
                ["address", "name", "summary", "engine_hints", "confidence", "feedback"],
                8,
                260,
            ),
            "recent_feedback": _compact_rows(
                known_map.get("recent_feedback"),
                ["address", "function_name", "corrected_name", "corrected_role", "usefulness", "strategy", "notes", "updated_at"],
                8,
                500,
            ),
        },
        "evidence_pack": _compact_evidence_pack(_dict(context.get("evidence_pack"))),
        "claim_board": _compact_claim_board(_dict(context.get("claim_board"))),
        "performance_budget": {
            "max_asm_lines": performance.get("max_asm_lines"),
            "max_pseudocode_chars": performance.get("max_pseudocode_chars"),
            "max_decompile_instructions": performance.get("max_decompile_instructions"),
            "max_decompile_bytes": performance.get("max_decompile_bytes"),
            "max_xref_items": performance.get("max_xref_items"),
            "max_xref_expansion_items": performance.get("max_xref_expansion_items"),
            "pseudocode_skipped": performance.get("pseudocode_skipped"),
            "skip_reason": _clip(performance.get("skip_reason"), 260),
            "function_metrics": {
                "bytes": metrics.get("bytes"),
                "instructions_scanned": metrics.get("instructions_scanned"),
                "jumps_scanned": metrics.get("jumps_scanned"),
                "calls_scanned": metrics.get("calls_scanned"),
                "jump_ratio": metrics.get("jump_ratio"),
                "flattening_hint": metrics.get("flattening_hint"),
            },
        },
        "notes": [_clip(item, 260) for item in _list(context.get("notes"))[:6]],
    }


def build_analysis_messages(context: Dict[str, Any], engine_profile: str) -> list:
    analyst_context = context.get("analyst_context") or {
        "present": bool(str(context.get("analyst_hint") or "").strip()),
        "user_hypothesis": str(context.get("analyst_hint") or "").strip(),
    }
    dump_context = context.get("dump_context") or {}
    user = {
        "task": "Analyze this IDA function, non-decompilable red/assembly region, or focused data/string artifact for game-modding reverse engineering.",
        "priority_analyst_context": analyst_context,
        "priority_dump_context": dump_context,
        "requirements": [
            "If pseudocode is unavailable, reason from assembly, xrefs, strings, calls, constants, and bytes.",
            "If context.mode is data or context.data_artifact.kind is present, treat the focus as a data/string artifact, not executable code.",
            "For data/string artifacts, do not invent loops, parameters, return values, accumulators, or hook behavior. Explain the literal value, address, segment, references to it, and which referencing function should be inspected next.",
            "For a data/string artifact, trainer_assessment.usefulness should usually be low or none, modification_surface should be none, and best_hook_strategy should point toward observing/tracing the referencing code rather than hooking the data itself.",
            "Do not treat IDA 'db xxh ; char' rows as executable assembly instructions.",
            "If pseudocode is available or supplied in context, analyze pseudocode data-flow before xrefs and before game-level guesses.",
            "If context.mode is pseudocode_reconstructed or context.decompiler.synthetic is true, treat pseudocode as approximate ASM-derived pseudo-C: use it to organize control/data flow, but verify claims against assembly addresses and mention reconstruction uncertainty in risks.",
            "First identify what the function mechanically computes: output parameters, field offsets, loop entry size, operation modes, arithmetic, and return value quality.",
            "Use context.semantic_cues as first-class local evidence. Mention the cues you relied on in semantic_cues_used.",
            "Use context.evidence_pack as the shared source of truth for multi-agent analysis. Important claims should cite evidence_pack fact ids such as F001.",
            "Use context.claim_board as the shared working memory. Support, weaken, or contradict claims using fact ids; do not invent unsupported claims.",
            "Do not leave summary, dataflow, risks, or user_context_alignment blank. If evidence is weak, say what local evidence exists and what remains unknown.",
            "Never output '-' as a whole field value unless the schema truly has no compatible evidence.",
            "If context.semantic_cues.bitstream_or_structured_reader_likelihood is medium or high, evaluate whether the function is a deserializer/parser before calling it a memcpy/copy.",
            "Repeated calls like read_func(a1, 64), read_func(a1, 6), read_func(a1, 9) usually imply a bitstream/file/network reader; identify the reader candidate and bit widths.",
            "Map output writes by base and offset/index. Prefer 'fills structure fields' over 'copies a buffer' when explicit offsets are written.",
            "Map structure reads by base and offset when present, especially a1/a2 pointer fields.",
            "For float min/max/multiply/add loops writing to a2[index] or an output array, describe the algorithm as a numeric accumulator/modifier before naming it damage, stats, health, etc.",
            "Byte selector checks such as field == 0/1/2 often indicate operation modes; explain each mode mechanically.",
            "Always fill trainer_assessment for local game-modding/trainer design.",
            "When possible, fill trainer_radar, trainer_candidates, hook_experiments, xref_graph, and structure_hypotheses as concise structured objects for the UI.",
            "trainer_radar must answer the practical question: should we hook this, observe it, trace the caller, trace the callee, or ignore it for trainer work?",
            "trainer_candidates should rank current/caller/callee functions by practical local trainer/modding usefulness, not generic reverse-engineering interest.",
            "hook_experiments should be concrete observe/log/compare/mutate-only-after-validation steps.",
            "structure_hypotheses should map offsets into a pseudo-struct only when offset evidence exists.",
            "In trainer_assessment.what_happens_if_hooked, explain the likely observable effect of hooking the function, not just what the function does.",
            "In trainer_assessment.usefulness, grade whether this is a good trainer hook point: high for direct gameplay value mutation, medium for useful telemetry or output mutation, low for identity/parsing/validation helpers, none when hooking is not meaningful.",
            "In trainer_assessment.candidate_trainer_features, suggest practical local lab/trainer features only when current evidence supports them.",
            "If the function parses identity/network/player-name data, say it is useful for telemetry/structure mapping but probably not a direct gameplay modifier.",
            "If the function accumulates damage/stat/inventory values into output fields, identify which output fields or arguments should be logged before mutation.",
            "If the analyst hint names damage received/done and the body shows float add/sub/mul/max accumulator math, treat it as a damage/stat modifier candidate to validate, not as not_recommended merely because strings are absent.",
            "For damage received/done hypotheses, explicitly propose log-first separation of caller paths, arguments, return value, output fields, and value direction before any mutation.",
            "Prefer hook_caller or hook_callee when the current function is only a parser, validator, wrapper, or helper.",
            "Recognize '*out_mask |= X' or equivalent '|=' on output parameters as dirty/update mask flags.",
            "Flag XOR/ROL/ROR/AND/OR/shift loops and large constants as checksum/hash/obfuscation/sanity-check candidates.",
            "Correlate read widths with bounds checks, for example read(6)-1 plus 0xFF/<=0x1F style sentinel validation.",
            "Give hardcoded strings maximum semantic weight, especially identity/network/player strings such as player-name labels.",
            "Never ignore context.semantic_cues.string_anchors when explaining function role.",
            "Explain behavior in friendly language.",
            "Identify engine/system role when possible.",
            "Suggest a safe function name only when evidence is strong.",
            "All claims must cite evidence.",
            "Use known_game_map as local project memory, but treat it as hypothesis unless current evidence confirms it.",
            "Use known_game_map.recent_feedback as high-priority analyst corrections. If a correction conflicts with your first guess, prefer the correction unless current binary evidence clearly contradicts it.",
            "When current function address matches a known feedback entry, explicitly reflect that feedback in user_context_alignment or risks and avoid repeating the old mistake.",
            "Use context.dump_context.user_notes as analyst-provided dump/process background; treat it as high-priority context but still not binary proof.",
            "Use context.external_evidence as high-priority static tool/analyst evidence for this dump: diff results, signatures, capa/rule matches, deobfuscation notes, structure/vtable hints, xrefs, and strings.",
            "When external evidence is present, explicitly mention which static evidence changed your confidence, naming, trainer usefulness, or next target.",
            "When external evidence mentions sidecar obfuscation, flattening, opaque predicates, indirect branches, bitwise mixes, or magic constants, explain the obfuscation impact before assigning a high-level gameplay role.",
            "If sidecar evidence marks a dispatcher/flattening candidate, prefer a conservative name and propose a next XREF/IR/deobfuscation step instead of pretending the bounded selection is the whole function.",
            "Treat external evidence as imported facts to verify against the current IDB; do not blindly trust old-version names or signatures if current code contradicts them.",
            "For dump/static analysis, prefer diff/deobf/structure/signature/rule evidence over runtime assumptions.",
            "If priority_analyst_context.present is true, treat priority_analyst_context.user_hypothesis as the primary hypothesis to verify.",
            "When a user hypothesis is present, explicitly compare current evidence against it in user_context_alignment.",
            "Do not ignore the user hypothesis just because symbols are weak; use it to focus what evidence to look for.",
            "Do not simply repeat the user's hypothesis as the answer; grade it as confirmed, plausible, weak, or contradicted.",
            "If the body shows a generic stat/modifier/vector computation, say that directly, then carry the user's damage/stat hint into a concrete validation plan instead of dismissing it.",
            "Prioritize context.focus and context.navigation when explaining what the user is currently inspecting.",
            "When focus.mouse_or_cursor_line or focus.highlight is present, explain that exact line or identifier first.",
            "Use context.xref_expansion to understand nearby callers/callees and likely role in the engine.",
            "Do not claim a specific caller role such as player action handler unless a caller name, address, or pseudocode line in the context supports it.",
            "Use context.game_context.process_name/process_display and online_lookup as dynamic process background, but never treat web lookup as binary evidence.",
            "If context.dump_context names an engine or process, do not add generic Unreal/Unity risk statements unless current binary evidence directly supports them.",
            "Do not infer a game engine from compiler artifacts such as __security_check_cookie, stack cookies, CRT helpers, or SEH boilerplate.",
            "Do not mention stack cookies, SEH, or compiler boilerplate unless they are directly relevant to the function's behavior.",
            "When an output buffer is initialized then modified in a loop, describe it as an output vector/array until stronger evidence names the gameplay concept.",
            "If context.performance_budget.pseudocode_skipped is true, explicitly say the analysis used bounded ASM/focus context and recommend narrowing selection for deeper analysis.",
            "If context.has_function is true, next_questions must include exactly these two actionable questions:",
            "Lets call it and see the returns",
            "Lets hook it and modify something",
            "Return user_context_alignment.used=true when priority_analyst_context was present, even if the evidence contradicts it.",
            "Return multi_agent and claim_board fields when context.evidence_pack is present.",
            "Return JSON matching the provided schema.",
        ],
        "engine_profile": prompt_for_profile(engine_profile),
        "schema": OUTPUT_SCHEMA,
        "context": compact_analysis_context(context),
    }
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _prompt_json(user)},
    ]


def build_council_critic_messages(
    context: Dict[str, Any],
    evidence_pack: Dict[str, Any],
    claim_board: Dict[str, Any],
    analyst_analysis: Dict[str, Any],
) -> list:
    user = {
        "task": "Act as the critic/verifier in a multi-agent reverse-engineering council.",
        "requirements": [
            "Do not produce the final user-facing analysis.",
            "Audit the analyst analysis against the Evidence Pack and Claim Board.",
            "This council is for game-modding/trainer reverse engineering. Do not let the final answer drift into generic binary analysis only.",
            "Specifically audit trainer_assessment: usefulness, what_happens_if_hooked, best_hook_strategy, modification_surface, values_to_log_first, candidate_trainer_features, recommended_experiments, not_useful_for, and stability_notes.",
            "If the analyst did not answer 'what happens if we hook it / is this useful / what can we do with it', add or weaken claims so the synthesizer fixes it.",
            "Mark claims as supported, weak, contradicted, or unsupported.",
            "Every verdict should cite evidence_ids from the Evidence Pack when possible.",
            "Attack overconfident names, unsupported game-role claims, weak hook usefulness, and claims based only on user hints.",
            "Prefer precise uncertainty over invention.",
            "Return only JSON matching the critic schema.",
        ],
        "critic_schema": AGENT_REVIEW_SCHEMA,
        "context": compact_analysis_context(context),
        "evidence_pack": _compact_evidence_pack(evidence_pack),
        "claim_board": _compact_claim_board(claim_board),
        "analyst_analysis": analyst_analysis,
    }
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _prompt_json(user)},
    ]


def build_xref_explorer_messages(
    context: Dict[str, Any],
    evidence_pack: Dict[str, Any],
    claim_board: Dict[str, Any],
) -> list:
    user = {
        "task": "Act as the external-context scout in a context-only reverse-engineering council.",
        "requirements": [
            "You are not the final analyst. Do not rewrite or decide the final function analysis.",
            "Focus only on callers, callees, data refs, strings, xref_expansion, and how they connect facts together.",
            "Your purpose is to add context for game-modding/trainer decisions: whether this function is a direct hook target, helper, parser, telemetry source, caller to trace, or callee to inspect.",
            "If the focus is a data/string artifact, map which functions reference it and what those references might mean; do not describe it as executable behavior.",
            "Add evidence-backed claims that connect multiple facts, for example string anchors plus caller/callee names, output writes plus consumers, or data refs plus surrounding functions.",
            "If XREF expansion is sparse or disabled, say so and recommend the next xref direction.",
            "Every new claim should cite fact ids from the Evidence Pack when possible.",
            "Do not produce final prose or a replacement analysis; update the Claim Board using the critic schema.",
            "Return only JSON matching the critic schema.",
        ],
        "critic_schema": AGENT_REVIEW_SCHEMA,
        "context": compact_analysis_context(context),
        "evidence_pack": _compact_evidence_pack(evidence_pack),
        "claim_board": _compact_claim_board(claim_board),
    }
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _prompt_json(user)},
    ]


def build_council_synthesis_messages(
    context: Dict[str, Any],
    evidence_pack: Dict[str, Any],
    claim_board: Dict[str, Any],
    analyst_analysis: Dict[str, Any],
    critic_output: Dict[str, Any],
) -> list:
    user = {
        "task": "Synthesize the final IDA analysis from the shared Evidence Pack, Claim Board, analyst output, and critic review.",
        "requirements": [
            "Return the final user-facing JSON analysis matching the main schema.",
            "This is a solo-anchored council: preserve the analyst's mechanical interpretation by default.",
            "Only rewrite behavior, algorithm, output offsets, hook usefulness, or suggested name when the Evidence Pack or critic clearly proves the analyst is wrong or incomplete.",
            "Do not compress away concrete offsets, calls, strings, operation modes, values to log, or trainer decisions from the analyst output.",
            "When uncertain, keep the analyst wording and add risks/evidence instead of replacing it with generic prose.",
            "The output is for local game-modding/trainer design, not just generic reverse engineering.",
            "Always preserve and complete trainer_assessment. The final UI must answer: what happens if we hook it, is this function useful, what can we do with it, what should we log first, and what should we avoid.",
            "If the function is not a direct trainer target, still explain its indirect value for telemetry, structure mapping, caller tracing, entity labeling, or finding the real downstream target.",
            "Use supported claims first, weak claims cautiously, contradicted claims only as risks or rejected hypotheses.",
            "Do not copy analyst claims that the critic contradicted unless new evidence supports them.",
            "Every important behavior/name/trainer statement should be grounded in evidence ids, addresses, strings, offsets, calls, or semantic cues.",
            "Preserve useful local enrichment and trainer assessment details.",
            "Fill multi_agent with agent contributions and policy.",
            "Include the updated claim_board in the final output.",
            "If the evidence is weak, choose a conservative function name or no name.",
            "Return only raw JSON.",
        ],
        "schema": OUTPUT_SCHEMA,
        "context": compact_analysis_context(context),
        "evidence_pack": _compact_evidence_pack(evidence_pack),
        "claim_board": _compact_claim_board(claim_board),
        "analyst_analysis": analyst_analysis,
        "critic_output": critic_output,
    }
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _prompt_json(user)},
    ]


def build_json_repair_messages(raw_text: str, parse_error: str) -> list:
    user = {
        "task": "Repair this invalid JSON response so it can be parsed by json.loads.",
        "parse_error": sanitize_prompt_text(parse_error, 1200),
        "schema": OUTPUT_SCHEMA,
        "invalid_json_text": sanitize_prompt_text(raw_text, 30000),
    }
    return [
        {"role": "system", "content": JSON_REPAIR_SYSTEM_PROMPT},
        {"role": "user", "content": _prompt_json(user)},
    ]


def build_action_messages(context: Dict[str, Any], analysis: Dict[str, Any], action_kind: str, user_goal: str) -> list:
    action_label = "call the function and inspect return values" if action_kind == "call" else "hook the function and modify behavior"
    user = {
        "task": "Help build a practical local game-modding experiment for this analyzed function.",
        "action": action_label,
        "user_goal": sanitize_prompt_text(user_goal, 5000),
        "requirements": [
            "Use the prior analysis and current IDA context.",
            "Use analysis.trainer_assessment as the primary guide for whether this is a good local trainer hook point.",
            "Use analysis.trainer_radar as the practical decision layer: verdict, strategy, next_move, log_first, hook_effect, and experiments should drive the plan.",
            "Use analysis.trainer_candidates to recommend whether the current function, a caller, or a callee should be hooked next.",
            "Use analysis.hook_experiments as the scaffold for the answer; do not invent a riskier mutation path when an observe/log experiment is recommended.",
            "Use analysis.structure_hypotheses to name output/input fields in the code comments when available.",
            "If trainer_assessment says observe_only or not_recommended, propose a logging/tracing scaffold first and explain what downstream target to find next.",
            "If trainer_assessment identifies an output_buffer, field_write, argument, or return_value surface, place the modification only after logging proves the value meaning.",
            "Use context.dump_context.user_notes when planning the experiment.",
            "Start with assumptions and unknowns.",
            "Explain what to log first before modifying behavior.",
            "Use __fastcall when proposing direct call or hook signatures unless evidence says otherwise.",
            "Use address/global placeholders matching the project style, for example globals::TargetFunction.",
            "Put the final C++ scaffold in one fenced ```cpp code block so the UI can extract it into the code workspace.",
            "Avoid anti-cheat bypass, stealth, evasion, spoofing, persistence, or weaponized behavior.",
            "Keep code scoped to legitimate local modding/debugging.",
        ],
        "hook_template_style": HOOK_TEMPLATE_GUIDE if action_kind == "hook" else "",
        "call_template_style": CALL_TEMPLATE_GUIDE if action_kind == "call" else "",
        "context": compact_analysis_context(context),
        "analysis": analysis,
    }
    return [
        {"role": "system", "content": ACTION_SYSTEM_PROMPT},
        {"role": "user", "content": _prompt_json(user)},
    ]


def build_pseudocode_diff_messages(
    old_text: str,
    new_text: str,
    local_diff: Dict[str, Any],
    user_goal: str,
) -> list:
    user = {
        "task": "Compare pseudocode from an older game build and a newer game build for local modding/trainer porting.",
        "user_goal": sanitize_prompt_text(user_goal, 2000),
        "requirements": [
            "Use local_diff as mechanical evidence; do not ignore changed calls, constants, offsets, or changed blocks.",
            "Explain what changed mechanically first: signature, branches, calls, constants, offsets, structure layout, output fields, validation, and dataflow.",
            "Then explain trainer/modding impact: whether an old hook is still likely valid, what must be re-logged, and what is risky to port blindly.",
            "Call out added/removed calls and changed constants as possible helper behavior, balance values, validation, parsing, or side effects.",
            "If offsets changed, treat structure layout as unstable until validated.",
            "If the new version only has small numeric changes, say whether it looks like balance/tuning instead of a hook rewrite.",
            "Return concise Markdown with sections: Summary, Mechanical Changes, Trainer Porting Impact, Risk, Experiments.",
            "Avoid anti-cheat bypass, stealth, evasion, or weaponized instructions.",
        ],
        "local_diff": local_diff,
        "old_pseudocode": sanitize_prompt_text(old_text, 22000),
        "new_pseudocode": sanitize_prompt_text(new_text, 22000),
    }
    return [
        {"role": "system", "content": ACTION_SYSTEM_PROMPT},
        {"role": "user", "content": _prompt_json(user)},
    ]
