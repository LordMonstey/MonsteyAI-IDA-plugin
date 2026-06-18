"""Runtime policy for keeping analysis responsive."""

from __future__ import annotations

from typing import Any, Dict


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def normalize_agent_mode(value: Any) -> str:
    mode = str(value or "Single").strip().title()
    return mode if mode in ("Single", "Duo", "Council") else "Single"


def analysis_depth(value: Any) -> str:
    depth = str(value or "Fast").strip().title()
    return depth if depth in ("Fast", "Balanced", "Deep") else "Fast"


def xref_expansion_count(context: Dict[str, Any]) -> int:
    expansion = _dict(_dict(context).get("xref_expansion"))
    callers = expansion.get("callers") if isinstance(expansion.get("callers"), list) else []
    callees = expansion.get("callees") if isinstance(expansion.get("callees"), list) else []
    return len(callers) + len(callees)


def agent_policy(cfg: Any, context: Dict[str, Any]) -> Dict[str, Any]:
    """Return requested/effective agent mode plus the reason for any downgrade."""
    requested = normalize_agent_mode(getattr(cfg, "agent_mode", "Single"))
    effective = requested
    reason = ""
    depth = analysis_depth(getattr(cfg, "analysis_depth", "Fast"))
    ctx = _dict(context)
    performance = _dict(ctx.get("performance_budget"))
    mode = str(ctx.get("mode") or "")
    region_kind = str(ctx.get("region_kind") or "")
    expanded_xrefs = xref_expansion_count(ctx)
    max_expand = int(performance.get("max_xref_expansion_items") or 0)
    asm_simple = (
        mode == "asm_fallback"
        and region_kind in ("function_asm", "selection", "selection_no_function", "segment_window", "segment_window_no_function")
    )
    data_focus = mode == "data" or str(ctx.get("region_kind") or "").startswith("data")
    if requested == "Council" and data_focus and depth != "Deep":
        effective = "Duo"
        reason = "speed guard: data/string focus uses local Evidence Pack and skips XREF LLM scouts unless Deep mode is selected."
    elif requested == "Council" and depth == "Fast":
        effective = "Duo"
        reason = "speed guard: Fast depth uses local Evidence Pack + one analyst instead of Context Council scouts."
    elif requested == "Council" and depth == "Balanced" and asm_simple and max_expand == 0 and expanded_xrefs == 0:
        effective = "Duo"
        reason = "speed guard: simple ASM without expanded XREF context uses Evidence Pack only; enable XREF expansion or Deep for context scouts."
    elif requested == "Council" and max_expand == 0 and expanded_xrefs == 0 and depth != "Deep":
        effective = "Duo"
        reason = "speed guard: Council requested but XREF expansion is disabled; using Evidence Pack only."
    return {
        "requested": requested,
        "effective": effective,
        "reason": reason,
        "depth": depth,
        "expanded_xrefs": expanded_xrefs,
        "max_xref_expansion_items": max_expand,
        "asm_simple": asm_simple,
        "data_focus": data_focus,
    }


def subagent_budget(cfg: Any, context: Dict[str, Any], phase: str) -> Dict[str, int]:
    depth = analysis_depth(getattr(cfg, "analysis_depth", "Fast"))
    base = max(10, int(getattr(cfg, "analysis_timeout_seconds", 45)))
    if depth == "Deep":
        timeouts = {"xref": min(max(18, base // 2), 35), "critic": min(max(20, base // 2), 40), "synth": min(max(24, base), 60)}
        tokens = {"xref": 1200, "critic": 1400, "synth": 1800}
    else:
        timeouts = {"xref": min(max(8, base // 4), 14), "critic": min(max(10, base // 3), 18), "synth": min(max(12, base // 2), 24)}
        tokens = {"xref": 700, "critic": 900, "synth": 1100}
    key = str(phase or "").lower()
    return {
        "timeout": int(timeouts.get(key, min(max(10, base // 3), 20))),
        "max_tokens": int(tokens.get(key, 900)),
    }


def watchdog_seconds(cfg: Any, context: Dict[str, Any] = None) -> int:
    base = max(10, int(getattr(cfg, "analysis_timeout_seconds", 75)))
    policy = agent_policy(cfg, context or {})
    mode = policy.get("effective") or policy.get("requested") or "Single"
    if mode == "Council":
        return max(30, base + 18)
    if mode == "Duo":
        return max(25, base + 15)
    return max(15, base + 5)


def model_policy(cfg: Any, context: Dict[str, Any]) -> Dict[str, Any]:
    """Route simple local analyses to a faster model when the user selected a heavy one."""
    provider = str(getattr(cfg, "provider", "local") or "local").lower()
    requested = str(getattr(cfg, "model", "") or "")
    effective = requested
    reason = ""
    if provider != "local":
        return {"requested": requested, "effective": effective, "reason": reason}
    policy = agent_policy(cfg, context)
    depth = analysis_depth(getattr(cfg, "analysis_depth", "Fast"))
    heavy = requested.lower().startswith("qwen3-coder:30b") or requested.lower().startswith("qwen3-coder")
    if heavy and depth in ("Fast", "Balanced") and policy.get("asm_simple"):
        effective = "qwen2.5-coder:7b"
        reason = (
            "speed guard: simple ASM analysis is routed from %s to %s. "
            "Use Deep mode to force the heavy model."
            % (requested, effective)
        )
    return {"requested": requested, "effective": effective, "reason": reason}
