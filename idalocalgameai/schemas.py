"""Small schema helpers without third-party dependencies."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional


EXPECTED_KEYS = {
    "mode",
    "summary",
    "behavior",
    "game_relevance",
    "engine_hints",
    "suggested_function_name",
    "confidence",
    "evidence",
    "risks",
    "comments",
    "variables",
    "structures",
    "dataflow",
    "structure_offsets",
    "algorithm",
    "trainer_assessment",
    "trainer_radar",
    "trainer_candidates",
    "driver_ioctl_assessment",
    "driver_ioctl_radar",
    "driver_ioctl_candidates",
    "ioctl_experiments",
    "hook_experiments",
    "xref_graph",
    "structure_hypotheses",
    "semantic_cues_used",
    "bitstream_deserialization",
    "user_context_alignment",
    "local_enrichment",
    "external_evidence_summary",
    "evidence_pack",
    "claim_board",
    "multi_agent",
    "next_questions",
}


def parse_json_object(text: str) -> Dict[str, Any]:
    """Parse strict JSON, with a conservative fallback for fenced output."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise
        obj = json.loads(text[start : end + 1])
    if not isinstance(obj, dict):
        raise ValueError("LLM response must be a JSON object")
    return obj


def extract_json_object(text: str) -> Dict[str, Any]:
    """Parse and normalize an analysis JSON object."""
    return normalize_analysis(parse_json_object(text))


def normalize_analysis(obj: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(obj)
    out.setdefault("mode", "unknown")
    out.setdefault("summary", "")
    out.setdefault("behavior", [])
    out.setdefault("game_relevance", [])
    out.setdefault("engine_hints", [])
    out.setdefault("suggested_function_name", None)
    out.setdefault("confidence", 0.0)
    out.setdefault("evidence", [])
    out.setdefault("risks", [])
    out.setdefault("comments", [])
    out.setdefault("variables", [])
    out.setdefault("structures", [])
    out.setdefault("dataflow", [])
    out.setdefault("structure_offsets", [])
    out.setdefault("algorithm", {"kind": "unknown", "description": ""})
    out.setdefault("trainer_assessment", {
        "usefulness": "unknown",
        "category": "unknown",
        "usefulness_reason": "",
        "what_happens_if_hooked": [],
        "best_hook_strategy": "observe_only",
        "modification_surface": "none",
        "values_to_log_first": [],
        "candidate_trainer_features": [],
        "recommended_experiments": [],
        "not_useful_for": [],
        "stability_notes": [],
    })
    out.setdefault("trainer_radar", {})
    out.setdefault("trainer_candidates", [])
    out.setdefault("driver_ioctl_assessment", {
        "risk": "unknown",
        "category": "unknown",
        "risk_reason": "",
        "ioctl_surface": "unknown",
        "transfer_method": "unknown",
        "buffer_sources": [],
        "validation_gaps": [],
        "rw_primitive_indicators": [],
        "values_to_verify": [],
        "safe_test_plan": [],
        "not_enough_evidence": [],
        "stability_notes": [],
    })
    out.setdefault("driver_ioctl_radar", {})
    out.setdefault("driver_ioctl_candidates", [])
    out.setdefault("ioctl_experiments", [])
    out.setdefault("hook_experiments", [])
    out.setdefault("xref_graph", {})
    out.setdefault("structure_hypotheses", [])
    out.setdefault("semantic_cues_used", [])
    out.setdefault("bitstream_deserialization", {
        "likelihood": "none",
        "reader_calls": [],
        "output_layout": [],
        "dirty_masks": [],
        "sanity_checks": [],
        "bitwise_checks": [],
        "string_anchors": [],
    })
    out.setdefault("user_context_alignment", {"used": False, "verdict": "weak", "supports_user_hint": [], "contradicts_user_hint": [], "notes": ""})
    out.setdefault("local_enrichment", {"applied": False, "notes": [], "policy": ""})
    out.setdefault("external_evidence_summary", {})
    out.setdefault("evidence_pack", {})
    out.setdefault("claim_board", {})
    out.setdefault("multi_agent", {"mode": "Single", "agents": [], "policy": ""})
    out.setdefault("next_questions", [])
    if not isinstance(out.get("dataflow"), list):
        out["dataflow"] = [str(out.get("dataflow") or "")]
    if not isinstance(out.get("structure_offsets"), list):
        out["structure_offsets"] = []
    if not isinstance(out.get("algorithm"), dict):
        out["algorithm"] = {"kind": "unknown", "description": str(out.get("algorithm") or "")}
    else:
        out["algorithm"].setdefault("kind", "unknown")
        out["algorithm"].setdefault("description", "")
    if not isinstance(out.get("trainer_assessment"), dict):
        out["trainer_assessment"] = {
            "usefulness": "unknown",
            "category": "unknown",
            "usefulness_reason": str(out.get("trainer_assessment") or ""),
            "what_happens_if_hooked": [],
            "best_hook_strategy": "observe_only",
            "modification_surface": "none",
            "values_to_log_first": [],
            "candidate_trainer_features": [],
            "recommended_experiments": [],
            "not_useful_for": [],
            "stability_notes": [],
        }
    else:
        for key, default in (
            ("usefulness", "unknown"),
            ("category", "unknown"),
            ("usefulness_reason", ""),
            ("what_happens_if_hooked", []),
            ("best_hook_strategy", "observe_only"),
            ("modification_surface", "none"),
            ("values_to_log_first", []),
            ("candidate_trainer_features", []),
            ("recommended_experiments", []),
            ("not_useful_for", []),
            ("stability_notes", []),
        ):
            out["trainer_assessment"].setdefault(key, default)
    if not isinstance(out.get("trainer_radar"), dict):
        out["trainer_radar"] = {}
    if not isinstance(out.get("trainer_candidates"), list):
        out["trainer_candidates"] = []
    if not isinstance(out.get("driver_ioctl_assessment"), dict):
        out["driver_ioctl_assessment"] = {
            "risk": "unknown",
            "category": "unknown",
            "risk_reason": str(out.get("driver_ioctl_assessment") or ""),
            "ioctl_surface": "unknown",
            "transfer_method": "unknown",
            "buffer_sources": [],
            "validation_gaps": [],
            "rw_primitive_indicators": [],
            "values_to_verify": [],
            "safe_test_plan": [],
            "not_enough_evidence": [],
            "stability_notes": [],
        }
    else:
        for key, default in (
            ("risk", "unknown"),
            ("category", "unknown"),
            ("risk_reason", ""),
            ("ioctl_surface", "unknown"),
            ("transfer_method", "unknown"),
            ("buffer_sources", []),
            ("validation_gaps", []),
            ("rw_primitive_indicators", []),
            ("values_to_verify", []),
            ("safe_test_plan", []),
            ("not_enough_evidence", []),
            ("stability_notes", []),
        ):
            out["driver_ioctl_assessment"].setdefault(key, default)
    if not isinstance(out.get("driver_ioctl_radar"), dict):
        out["driver_ioctl_radar"] = {}
    if not isinstance(out.get("driver_ioctl_candidates"), list):
        out["driver_ioctl_candidates"] = []
    if not isinstance(out.get("ioctl_experiments"), list):
        out["ioctl_experiments"] = []
    if not isinstance(out.get("hook_experiments"), list):
        out["hook_experiments"] = []
    if not isinstance(out.get("xref_graph"), dict):
        out["xref_graph"] = {}
    if not isinstance(out.get("structure_hypotheses"), list):
        out["structure_hypotheses"] = []
    if not isinstance(out.get("semantic_cues_used"), list):
        out["semantic_cues_used"] = [str(out.get("semantic_cues_used") or "")]
    if not isinstance(out.get("bitstream_deserialization"), dict):
        out["bitstream_deserialization"] = {
            "likelihood": "none",
            "reader_calls": [],
            "output_layout": [],
            "dirty_masks": [],
            "sanity_checks": [],
            "bitwise_checks": [],
            "string_anchors": [],
        }
    else:
        for key, default in (
            ("likelihood", "none"),
            ("reader_calls", []),
            ("output_layout", []),
            ("dirty_masks", []),
            ("sanity_checks", []),
            ("bitwise_checks", []),
            ("string_anchors", []),
        ):
            out["bitstream_deserialization"].setdefault(key, default)
    if not isinstance(out.get("user_context_alignment"), dict):
        out["user_context_alignment"] = {"used": False, "verdict": "weak", "supports_user_hint": [], "contradicts_user_hint": [], "notes": str(out.get("user_context_alignment") or "")}
    else:
        out["user_context_alignment"].setdefault("used", False)
        out["user_context_alignment"].setdefault("verdict", "weak")
        out["user_context_alignment"].setdefault("supports_user_hint", [])
        out["user_context_alignment"].setdefault("contradicts_user_hint", [])
        out["user_context_alignment"].setdefault("notes", "")
    if not isinstance(out.get("local_enrichment"), dict):
        out["local_enrichment"] = {"applied": False, "notes": [], "policy": str(out.get("local_enrichment") or "")}
    else:
        out["local_enrichment"].setdefault("applied", False)
        out["local_enrichment"].setdefault("notes", [])
        out["local_enrichment"].setdefault("policy", "")
    if not isinstance(out.get("external_evidence_summary"), dict):
        out["external_evidence_summary"] = {}
    if not isinstance(out.get("evidence_pack"), dict):
        out["evidence_pack"] = {}
    if not isinstance(out.get("claim_board"), dict):
        out["claim_board"] = {}
    if not isinstance(out.get("multi_agent"), dict):
        out["multi_agent"] = {"mode": str(out.get("multi_agent") or "Single"), "agents": [], "policy": ""}
    else:
        out["multi_agent"].setdefault("mode", "Single")
        out["multi_agent"].setdefault("agents", [])
        out["multi_agent"].setdefault("policy", "")
    try:
        out["confidence"] = max(0.0, min(1.0, float(out["confidence"])))
    except Exception:
        out["confidence"] = 0.0
    return out


def validate_function_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    name = str(name).strip()
    if len(name) > 96:
        return None
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        return None
    generic = {
        "function",
        "sub_function",
        "process_data",
        "handle_data",
        "do_work",
        "unknown_function",
        "game_function",
    }
    if name.lower() in generic:
        return None
    return name


def compact_lines(items: Any, limit: int = 8) -> List[str]:
    if not isinstance(items, list):
        return []
    lines = []
    for item in items[:limit]:
        if isinstance(item, dict):
            bits = []
            for key in ("address", "kind", "text", "reason", "value", "target"):
                if key in item and item[key] is not None:
                    bits.append("%s=%s" % (key, item[key]))
            lines.append(", ".join(bits) if bits else json.dumps(item, sort_keys=True))
        else:
            lines.append(str(item))
    return lines
