"""Profile guardrails for Monstey analysis modes."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List


TRAINER_PROFILE = "Trainer / Modding"
DRIVER_PROFILE = "Driver IOCTL"

DRIVER_TARGET_RE = re.compile(
    r"(^|[\\/._ -])(?:driver|kmdf|wdf|wdm|kernel|ntoskrnl|win32k|flt|filter)([\\/._ -]|$)|\.sys$",
    re.IGNORECASE,
)


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value in (None, "", "-"):
        return []
    return [value]


def _clean(value: Any) -> str:
    return str(value or "").strip()


def driver_cue_count(context: Dict[str, Any]) -> int:
    cues = _as_dict(context.get("semantic_cues"))
    keys = (
        "driver_api_calls",
        "ioctl_code_checks",
        "ioctl_buffer_access",
        "ioctl_validation_checks",
        "ioctl_rw_primitives",
        "ioctl_method_hints",
        "driver_strings",
    )
    return sum(len(_as_list(cues.get(key))) for key in keys)


def driver_likelihood(context: Dict[str, Any]) -> str:
    cues = _as_dict(context.get("semantic_cues"))
    return _clean(cues.get("driver_ioctl_likelihood") or "none").lower()


def is_driver_target_context(context: Dict[str, Any]) -> bool:
    database = _as_dict(context.get("database"))
    game_context = _as_dict(context.get("game_context"))
    dump_context = _as_dict(context.get("dump_context"))
    values = [
        database.get("root_filename"),
        database.get("input_file"),
        game_context.get("process_name"),
        game_context.get("process_display"),
        game_context.get("process_full_name"),
        game_context.get("selected_candidate"),
        dump_context.get("process_name"),
    ]
    for value in values:
        text = _clean(value)
        if not text:
            continue
        base = os.path.basename(text).lower()
        if base.endswith(".sys") or DRIVER_TARGET_RE.search(text):
            return True
    return False


def has_driver_evidence(context: Dict[str, Any]) -> bool:
    likelihood = driver_likelihood(context)
    if likelihood in ("medium", "high"):
        return True
    return driver_cue_count(context) > 0


def effective_analysis_profile(context: Dict[str, Any], requested: Any = None) -> str:
    requested_text = _clean(requested or context.get("requested_analysis_profile") or context.get("analysis_profile") or TRAINER_PROFILE)
    if requested_text != DRIVER_PROFILE:
        return requested_text if requested_text else TRAINER_PROFILE
    if is_driver_target_context(context) or has_driver_evidence(context):
        return DRIVER_PROFILE
    return TRAINER_PROFILE


def apply_effective_analysis_profile(context: Dict[str, Any], requested: Any = None) -> Dict[str, Any]:
    requested_text = _clean(requested or context.get("requested_analysis_profile") or context.get("analysis_profile") or TRAINER_PROFILE)
    effective = effective_analysis_profile(context, requested_text)
    context["requested_analysis_profile"] = requested_text
    context["analysis_profile"] = effective
    context["profile_guard"] = {
        "requested": requested_text,
        "effective": effective,
        "downgraded": requested_text == DRIVER_PROFILE and effective != DRIVER_PROFILE,
        "driver_target": is_driver_target_context(context),
        "driver_cue_count": driver_cue_count(context),
        "driver_likelihood": driver_likelihood(context),
        "reason": (
            "Driver IOCTL profile ignored because this focus has no driver/IOCTL evidence and the loaded target does not look like a driver."
            if requested_text == DRIVER_PROFILE and effective != DRIVER_PROFILE
            else "Selected profile accepted for this focus."
        ),
    }
    return context


def is_effective_driver_profile(context: Dict[str, Any]) -> bool:
    return effective_analysis_profile(context, context.get("analysis_profile")) == DRIVER_PROFILE
