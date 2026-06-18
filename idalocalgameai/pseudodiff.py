"""Local pseudocode diff helpers for game update comparisons."""

from __future__ import annotations

import difflib
import re
from typing import Any, Dict, List

from .sanitize import sanitize_prompt_text, sanitize_text


CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*|sub_[0-9A-Fa-f]+)\s*\(")
NUMBER_RE = re.compile(r"\b0x[0-9A-Fa-f]+\b|\b\d+(?:\.\d+)?f?\b")
OFFSET_RE = re.compile(r"\+\s*(0x[0-9A-Fa-f]+|\d+)")


def _clean_line(line: Any) -> str:
    return sanitize_text(line, max_chars=900, collapse_ws=True)


def _lines(text: str) -> List[str]:
    text = sanitize_text(text, max_chars=240_000)
    return [_clean_line(line) for line in text.splitlines() if _clean_line(line)]


def _tokens(lines: List[str], regex: re.Pattern) -> List[str]:
    out = []
    seen = set()
    for line in lines:
        for match in regex.finditer(line):
            value = match.group(1) if match.groups() else match.group(0)
            if value not in seen:
                seen.add(value)
                out.append(value)
    return out


def _changed_lines(old_lines: List[str], new_lines: List[str], limit: int = 80) -> Dict[str, Any]:
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    added = []
    removed = []
    changed = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag in ("delete", "replace"):
            for line in old_lines[i1:i2]:
                if len(removed) < limit:
                    removed.append(line)
        if tag in ("insert", "replace"):
            for line in new_lines[j1:j2]:
                if len(added) < limit:
                    added.append(line)
        if tag == "replace" and len(changed) < limit:
            changed.append({
                "old": old_lines[i1:i2][:6],
                "new": new_lines[j1:j2][:6],
            })
    return {"added": added, "removed": removed, "changed_blocks": changed}


def _impact_from_change(text: str) -> str:
    low = text.lower()
    if any(token in low for token in ("damage", "health", "shield", "armor", "hit")):
        return "damage/stat behavior may have changed"
    if any(token in low for token in ("ammo", "inventory", "stack", "resource", "currency")):
        return "inventory/resource behavior may have changed"
    if any(token in low for token in ("cooldown", "timer", "stamina", "energy")):
        return "cooldown/resource timing may have changed"
    if any(token in low for token in ("input", "button", "key", "controller")):
        return "input handling may have changed"
    if any(token in low for token in ("serialize", "deserialize", "bitstream", "packet", "reader")):
        return "parser/field layout may have changed"
    if any(token in low for token in ("xor", "rol", "ror", "checksum", "hash", "validate")):
        return "validation/checksum logic may have changed"
    if any(token in low for token in ("fmaxf", "fminf", "max", "min", "*", "+", "-")):
        return "numeric transform or clamp may have changed"
    return "mechanical behavior changed"


def local_pseudocode_diff(old_text: str, new_text: str) -> Dict[str, Any]:
    old_lines = _lines(old_text)
    new_lines = _lines(new_text)
    changes = _changed_lines(old_lines, new_lines)
    old_calls = _tokens(old_lines, CALL_RE)
    new_calls = _tokens(new_lines, CALL_RE)
    old_numbers = _tokens(old_lines, NUMBER_RE)
    new_numbers = _tokens(new_lines, NUMBER_RE)
    old_offsets = _tokens(old_lines, OFFSET_RE)
    new_offsets = _tokens(new_lines, OFFSET_RE)
    added_calls = [item for item in new_calls if item not in old_calls]
    removed_calls = [item for item in old_calls if item not in new_calls]
    added_numbers = [item for item in new_numbers if item not in old_numbers]
    removed_numbers = [item for item in old_numbers if item not in new_numbers]
    added_offsets = [item for item in new_offsets if item not in old_offsets]
    removed_offsets = [item for item in old_offsets if item not in new_offsets]
    change_text = " ".join(changes["added"][:12] + changes["removed"][:12] + added_calls + removed_calls)
    impact = _impact_from_change(change_text)
    similarity = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False).ratio() if old_lines or new_lines else 1.0
    risk = "low"
    if added_offsets or removed_offsets or added_calls or removed_calls:
        risk = "medium"
    if any(token in change_text.lower() for token in ("validate", "checksum", "packet", "serialize", "deserialize")):
        risk = "high"
    experiments = [
        "Re-run the Trainer Radar on the new function and compare strategy/log-first fields.",
        "If offsets changed, validate structure hypotheses before reusing old hooks.",
        "If calls changed, inspect added/removed callees before porting the hook.",
    ]
    if risk == "high":
        experiments.insert(0, "Use observe-only logging first; do not reuse old mutation offsets blindly.")
    return {
        "mode": "local_pseudocode_diff",
        "similarity": round(float(similarity), 3),
        "summary": "%d added lines, %d removed lines, %d changed blocks. %s." % (
            len(changes["added"]),
            len(changes["removed"]),
            len(changes["changed_blocks"]),
            impact,
        ),
        "impact": impact,
        "porting_risk": risk,
        "added_lines": changes["added"][:40],
        "removed_lines": changes["removed"][:40],
        "changed_blocks": changes["changed_blocks"][:12],
        "calls": {
            "added": added_calls[:20],
            "removed": removed_calls[:20],
            "unchanged_count": len([item for item in new_calls if item in old_calls]),
        },
        "constants": {
            "added": added_numbers[:24],
            "removed": removed_numbers[:24],
        },
        "offsets": {
            "added": added_offsets[:24],
            "removed": removed_offsets[:24],
        },
        "trainer_notes": [
            impact,
            "Port old hooks only after confirming call signature, offsets, and mutation surface still match.",
            "Changed constants may indicate balance, clamp, multiplier, timer, or validation updates.",
        ],
        "recommended_experiments": experiments,
    }


def _bullet_lines(items: Any, limit: int = 10) -> List[str]:
    if not isinstance(items, list):
        items = [] if not items else [items]
    out: List[str] = []
    for item in items[:limit]:
        text = str(item or "").strip()
        text = sanitize_prompt_text(text, 700)
        if text:
            out.append("- %s" % text)
    return out


def render_local_pseudocode_diff_text(result: Dict[str, Any]) -> str:
    """Plain-text report used when the LLM is unavailable or not needed."""
    result = result if isinstance(result, dict) else {}
    calls = result.get("calls") if isinstance(result.get("calls"), dict) else {}
    constants = result.get("constants") if isinstance(result.get("constants"), dict) else {}
    offsets = result.get("offsets") if isinstance(result.get("offsets"), dict) else {}

    lines = [
        "Pseudocode Diff",
        "",
        "Similarity: %s" % result.get("similarity", "-"),
        "Porting risk: %s" % result.get("porting_risk", "-"),
        "Summary: %s" % result.get("summary", "-"),
        "Impact: %s" % result.get("impact", "-"),
        "",
        "Calls added:",
    ]
    lines.extend(_bullet_lines(calls.get("added"), 12) or ["- none"])
    lines.append("")
    lines.append("Calls removed:")
    lines.extend(_bullet_lines(calls.get("removed"), 12) or ["- none"])
    lines.append("")
    lines.append("Offsets added:")
    lines.extend(_bullet_lines(offsets.get("added"), 12) or ["- none"])
    lines.append("")
    lines.append("Offsets removed:")
    lines.extend(_bullet_lines(offsets.get("removed"), 12) or ["- none"])
    lines.append("")
    lines.append("Constants added:")
    lines.extend(_bullet_lines(constants.get("added"), 16) or ["- none"])
    lines.append("")
    lines.append("Constants removed:")
    lines.extend(_bullet_lines(constants.get("removed"), 16) or ["- none"])
    lines.append("")
    lines.append("Trainer/modding notes:")
    lines.extend(_bullet_lines(result.get("trainer_notes"), 8) or ["- none"])
    lines.append("")
    lines.append("Recommended experiments:")
    lines.extend(_bullet_lines(result.get("recommended_experiments"), 8) or ["- none"])
    lines.append("")
    lines.append("Changed blocks:")
    blocks = result.get("changed_blocks") if isinstance(result.get("changed_blocks"), list) else []
    if not blocks:
        lines.append("- none")
    for idx, block in enumerate(blocks[:8], 1):
        if not isinstance(block, dict):
            continue
        lines.append("Block %d old:" % idx)
        lines.extend("  - %s" % line for line in block.get("old", [])[:5])
        lines.append("Block %d new:" % idx)
        lines.extend("  + %s" % line for line in block.get("new", [])[:5])
    return "\n".join(lines).strip()
