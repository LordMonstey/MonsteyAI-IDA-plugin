"""Approximate ASM-to-pseudocode reconstruction for non-decompilable regions."""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .sanitize import sanitize_text


_HEX_SUFFIX_RE = re.compile(r"\b([0-9A-Fa-f]+)h\b")
_HEX_RE = re.compile(r"\b0x[0-9A-Fa-f]+\b")
_LOC_RE = re.compile(r"\bloc_([0-9A-Fa-f]+)\b", re.IGNORECASE)

_JCC = {
    "jz",
    "je",
    "jnz",
    "jne",
    "ja",
    "jnbe",
    "jae",
    "jnb",
    "jb",
    "jnae",
    "jbe",
    "jna",
    "jg",
    "jnle",
    "jge",
    "jnl",
    "jl",
    "jnge",
    "jle",
    "jng",
    "js",
    "jns",
    "jo",
    "jno",
    "jp",
    "jpe",
    "jnp",
    "jpo",
}

_SIZE_HINTS = [
    ("xmmword", "128"),
    ("oword", "128"),
    ("qword", "64"),
    ("dword", "32"),
    ("word", "16"),
    ("byte", "8"),
]

_REGISTER_NAMES = {
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
    "r8d",
    "r9d",
    "r10d",
    "r11d",
    "r12d",
    "r13d",
    "r14d",
    "r15d",
    "ax",
    "bx",
    "cx",
    "dx",
    "si",
    "di",
    "bp",
    "sp",
    "al",
    "bl",
    "cl",
    "dl",
}


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _safe_line(value: Any, limit: int = 320) -> str:
    return sanitize_text(str(value or ""), max_chars=limit, collapse_ws=True)


def _hex_suffix_to_c(match: re.Match[str]) -> str:
    raw = match.group(1)
    if len(raw) == 1 and raw.isdigit():
        return raw
    return "0x%s" % raw.upper()


def _normalize_hex(text: str) -> str:
    text = _HEX_SUFFIX_RE.sub(_hex_suffix_to_c, text)
    return text.replace("offset ", "&")


def _split_operands(text: str) -> List[str]:
    out: List[str] = []
    current: List[str] = []
    depth = 0
    for ch in text:
        if ch in "[(":
            depth += 1
        elif ch in "])" and depth > 0:
            depth -= 1
        if ch == "," and depth == 0:
            value = "".join(current).strip()
            if value:
                out.append(value)
            current = []
            continue
        current.append(ch)
    value = "".join(current).strip()
    if value:
        out.append(value)
    return out


def _operands(mnemonic: str, disasm: str) -> List[str]:
    text = disasm.split(";", 1)[0].strip()
    if not text:
        return []
    prefix = str(mnemonic or "").strip()
    if prefix and text.lower().startswith(prefix.lower()):
        text = text[len(prefix) :].strip()
    else:
        parts = text.split(None, 1)
        text = parts[1] if len(parts) > 1 else ""
    return _split_operands(text)


def _operand_size_hint(op: str) -> str:
    low = str(op or "").strip().lower()
    if re.fullmatch(r"xmm\d+", low):
        return "128"
    if re.fullmatch(r"ymm\d+", low):
        return "256"
    if re.fullmatch(r"zmm\d+", low):
        return "512"
    if low in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp") or re.fullmatch(r"r\d+", low):
        return "64"
    if low in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp") or re.fullmatch(r"r\d+d", low):
        return "32"
    if low in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp") or re.fullmatch(r"r\d+w", low):
        return "16"
    if low in ("al", "bl", "cl", "dl") or re.fullmatch(r"r\d+b", low):
        return "8"
    return ""


def _memory_size(op: str, mnemonic: str = "", fallback: str = "") -> str:
    low = op.lower()
    for needle, size in _SIZE_HINTS:
        if needle in low:
            return size
    if str(mnemonic).lower().endswith("ss"):
        return "32f"
    if str(mnemonic).lower().endswith("sd"):
        return "64f"
    if fallback:
        return fallback
    return "?"


def _clean_expr(expr: str) -> str:
    expr = _normalize_hex(expr)
    expr = re.sub(r"\b(?:cs|ds|ss|es|fs|gs):", "", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\s+", " ", expr).strip()
    expr = expr.replace(" + ", " + ").replace("+", " + ")
    expr = expr.replace(" - ", " - ").replace("-", " - ")
    expr = expr.replace("*", " * ")
    expr = re.sub(r"\s+", " ", expr).strip()
    return expr


def _operand_to_c(op: str, mnemonic: str = "", fallback_size: str = "") -> str:
    original = str(op or "").strip()
    op = _normalize_hex(original)
    op = re.sub(r"\b(?:short|near ptr|far ptr|ptr)\b", "", op, flags=re.IGNORECASE)
    op = re.sub(r"\b(?:xmmword|oword|qword|dword|word|byte)\b", "", op, flags=re.IGNORECASE)
    op = re.sub(r"\b(?:cs|ds|ss|es|fs|gs):", "", op, flags=re.IGNORECASE).strip()
    if "[" in op and "]" in op:
        inside = op[op.find("[") + 1 : op.rfind("]")]
        return "MEM%s[%s]" % (_memory_size(original, mnemonic, fallback_size), _clean_expr(inside))
    op = op.strip()
    if op.lower() in _REGISTER_NAMES:
        return op.lower()
    return _clean_expr(op)


def _fmt_address(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.lower().startswith("0x"):
        return "0x%s" % text[2:].upper()
    try:
        return "0x%X" % int(text, 16)
    except Exception:
        return text


def _address_int(value: Any) -> Optional[int]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.lower().startswith("0x"):
        text = text[2:]
    try:
        return int(text, 16)
    except Exception:
        return None


def _target_int(op: str) -> Optional[int]:
    loc = _LOC_RE.search(op or "")
    if loc:
        try:
            return int(loc.group(1), 16)
        except Exception:
            return None
    hit = _HEX_RE.search(_normalize_hex(op or ""))
    if hit:
        try:
            return int(hit.group(0), 16)
        except Exception:
            return None
    suffix = _HEX_SUFFIX_RE.search(op or "")
    if suffix:
        try:
            return int(suffix.group(1), 16)
        except Exception:
            return None
    return None


def _target_label(op: str, known_targets: Iterable[int]) -> str:
    target = _target_int(op)
    if target is not None and target in set(known_targets):
        return "loc_%X" % target
    clean = _operand_to_c(op)
    clean = re.sub(r"[^A-Za-z0-9_:$@.?]+", "_", clean).strip("_")
    return clean or "unknown_target"


def _condition_from_last(mnemonic: str, last_compare: Optional[Tuple[str, str, str]]) -> str:
    cc = str(mnemonic or "").lower()
    if not last_compare:
        return "%s_condition" % cc
    kind, left, right = last_compare
    if kind == "test":
        zero = "((%s & %s) == 0)" % (left, right)
        nonzero = "((%s & %s) != 0)" % (left, right)
        if cc in ("jz", "je"):
            return zero
        if cc in ("jnz", "jne"):
            return nonzero
    mapping = {
        "jz": "%s == %s",
        "je": "%s == %s",
        "jnz": "%s != %s",
        "jne": "%s != %s",
        "ja": "%s > %s /* unsigned */",
        "jnbe": "%s > %s /* unsigned */",
        "jae": "%s >= %s /* unsigned */",
        "jnb": "%s >= %s /* unsigned */",
        "jb": "%s < %s /* unsigned */",
        "jnae": "%s < %s /* unsigned */",
        "jbe": "%s <= %s /* unsigned */",
        "jna": "%s <= %s /* unsigned */",
        "jg": "%s > %s",
        "jnle": "%s > %s",
        "jge": "%s >= %s",
        "jnl": "%s >= %s",
        "jl": "%s < %s",
        "jnge": "%s < %s",
        "jle": "%s <= %s",
        "jng": "%s <= %s",
    }
    if cc in mapping:
        return mapping[cc] % (left, right)
    flag_map = {
        "js": "sign_flag",
        "jns": "!sign_flag",
        "jo": "overflow_flag",
        "jno": "!overflow_flag",
        "jp": "parity_flag",
        "jpe": "parity_flag",
        "jnp": "!parity_flag",
        "jpo": "!parity_flag",
    }
    return flag_map.get(cc, "%s_condition" % cc)


def _is_data_directive(mnemonic: str, disasm: str) -> bool:
    low_mnem = str(mnemonic or "").lower()
    low_disasm = str(disasm or "").lstrip().lower()
    return low_mnem in ("db", "dw", "dd", "dq", "dt", "do", "align") or low_disasm.startswith(
        ("db ", "dw ", "dd ", "dq ", "align ")
    )


def _translate_instruction(
    row: Dict[str, Any],
    known_targets: Iterable[int],
    last_compare: Optional[Tuple[str, str, str]],
) -> Tuple[List[str], Optional[Tuple[str, str, str]], bool]:
    mnemonic = str(row.get("mnemonic") or "").lower().strip()
    disasm = _safe_line(row.get("disasm"), 420)
    ops = _operands(mnemonic, disasm)
    fallback_sizes = [""] * len(ops)
    if len(ops) >= 2 and mnemonic in (
        "mov",
        "movaps",
        "movups",
        "movdqa",
        "movdqu",
        "movss",
        "movsd",
        "movzx",
        "movsx",
        "movsxd",
        "add",
        "sub",
        "xor",
        "or",
        "and",
    ):
        fallback_sizes[1] = _operand_size_hint(ops[0])
    c_ops = [_operand_to_c(op, mnemonic, fallback_sizes[idx] if idx < len(fallback_sizes) else "") for idx, op in enumerate(ops)]
    lines: List[str] = []
    recognized = True

    if not mnemonic:
        return ["/* undecoded instruction */"], last_compare, False
    if _is_data_directive(mnemonic, disasm):
        return ["/* data directive, not executable code: %s */" % disasm], last_compare, False
    if mnemonic in ("nop", "int3"):
        return ["/* %s */" % mnemonic], last_compare, True
    if mnemonic in ("ret", "retn", "retf"):
        return ["return rax;"], last_compare, True
    if mnemonic == "jmp" and ops:
        return ["goto %s;" % _target_label(ops[-1], known_targets)], last_compare, True
    if mnemonic in _JCC and ops:
        condition = _condition_from_last(mnemonic, last_compare)
        return ["if (%s) goto %s;" % (condition, _target_label(ops[-1], known_targets))], last_compare, True
    if mnemonic == "cmp" and len(c_ops) >= 2:
        return ["/* compare %s with %s */" % (c_ops[0], c_ops[1])], ("cmp", c_ops[0], c_ops[1]), True
    if mnemonic == "test" and len(c_ops) >= 2:
        return ["/* test %s & %s */" % (c_ops[0], c_ops[1])], ("test", c_ops[0], c_ops[1]), True
    if mnemonic.startswith("set") and len(c_ops) >= 1:
        cc = "j" + mnemonic[3:]
        condition = _condition_from_last(cc, last_compare)
        return ["%s = (%s) ? 1 : 0;" % (c_ops[0], condition)], last_compare, True
    if mnemonic.startswith("cmov") and len(c_ops) >= 2:
        cc = "j" + mnemonic[4:]
        condition = _condition_from_last(cc, last_compare)
        return ["if (%s) %s = %s;" % (condition, c_ops[0], c_ops[1])], last_compare, True
    if mnemonic in ("call", "callq") and ops:
        return ["rax = %s(/* args from current register state */);" % _operand_to_c(ops[-1], mnemonic)], last_compare, True
    if mnemonic in ("push", "pop") and c_ops:
        if mnemonic == "push":
            return ["push(%s);" % c_ops[0]], last_compare, True
        return ["%s = pop();" % c_ops[0]], last_compare, True
    if mnemonic in ("mov", "movaps", "movups", "movdqa", "movdqu", "movss", "movsd") and len(c_ops) >= 2:
        return ["%s = %s;" % (c_ops[0], c_ops[1])], last_compare, True
    if mnemonic in ("movzx", "movsx", "movsxd") and len(c_ops) >= 2:
        return ["%s = extend(%s);" % (c_ops[0], c_ops[1])], last_compare, True
    if mnemonic == "lea" and len(c_ops) >= 2:
        return ["%s = address_of(%s);" % (c_ops[0], c_ops[1])], last_compare, True
    if mnemonic in ("xor", "pxor") and len(c_ops) >= 2 and c_ops[0] == c_ops[1]:
        return ["%s = 0;" % c_ops[0]], last_compare, True
    binary_ops = {
        "add": "+=",
        "addss": "+=",
        "addsd": "+=",
        "sub": "-=",
        "subss": "-=",
        "subsd": "-=",
        "imul": "*=",
        "mul": "*=",
        "mulss": "*=",
        "mulsd": "*=",
        "xor": "^=",
        "or": "|=",
        "and": "&=",
        "shl": "<<=",
        "sal": "<<=",
        "shr": ">>=",
        "sar": ">>=",
        "minss": "= min",
        "maxss": "= max",
    }
    if mnemonic in binary_ops and len(c_ops) >= 2:
        op = binary_ops[mnemonic]
        if op == "= min":
            return ["%s = min(%s, %s);" % (c_ops[0], c_ops[0], c_ops[1])], last_compare, True
        if op == "= max":
            return ["%s = max(%s, %s);" % (c_ops[0], c_ops[0], c_ops[1])], last_compare, True
        return ["%s %s %s;" % (c_ops[0], op, c_ops[1])], last_compare, True
    if mnemonic in ("inc", "dec") and c_ops:
        return ["%s %s;" % (c_ops[0], "++" if mnemonic == "inc" else "--")], last_compare, True
    if mnemonic in ("neg", "not") and c_ops:
        return ["%s = %s%s;" % (c_ops[0], "-" if mnemonic == "neg" else "~", c_ops[0])], last_compare, True
    if mnemonic.startswith("rep") or mnemonic in ("movsb", "movsw", "movsd", "movsq", "stosb", "stosd", "stosq"):
        return ["%s(/* string/memory operation, inspect rcx/rsi/rdi */);" % mnemonic], last_compare, True

    recognized = False
    if disasm:
        lines.append("/* TODO translate: %s */" % disasm)
    else:
        lines.append("/* TODO translate: %s */" % mnemonic)
    return lines, last_compare, recognized


def render_asm_source(context: Dict[str, Any]) -> str:
    lines = []
    for row in _as_list(context.get("assembly")):
        address = _fmt_address(row.get("address"))
        disasm = _safe_line(row.get("disasm"), 420)
        bytes_preview = _safe_line(row.get("bytes"), 160)
        if bytes_preview:
            lines.append("%s  %-22s  %s" % (address, bytes_preview, disasm))
        else:
            lines.append("%s  %s" % (address, disasm))
    return "\n".join(lines)


def reconstruct_pseudocode_from_context(context: Dict[str, Any]) -> Dict[str, Any]:
    asm = _as_list(context.get("assembly"))
    warnings: List[str] = []
    if not asm:
        return {
            "available": False,
            "kind": "asm_reconstruction",
            "confidence": 0.0,
            "pseudo": "",
            "lines": [],
            "warnings": ["No assembly rows were captured from IDA."],
            "evidence": [],
        }

    row_addresses = {_address_int(row.get("address")) for row in asm}
    row_addresses.discard(None)
    known_targets = set()
    for row in asm:
        mnemonic = str(row.get("mnemonic") or "").lower().strip()
        if mnemonic.startswith("j"):
            for op in _operands(mnemonic, _safe_line(row.get("disasm"), 420)):
                target = _target_int(op)
                if target is not None and target in row_addresses:
                    known_targets.add(target)

    data_rows = sum(1 for row in asm if _is_data_directive(row.get("mnemonic"), row.get("disasm")))
    if data_rows and data_rows >= max(2, int(len(asm) * 0.55)):
        warnings.append("Captured rows look mostly like data directives, not executable code.")
    if context.get("mode") == "data" or (context.get("data_artifact") or {}).get("kind"):
        warnings.append("IDA classified the focus as data/string; define code or select executable instructions for a stronger reconstruction.")

    function_name = str(context.get("function_name") or "").strip()
    start_ea = _fmt_address(context.get("start_ea") or context.get("current_ea"))
    end_ea = _fmt_address(context.get("end_ea") or "")
    safe_name = re.sub(r"[^A-Za-z0-9_]+", "_", function_name).strip("_")
    if not safe_name or safe_name.lower() in ("none", "-"):
        safe_name = "reconstructed_%s" % (start_ea.replace("0x", "") or "region")

    output: List[str] = [
        "/*",
        " MonsteyAI ASM -> pseudo-C reconstruction.",
        " This is an approximate reading aid generated from IDA assembly, not Hex-Rays output.",
        " Verify control flow, stack/register state, and memory sizes against the original addresses.",
        " Source range: %s%s" % (start_ea or "unknown", (" - " + end_ea) if end_ea else ""),
        "*/",
        "__int64 __fastcall %s(/* unknown args */)" % safe_name,
        "{",
        "    // Registers and MEMxx[...] are reconstructed from the current assembly selection.",
    ]
    evidence: List[Dict[str, str]] = []
    last_compare: Optional[Tuple[str, str, str]] = None
    translated = 0
    for row in asm:
        address = _fmt_address(row.get("address"))
        address_int = _address_int(row.get("address"))
        disasm = _safe_line(row.get("disasm"), 420)
        if address_int in known_targets and address_int is not None:
            output.append("loc_%X:" % address_int)
        output.append("    /* %s: %s */" % (address or "?", disasm or str(row.get("mnemonic") or "")))
        translated_lines, last_compare, recognized = _translate_instruction(row, known_targets, last_compare)
        if recognized:
            translated += 1
        for line in translated_lines:
            output.append("    %s" % line)
        if len(evidence) < 80:
            evidence.append({"address": address, "kind": "asm", "text": disasm})
    output.append("}")

    confidence = 0.18
    if asm:
        confidence = min(0.62, max(0.18, (float(translated) / float(len(asm))) * 0.62))
    if warnings:
        confidence = min(confidence, 0.34)
    pseudo = "\n".join(output)
    lines = pseudo.splitlines()
    return {
        "available": True,
        "kind": "asm_reconstruction",
        "confidence": round(confidence, 2),
        "name": safe_name,
        "source_start": start_ea,
        "source_end": end_ea,
        "line_count": len(lines),
        "instruction_count": len(asm),
        "translated_instruction_count": translated,
        "pseudo": pseudo,
        "lines": lines,
        "warnings": warnings,
        "evidence": evidence,
    }


def attach_reconstruction_to_context(context: Dict[str, Any], reconstruction: Dict[str, Any]) -> Dict[str, Any]:
    try:
        ctx = copy.deepcopy(context)
    except Exception:
        ctx = dict(context)
    pseudo = str(reconstruction.get("pseudo") or "")
    lines = pseudo.splitlines()
    ctx["mode"] = "pseudocode_reconstructed"
    ctx["region_kind"] = ctx.get("region_kind") or "selection"
    ctx["decompiler"] = {
        "available": bool(pseudo),
        "synthetic": True,
        "source": "asm_reconstruction",
        "error": "Hex-Rays pseudocode unavailable or bypassed; Monstey generated approximate pseudo-C from assembly.",
        "truncated": False,
        "skipped_by_budget": False,
        "lines": lines,
        "focus": {
            "line_number": 0,
            "line": lines[0] if lines else "",
            "nearby_lines": [{"line_number": idx, "text": line} for idx, line in enumerate(lines[:24])],
            "highlight": {"source": "asm_reconstruction"},
        },
    }
    ctx["reconstructed_pseudocode"] = reconstruction
    notes = list(_as_list(ctx.get("notes")))
    notes.insert(0, "Synthetic pseudo-C was generated from focused assembly; verify every claim against assembly addresses.")
    ctx["notes"] = notes[:8]
    budget = dict(ctx.get("performance_budget") or {})
    budget["synthetic_pseudocode"] = True
    budget["pseudocode_skipped"] = False
    ctx["performance_budget"] = budget
    try:
        from .ida_context import collect_semantic_cues

        ctx["semantic_cues"] = collect_semantic_cues(ctx.get("decompiler") or {}, ctx.get("assembly") or [], ctx.get("xrefs") or {})
    except Exception:
        pass
    return ctx
