"""Monstey optional analysis sidecar.

This file is executed in a separate Python process so optional heavy
reverse-engineering libraries do not destabilize IDAPython.
"""

from __future__ import annotations

import importlib
import json
import math
import os
import re
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple


LIBRARIES = [
    ("capstone", "capstone", "structured disassembly and operand extraction"),
    ("lief", "lief", "PE/ELF/Mach-O metadata and section/import analysis"),
    ("yara-python", "yara", "custom rule matching against dumps/files"),
    ("unicorn", "unicorn", "bounded CPU emulation for future block experiments"),
    ("miasm", "miasm", "IR, expression simplification, deobfuscation groundwork"),
    ("angr", "angr", "symbolic execution and CFG recovery side workflows"),
    ("triton", "triton", "dynamic symbolic execution / taint if manually installed"),
]

JCC = {
    "ja",
    "jae",
    "jb",
    "jbe",
    "jc",
    "je",
    "jg",
    "jge",
    "jl",
    "jle",
    "jna",
    "jnae",
    "jnb",
    "jnbe",
    "jnc",
    "jne",
    "jng",
    "jnge",
    "jnl",
    "jnle",
    "jno",
    "jnp",
    "jns",
    "jnz",
    "jo",
    "jp",
    "jpe",
    "jpo",
    "js",
    "jz",
}

BITWISE = {"xor", "or", "and", "rol", "ror", "rcl", "rcr", "shl", "shr", "sar", "sal"}
MEMORY_OP_RE = re.compile(r"\[(?P<body>[^\]]+)\]")
HEX_RE = re.compile(r"\b(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,}h)\b")
ADDR_RE = re.compile(r"\b0x[0-9A-Fa-f]{4,}\b")


def clean(value: Any, limit: int = 700) -> str:
    text = str(value or "")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def fmt_ea(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return "0x%X" % int(text, 16 if text.lower().startswith("0x") else 10)
    except Exception:
        match = ADDR_RE.search(text)
        return match.group(0) if match else ""


def ea_int(value: Any) -> Optional[int]:
    text = fmt_ea(value)
    if not text:
        return None
    try:
        return int(text, 16)
    except Exception:
        return None


def parse_bytes(value: Any) -> bytes:
    text = str(value or "")
    hex_bytes = re.findall(r"\b[0-9A-Fa-f]{2}\b", text)
    if not hex_bytes:
        compact = re.sub(r"[^0-9A-Fa-f]", "", text)
        if len(compact) >= 2 and len(compact) % 2 == 0:
            hex_bytes = [compact[idx : idx + 2] for idx in range(0, len(compact), 2)]
    try:
        return bytes(int(item, 16) for item in hex_bytes[:32])
    except Exception:
        return b""


def context_asm_rows(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    asm = context.get("assembly")
    if isinstance(asm, dict):
        rows = as_list(asm.get("lines") or asm.get("rows"))
    else:
        rows = as_list(asm)
    out: List[Dict[str, Any]] = []
    for item in rows:
        if isinstance(item, dict):
            disasm = item.get("disasm") or item.get("text") or item.get("line") or ""
            out.append(
                {
                    "address": fmt_ea(item.get("address") or item.get("ea")),
                    "mnemonic": clean(item.get("mnemonic") or first_mnemonic(disasm), 40).lower(),
                    "disasm": clean(disasm, 500),
                    "bytes": clean(item.get("bytes"), 160),
                }
            )
        else:
            text = clean(item, 500)
            out.append({"address": "", "mnemonic": first_mnemonic(text), "disasm": text, "bytes": ""})
    return [row for row in out if row.get("disasm") or row.get("mnemonic")]


def first_mnemonic(disasm: Any) -> str:
    text = str(disasm or "").strip()
    if ":" in text[:24]:
        text = text.split(":", 1)[1].strip()
    parts = text.split(None, 1)
    return parts[0].lower() if parts else ""


def operand_text(disasm: str, mnemonic: str) -> str:
    text = str(disasm or "").split(";", 1)[0].strip()
    if mnemonic and text.lower().startswith(mnemonic.lower()):
        return text[len(mnemonic) :].strip()
    parts = text.split(None, 1)
    return parts[1].strip() if len(parts) > 1 else ""


def split_operands(text: str) -> List[str]:
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


def library_status() -> Dict[str, Any]:
    items = []
    for label, module, purpose in LIBRARIES:
        item = {"name": label, "module": module, "available": False, "version": "", "purpose": purpose}
        try:
            mod = importlib.import_module(module)
            item["available"] = True
            item["version"] = str(getattr(mod, "__version__", getattr(mod, "version", "")) or "")
        except Exception as exc:
            item["error"] = clean(exc, 180)
        items.append(item)
    return {
        "ok": True,
        "python": sys.executable,
        "version": sys.version.split()[0],
        "libraries": items,
        "available_count": len([item for item in items if item.get("available")]),
    }


def evidence(kind: str, address: Any, text: str) -> str:
    ea = fmt_ea(address)
    body = clean(text, 700)
    if ea:
        return "%s %s %s" % (kind, ea, body)
    return "note %s" % body


def obfuscation_heuristics(context: Dict[str, Any]) -> Tuple[List[str], Dict[str, Any]]:
    rows = context_asm_rows(context)
    start = context.get("start_ea") or context.get("current_ea") or (rows[0].get("address") if rows else "")
    lines: List[str] = []
    if not rows:
        return [evidence("note", start, "sidecar obfuscation: no assembly rows available")], {"instruction_count": 0}

    jcc_rows = [row for row in rows if row.get("mnemonic") in JCC]
    jmp_rows = [row for row in rows if row.get("mnemonic") == "jmp"]
    call_rows = [row for row in rows if row.get("mnemonic") == "call"]
    ret_rows = [row for row in rows if row.get("mnemonic", "").startswith("ret")]
    bitwise_rows = [row for row in rows if row.get("mnemonic") in BITWISE]
    branch_count = len(jcc_rows) + len(jmp_rows)
    density = branch_count / float(max(1, len(rows)))
    indirect = []
    selector_counts: Dict[str, int] = {}
    magic_constants = []
    opaque_candidates = []
    memory_refs = []

    for idx, row in enumerate(rows):
        mnemonic = row.get("mnemonic") or ""
        disasm = row.get("disasm") or ""
        ops = split_operands(operand_text(disasm, mnemonic))
        low = disasm.lower()
        if mnemonic in ("jmp", "call") and ("[" in disasm or "ptr" in low and "0x" not in low):
            indirect.append(row)
        if mnemonic in ("cmp", "test") and len(ops) >= 2:
            left = clean(ops[0], 120)
            right = clean(ops[1], 120)
            selector_counts[left.lower()] = selector_counts.get(left.lower(), 0) + 1
            if mnemonic == "cmp" and left.lower() == right.lower() and idx + 1 < len(rows) and rows[idx + 1].get("mnemonic") in JCC:
                opaque_candidates.append((row, rows[idx + 1], "self-compare followed by conditional branch"))
            if idx > 0 and rows[idx - 1].get("mnemonic") == "xor":
                prev_ops = split_operands(operand_text(rows[idx - 1].get("disasm") or "", "xor"))
                if len(prev_ops) >= 2 and prev_ops[0].lower() == prev_ops[1].lower() and idx + 1 < len(rows) and rows[idx + 1].get("mnemonic") in JCC:
                    opaque_candidates.append((row, rows[idx + 1], "zeroed register test followed by conditional branch"))
        for match in HEX_RE.findall(disasm):
            value = match[:-1] if match.lower().endswith("h") else match
            try:
                number = int(value, 16 if value.lower().startswith("0x") else 16)
                if number > 0xFFFF:
                    magic_constants.append((row, "0x%X" % number))
            except Exception:
                pass
        if "[" in disasm and "]" in disasm:
            memory_refs.append(row)

    repeated_selectors = [(key, count) for key, count in selector_counts.items() if count >= 3]
    if density >= 0.28 and len(rows) >= 18:
        lines.append(
            evidence(
                "deobf",
                start,
                "sidecar obfuscation: high branch density %.2f (%d branches / %d instructions), flattening or dispatcher candidate"
                % (density, branch_count, len(rows)),
            )
        )
    if repeated_selectors:
        lines.append(
            evidence(
                "deobf",
                start,
                "sidecar obfuscation: repeated selector comparisons %s, possible state-machine/flattening dispatcher"
                % ", ".join("%s x%d" % (key, count) for key, count in repeated_selectors[:6]),
            )
        )
    for row in indirect[:8]:
        lines.append(evidence("deobf", row.get("address"), "sidecar obfuscation: indirect branch/call candidate: %s" % row.get("disasm")))
    for cmp_row, jcc_row, reason in opaque_candidates[:10]:
        lines.append(
            evidence(
                "deobf",
                cmp_row.get("address"),
                "sidecar obfuscation: opaque predicate candidate (%s): %s -> %s"
                % (reason, cmp_row.get("disasm"), jcc_row.get("disasm")),
            )
        )
    if bitwise_rows and len(bitwise_rows) >= 4:
        lines.append(
            evidence(
                "crypto_signature",
                bitwise_rows[0].get("address") or start,
                "sidecar bitwise mix: %d XOR/AND/OR/shift/rotate instructions; inspect for hash, checksum, string decode, or obfuscation"
                % len(bitwise_rows),
            )
        )
    for row, constant in magic_constants[:12]:
        lines.append(evidence("crypto_signature", row.get("address"), "sidecar magic constant: %s in `%s`" % (constant, row.get("disasm"))))
    if call_rows and len(call_rows) >= max(6, int(len(rows) * 0.18)):
        lines.append(evidence("capability", start, "sidecar shape: call-heavy block (%d calls), possible wrapper/dispatcher/helper cluster" % len(call_rows)))
    if not lines:
        lines.append(
            evidence(
                "note",
                start,
                "sidecar obfuscation: no strong flattening/opaque-predicate signature in bounded ASM; branches=%d bitwise=%d memrefs=%d"
                % (branch_count, len(bitwise_rows), len(memory_refs)),
            )
        )

    metrics = {
        "instruction_count": len(rows),
        "branch_count": branch_count,
        "conditional_branch_count": len(jcc_rows),
        "jump_count": len(jmp_rows),
        "call_count": len(call_rows),
        "ret_count": len(ret_rows),
        "branch_density": round(density, 3),
        "bitwise_count": len(bitwise_rows),
        "indirect_branch_count": len(indirect),
        "opaque_candidate_count": len(opaque_candidates),
        "magic_constant_count": len(magic_constants),
    }
    return lines[:120], metrics


def capstone_scout(context: Dict[str, Any]) -> List[str]:
    status = library_status()
    cap_item = next((item for item in status["libraries"] if item["name"] == "capstone"), {})
    if not cap_item.get("available"):
        return [evidence("note", context.get("start_ea") or context.get("current_ea"), "sidecar capstone: unavailable; install toolchain core")]
    try:
        from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_64, Cs
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    except Exception as exc:
        return [evidence("note", context.get("start_ea") or context.get("current_ea"), "sidecar capstone import failed: %s" % clean(exc, 200))]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    lines: List[str] = []
    for row in context_asm_rows(context)[:220]:
        code = parse_bytes(row.get("bytes"))
        address = ea_int(row.get("address")) or 0
        if not code or not address:
            continue
        try:
            insns = list(md.disasm(code, address, count=1))
        except Exception:
            insns = []
        if not insns:
            continue
        insn = insns[0]
        groups = []
        try:
            if insn.group(CS_GRP_JUMP):
                groups.append("jump")
            if insn.group(CS_GRP_CALL):
                groups.append("call")
            if insn.group(CS_GRP_RET):
                groups.append("ret")
        except Exception:
            pass
        mem_ops = []
        imm_ops = []
        reg_ops = []
        for op in getattr(insn, "operands", []) or []:
            if op.type == X86_OP_MEM:
                base = insn.reg_name(op.mem.base) if op.mem.base else ""
                index = insn.reg_name(op.mem.index) if op.mem.index else ""
                mem_ops.append("base=%s index=%s scale=%s disp=0x%X size=%s" % (base or "-", index or "-", op.mem.scale, op.mem.disp & 0xFFFFFFFFFFFFFFFF, op.size))
            elif op.type == X86_OP_IMM:
                imm_ops.append("0x%X" % (op.imm & 0xFFFFFFFFFFFFFFFF))
            elif op.type == X86_OP_REG:
                reg_ops.append(insn.reg_name(op.reg))
        if mem_ops:
            lines.append(evidence("structure", row.get("address"), "sidecar capstone mem operand: %s | %s %s" % ("; ".join(mem_ops[:3]), insn.mnemonic, insn.op_str)))
        if groups and ("jump" in groups or "call" in groups):
            lines.append(evidence("xref", row.get("address"), "sidecar capstone control transfer: groups=%s imm=%s text=%s %s" % (",".join(groups), ",".join(imm_ops[:3]) or "-", insn.mnemonic, insn.op_str)))
        same_reg_clear = insn.mnemonic == "xor" and len(reg_ops) >= 2 and reg_ops[0] == reg_ops[1]
        large_non_branch_imm = bool(not groups and imm_ops and any(len(item) >= 8 for item in imm_ops))
        if (insn.mnemonic in BITWISE and not same_reg_clear) or large_non_branch_imm:
            lines.append(evidence("crypto_signature", row.get("address"), "sidecar capstone operation: %s %s imm=%s regs=%s" % (insn.mnemonic, insn.op_str, ",".join(imm_ops[:4]) or "-", ",".join(reg_ops[:6]) or "-")))
    if not lines:
        lines.append(evidence("note", context.get("start_ea") or context.get("current_ea"), "sidecar capstone: no byte-backed instructions in current bounded context"))
    return lines[:120]


def file_path_from_context(context: Dict[str, Any]) -> str:
    db = as_dict(context.get("database"))
    for key in ("input_file", "root_filename", "path"):
        value = db.get(key)
        if value and os.path.isfile(str(value)):
            return str(value)
    value = context.get("input_file")
    if value and os.path.isfile(str(value)):
        return str(value)
    return ""


def lief_scout(context: Dict[str, Any]) -> List[str]:
    start = context.get("start_ea") or context.get("current_ea")
    path = file_path_from_context(context)
    if not path:
        return [evidence("note", start, "sidecar LIEF: no executable path available from IDA database context")]
    try:
        import lief
    except Exception:
        return [evidence("note", start, "sidecar LIEF: unavailable; install toolchain core")]
    if os.path.getsize(path) > 512 * 1024 * 1024:
        return [evidence("note", start, "sidecar LIEF: skipped very large input file >512 MiB")]
    try:
        binary = lief.parse(path)
    except Exception as exc:
        return [evidence("note", start, "sidecar LIEF parse failed: %s" % clean(exc, 260))]
    if binary is None:
        return [evidence("note", start, "sidecar LIEF: parser returned no binary")]

    lines: List[str] = []
    fmt = clean(getattr(binary, "format", ""), 80)
    imagebase = getattr(getattr(binary, "optional_header", None), "imagebase", None)
    lines.append(evidence("note", start, "sidecar LIEF: format=%s imagebase=%s sections=%d" % (fmt, ("0x%X" % imagebase) if isinstance(imagebase, int) else "-", len(getattr(binary, "sections", []) or []))))
    for section in list(getattr(binary, "sections", []) or [])[:24]:
        name = clean(getattr(section, "name", ""), 80)
        size = int(getattr(section, "size", 0) or 0)
        entropy = 0.0
        try:
            entropy = float(section.entropy)
        except Exception:
            pass
        flags = clean(getattr(section, "characteristics_lists", ""), 160)
        va = getattr(section, "virtual_address", 0)
        if entropy >= 7.1 or "MEM_EXECUTE" in flags or "MEM_WRITE" in flags:
            lines.append(evidence("capability", start, "sidecar LIEF section: %s va=0x%X size=0x%X entropy=%.2f flags=%s" % (name, int(va or 0), size, entropy, flags)))
    imports = []
    try:
        for imp in getattr(binary, "imports", []) or []:
            lib = clean(getattr(imp, "name", ""), 80)
            for entry in list(getattr(imp, "entries", []) or [])[:80]:
                name = clean(getattr(entry, "name", ""), 100)
                if name:
                    imports.append("%s!%s" % (lib, name))
                if len(imports) >= 120:
                    break
            if len(imports) >= 120:
                break
    except Exception:
        pass
    interesting = [item for item in imports if re.search(r"VirtualProtect|VirtualAlloc|CreateThread|memcpy|memmove|Rtl|QueryPerformance|GetAsyncKeyState", item, re.I)]
    if interesting:
        lines.append(evidence("capability", start, "sidecar LIEF imports: %s" % "; ".join(interesting[:24])))
    return lines[:120]


def yara_scout(context: Dict[str, Any]) -> List[str]:
    start = context.get("start_ea") or context.get("current_ea")
    try:
        import yara
    except Exception:
        return [evidence("note", start, "sidecar YARA: unavailable; install toolchain core")]
    rule_dir = os.path.join(os.path.expanduser("~"), ".monstey-ai-plugin", "yara")
    if not os.path.isdir(rule_dir):
        return [evidence("note", start, "sidecar YARA: no rules folder yet: %s" % rule_dir)]
    rule_files = []
    for root, _, names in os.walk(rule_dir):
        for name in names:
            if name.lower().endswith((".yar", ".yara")):
                rule_files.append(os.path.join(root, name))
        if len(rule_files) >= 128:
            break
    if not rule_files:
        return [evidence("note", start, "sidecar YARA: rules folder exists but contains no .yar/.yara files")]
    path = file_path_from_context(context)
    if not path:
        return [evidence("note", start, "sidecar YARA: no executable path available from IDA database context")]
    if os.path.getsize(path) > 512 * 1024 * 1024:
        return [evidence("note", start, "sidecar YARA: skipped very large input file >512 MiB")]
    try:
        file_map = {"r%d" % idx: rule for idx, rule in enumerate(rule_files[:128])}
        rules = yara.compile(filepaths=file_map)
        matches = rules.match(path, timeout=20)
    except Exception as exc:
        return [evidence("note", start, "sidecar YARA failed: %s" % clean(exc, 260))]
    lines = []
    for match in matches[:80]:
        namespace = clean(getattr(match, "namespace", ""), 80)
        rule = clean(getattr(match, "rule", ""), 120)
        tags = ",".join(getattr(match, "tags", []) or [])
        lines.append(evidence("signature", start, "sidecar YARA match: namespace=%s rule=%s tags=%s" % (namespace, rule, tags or "-")))
    if not lines:
        lines.append(evidence("note", start, "sidecar YARA: no custom rule matches"))
    return lines


def scout_context(context: Dict[str, Any], scout: str = "all") -> Dict[str, Any]:
    started = time.perf_counter()
    context = as_dict(context)
    scout = clean(scout or "all", 40).lower()
    status = library_status()
    lines: List[str] = []
    metrics: Dict[str, Any] = {}

    if scout in ("all", "obfuscation", "deobf"):
        obf_lines, metrics = obfuscation_heuristics(context)
        lines.extend(obf_lines)
    if scout in ("all", "capstone", "obfuscation", "deobf"):
        lines.extend(capstone_scout(context))
    if scout in ("all", "lief", "pe"):
        lines.extend(lief_scout(context))
    if scout in ("all", "yara", "rules"):
        lines.extend(yara_scout(context))

    available = [item["name"] for item in status["libraries"] if item.get("available")]
    if scout in ("all", "obfuscation", "deobf"):
        if "miasm" in available:
            lines.append(evidence("deobf", context.get("start_ea") or context.get("current_ea"), "sidecar Miasm: available for future IR simplification/deobfuscation passes"))
        if "unicorn" in available:
            lines.append(evidence("trace", context.get("start_ea") or context.get("current_ea"), "sidecar Unicorn: available for future bounded block emulation experiments"))
        if "angr" in available:
            lines.append(evidence("deobf", context.get("start_ea") or context.get("current_ea"), "sidecar angr: available for future symbolic/CFG side workflows"))

    deduped = []
    seen = set()
    for line in lines:
        key = line.lower()
        if key in seen:
            continue
        deduped.append(line)
        seen.add(key)
    return {
        "ok": True,
        "scout": scout,
        "libraries": status["libraries"],
        "metrics": metrics,
        "evidence_text": "\n".join(deduped[:260]),
        "row_count": len(deduped[:260]),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
    }


def read_request() -> Dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def main() -> int:
    request = read_request()
    command = (request.get("command") or (sys.argv[1] if len(sys.argv) > 1 else "check")).lower()
    try:
        if command == "check":
            out = library_status()
            lines = []
            for item in out["libraries"]:
                state = "available" if item.get("available") else "missing"
                detail = item.get("version") or item.get("error") or ""
                lines.append("note sidecar toolchain: %s %s %s" % (item["name"], state, clean(detail, 180)))
            out["evidence_text"] = "\n".join(lines)
        elif command == "scout_context":
            out = scout_context(as_dict(request.get("context")), request.get("scout") or "all")
        else:
            out = {"ok": False, "error": "unknown command: %s" % command}
    except Exception as exc:
        out = {"ok": False, "error": clean(exc, 1000)}
    sys.stdout.write(json.dumps(out, ensure_ascii=True, sort_keys=True))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
