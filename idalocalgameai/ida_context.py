"""IDA context extraction.

This module is imported inside IDA. Keep it dependency-light and resilient:
if Hex-Rays fails, the plugin still produces a useful assembly context.
"""

from __future__ import annotations

import binascii
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import idaapi
import idautils
import idc

from .game_context import collect_game_context
from .navigation import navigation_snapshot, preferred_focus_ea
from .profile_guard import apply_effective_analysis_profile

try:
    import ida_hexrays
except Exception:
    ida_hexrays = None


INTEGER_LITERAL_RE = re.compile(r"\b0x[0-9A-Fa-f]+\b|\b\d{2,}\b")
READER_CALL_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*|sub_[0-9A-Fa-f]+)\s*\(\s*(a\d+|v\d+|this)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*(?:LL|i64|u|U)?",
    re.IGNORECASE,
)
OUTPUT_WRITE_RES = [
    re.compile(r"\*\s*\([^)]*\*\)\s*(a\d+)\s*=", re.IGNORECASE),
    re.compile(r"\*\([^)]*\*\)\s*\(\s*(a\d+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*=", re.IGNORECASE),
    re.compile(r"\b(a\d+)\s*\[\s*([^\]]+)\s*\]\s*=", re.IGNORECASE),
    re.compile(r"\*\s*(a\d+)\s*=", re.IGNORECASE),
]
FIELD_ACCESS_RE = re.compile(
    r"\*\s*\([^)]*\*\)\s*\(\s*(a\d+|v\d+|result|this)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)",
    re.IGNORECASE,
)
DIRTY_MASK_RE = re.compile(r"(\*?\s*a\d+|[A-Za-z_][A-Za-z0-9_]*|\*\([^)]*\*\)\([^)]*\))\s*\|=\s*(0x[0-9A-Fa-f]+|\d+)", re.IGNORECASE)
COMPARE_LITERAL_RE = re.compile(r"(==|!=|<=|>=|<|>)\s*(0x[0-9A-Fa-f]+|\d+)", re.IGNORECASE)
BYTE_SELECTOR_RE = re.compile(
    r"(\*\s*\(\s*_BYTE\s*\*\)\s*[A-Za-z0-9_]+(?:\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+))?|\b[A-Za-z0-9_]+\[[^\]]+\])\s*(==|!=)\s*(0x[0-9A-Fa-f]+|\d+)",
    re.IGNORECASE,
)
ASM_FLOAT_OP_RE = re.compile(r"\b(addss|subss|mulss|divss|maxss|minss)\b")
SIMD_VECTOR_OP_RE = re.compile(r"\b(__m128|_mm_[A-Za-z0-9_]+|xmm\d+|shuffle_ps|andnot_ps|cmpeq_ps|and_ps|or_ps)\b", re.IGNORECASE)
ACCUMULATOR_ASSIGN_RE = re.compile(r"\b(v\d+|a\d+\[[^\]]+\])\s*=\s*\1\s*[+\-*/]")
ASM_FLOAT_MEM_READ_RE = re.compile(
    r"\b(?:addss|subss|mulss|divss|maxss|minss|movss)\s+xmm\d+\s*,\s*(?:dword ptr\s+)?\[([A-Za-z0-9_]+)(?:\+([^\]]+))?\]",
    re.IGNORECASE,
)
ASM_FLOAT_MEM_WRITE_RE = re.compile(
    r"\bmovss\s+(?:dword ptr\s+)?\[([A-Za-z0-9_]+)(?:\+([^\]]+))?\]\s*,\s*xmm\d+",
    re.IGNORECASE,
)
ASCII_LABEL_RE = re.compile(r"[^A-Za-z0-9_]+")
IOCTL_CODE_RE = re.compile(
    r"\b(?:ioctl|iocontrolcode|controlcode|deviceiocontrol|ctl_code|parameters\.deviceiocontrol)\b|"
    r"\b0x(?:22|800|801|802|803|9C|A0)[0-9A-Fa-f]{3,6}\b",
    re.IGNORECASE,
)
DRIVER_API_TOKENS = (
    "iocalldriver",
    "iocreatedevice",
    "iocreatesymboliclink",
    "iodeletedevice",
    "iodeletesymboliclink",
    "iocreatedevice",
    "iocompleterequest",
    "iostacklocation",
    "getcurrentirpstacklocation",
    "irp_mj_device_control",
    "majorfunction",
    "deviceiocontrol",
    "dispatchdevicecontrol",
)
IOCTL_BUFFER_TOKENS = (
    "systembuffer",
    "type3inputbuffer",
    "userbuffer",
    "mdladdress",
    "inputbufferlength",
    "outputbufferlength",
    "iostacklocation",
    "parameters.deviceiocontrol",
)
IOCTL_VALIDATION_TOKENS = (
    "probeforread",
    "probeforwrite",
    "mmisaddressvalid",
    "sehexcept",
    "__try",
    "__except",
    "status_invalid_parameter",
    "status_buffer_too_small",
)
IOCTL_LENGTH_GUARD_RE = re.compile(
    r"(?:inputbufferlength|outputbufferlength).*(?:==|!=|<=|>=|<|>|\\bcmp\\b|\\btest\\b|status_)|"
    r"(?:==|!=|<=|>=|<|>|\\bcmp\\b|\\btest\\b|status_).*(?:inputbufferlength|outputbufferlength)",
    re.IGNORECASE,
)
IOCTL_RW_PRIMITIVE_TOKENS = (
    "mmcopyvirtualmemory",
    "pslookupprocessbyprocessid",
    "kestackattachprocess",
    "keunstackdetachprocess",
    "zwmapviewofsection",
    "mmmapiospace",
    "mmunmapiospace",
    "read_register",
    "write_register",
    "physicalmemory",
    "virtualaddress",
    "writewhatwhere",
)
GENERIC_COPY_TOKENS = (
    "rtlcopymemory",
    "memcpy",
    "memmove",
)
IOCTL_METHOD_TOKENS = (
    "method_buffered",
    "method_in_direct",
    "method_out_direct",
    "method_neither",
    "irp->associatedirp.systembuffer",
    "associatedirp.systembuffer",
)


def fmt_ea(ea: int) -> str:
    return "0x%X" % int(ea)


def parse_ea(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            return int(value, 16 if value.lower().startswith("0x") else 10)
        return int(value)
    except Exception:
        return None


def clean_line(text: Any) -> str:
    try:
        return ida_lines.tag_remove(str(text))
    except Exception:
        return str(text)


def semantic_code_text(text: Any) -> str:
    out = clean_line(text)
    out = re.sub(r"\s*;\s*AI:.*$", "", out)
    out = re.sub(r"\s+AI:\s*Evidence.*$", "", out)
    out = re.sub(r"\s+", " ", out).strip()
    return out


def current_selection() -> Optional[Tuple[int, int]]:
    viewers = []
    try:
        viewers.append(ida_kernwin.get_current_viewer())
    except Exception:
        pass
    viewers.append(None)
    for viewer in viewers:
        try:
            result = ida_kernwin.read_range_selection(viewer)
            if isinstance(result, tuple):
                if len(result) == 3:
                    ok, start, end = result
                    if ok and start != idaapi.BADADDR and end != idaapi.BADADDR and start < end:
                        return int(start), int(end)
                if len(result) == 2:
                    start, end = result
                    if start != idaapi.BADADDR and end != idaapi.BADADDR and start < end:
                        return int(start), int(end)
        except Exception:
            continue
    return None


def get_function_at(ea: int):
    func = ida_funcs.get_func(ea)
    if func:
        return func
    return None


def iter_heads_limited(start: int, end: int, max_lines: int) -> Iterable[int]:
    count = 0
    for head in idautils.Heads(start, end):
        if count >= max_lines:
            break
        count += 1
        yield int(head)


def function_metrics(start: int, end: int, max_scan: int = 1200) -> Dict[str, Any]:
    instructions = 0
    jumps = 0
    calls = 0
    indirect = 0
    truncated = False
    try:
        for ea in idautils.Heads(start, end):
            instructions += 1
            if instructions > max_scan:
                truncated = True
                break
            mnem = (idc.print_insn_mnem(ea) or "").lower()
            if mnem.startswith("j"):
                jumps += 1
                dis = clean_line(idc.GetDisasm(ea)).lower()
                if "[" in dis or "reg" in dis:
                    indirect += 1
            elif mnem == "call":
                calls += 1
    except Exception:
        pass
    jump_ratio = float(jumps) / float(max(1, instructions))
    return {
        "bytes": max(0, int(end) - int(start)),
        "instructions_scanned": instructions,
        "instruction_scan_truncated": truncated,
        "jumps_scanned": jumps,
        "calls_scanned": calls,
        "indirect_jumps_scanned": indirect,
        "jump_ratio": jump_ratio,
        "flattening_hint": bool(instructions >= 120 and jump_ratio >= 0.28),
    }


def should_skip_decompile(metrics: Dict[str, Any], max_instructions: int, max_bytes: int) -> Tuple[bool, str]:
    if max_bytes > 0 and int(metrics.get("bytes") or 0) > max_bytes:
        return True, "function byte size %d exceeds budget %d" % (int(metrics.get("bytes") or 0), max_bytes)
    if max_instructions > 0 and int(metrics.get("instructions_scanned") or 0) > max_instructions:
        return True, "instruction scan exceeds budget %d" % max_instructions
    if metrics.get("instruction_scan_truncated") and max_instructions > 0:
        return True, "instruction scan truncated before complete function; likely too large for fast decompile"
    return False, ""


def get_bytes_preview(ea: int, max_len: int = 16) -> str:
    try:
        size = ida_bytes.get_item_size(ea)
        size = max(1, min(size, max_len))
        data = ida_bytes.get_bytes(ea, size)
        if not data:
            return ""
        return binascii.hexlify(data).decode("ascii")
    except Exception:
        return ""


def get_string_at(ea: int) -> Optional[str]:
    try:
        value = idc.get_strlit_contents(ea, -1, 0)
        if value is None:
            value = idc.get_strlit_contents(ea)
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)
    except Exception:
        return None


def _byte_at(ea: int) -> Optional[int]:
    try:
        return int(idc.get_wide_byte(ea)) & 0xFF
    except Exception:
        return None


def _is_ascii_text_byte(value: Optional[int]) -> bool:
    if value is None:
        return False
    return value == 9 or 0x20 <= int(value) <= 0x7E


def _safe_ascii_label(value: str, fallback: str = "data_string") -> str:
    text = ASCII_LABEL_RE.sub("_", str(value or "")).strip("_").lower()
    if not text:
        return fallback
    return ("%s_%s" % (fallback, text[:48])).strip("_")


def ascii_string_around(ea: int, max_len: int = 256, min_len: int = 4) -> Optional[Dict[str, Any]]:
    """Recover a plain ASCII string even when IDA has only byte items."""
    try:
        head = ida_bytes.get_item_head(ea)
        if head != idaapi.BADADDR:
            ida_string = get_string_at(head)
            if ida_string and len(ida_string) >= min_len:
                size = max(1, int(ida_bytes.get_item_size(head) or len(ida_string)))
                return {
                    "kind": "ascii_string",
                    "start_ea": fmt_ea(head),
                    "end_ea": fmt_ea(head + min(size, max(len(ida_string), 1))),
                    "value": ida_string[:max_len],
                    "length": len(ida_string),
                    "source": "ida_strlit",
                }
    except Exception:
        pass

    seg = ida_segment.getseg(ea)
    if not seg:
        return None
    current = _byte_at(ea)
    if not _is_ascii_text_byte(current):
        return None

    start = int(ea)
    while start > int(seg.start_ea) and (int(ea) - start) < max_len:
        prev = start - 1
        value = _byte_at(prev)
        if not _is_ascii_text_byte(value):
            break
        start = prev

    end = int(ea)
    while end < int(seg.end_ea) and (end - start) < max_len:
        value = _byte_at(end)
        if not _is_ascii_text_byte(value):
            break
        end += 1

    if end <= start:
        return None
    raw = ida_bytes.get_bytes(start, end - start) or b""
    try:
        text = raw.decode("ascii", errors="ignore")
    except Exception:
        text = ""
    text = text.strip("\x00")
    if len(text) < min_len:
        return None
    return {
        "kind": "ascii_string",
        "start_ea": fmt_ea(start),
        "end_ea": fmt_ea(end),
        "value": text[:max_len],
        "length": len(text),
        "source": "ascii_scan",
    }


def is_code_item(ea: int) -> bool:
    try:
        head = ida_bytes.get_item_head(ea)
        if head == idaapi.BADADDR:
            head = ea
        return bool(ida_bytes.is_code(ida_bytes.get_full_flags(head)))
    except Exception:
        return False


def focused_data_artifact(ea: int) -> Optional[Dict[str, Any]]:
    if is_code_item(ea):
        return None
    try:
        head = ida_bytes.get_item_head(ea)
        if head == idaapi.BADADDR:
            head = ea
    except Exception:
        head = ea
    preview = data_ref_preview(head, 48)
    string_info = ascii_string_around(ea)
    if string_info:
        start = parse_ea(string_info.get("start_ea")) or head
        end = parse_ea(string_info.get("end_ea")) or (start + max(1, int(string_info.get("length") or 1)))
        value = str(string_info.get("value") or "")
        return {
            "kind": "ascii_string",
            "address": fmt_ea(start),
            "start_ea": fmt_ea(start),
            "end_ea": fmt_ea(end),
            "focus_ea": fmt_ea(ea),
            "segment": segment_name_at(start),
            "name": preview.get("name") or "",
            "label": _safe_ascii_label(value, "data_string"),
            "value": value,
            "length": int(string_info.get("length") or len(value)),
            "source": string_info.get("source"),
            "bytes": get_bytes_preview(start, min(64, max(1, end - start))),
            "type_hint": "ascii_string",
        }
    try:
        size = max(1, int(ida_bytes.get_item_size(head) or 1))
    except Exception:
        size = 1
    return {
        "kind": "data_item",
        "address": fmt_ea(head),
        "start_ea": fmt_ea(head),
        "end_ea": fmt_ea(head + size),
        "focus_ea": fmt_ea(ea),
        "segment": segment_name_at(head),
        "name": preview.get("name") or "",
        "label": preview.get("name") or "data_%X" % int(head),
        "value": preview.get("value_hint") or "",
        "length": size,
        "source": "ida_data_item",
        "bytes": preview.get("bytes") or "",
        "type_hint": preview.get("type_hint") or "data",
    }


def segment_name_at(ea: int) -> str:
    try:
        seg = ida_segment.getseg(ea)
        if seg:
            return ida_segment.get_segm_name(seg) or ""
    except Exception:
        pass
    return ""


def data_ref_preview(ea: int, max_bytes: int = 16) -> Dict[str, Any]:
    name = ""
    try:
        name = ida_name.get_name(ea) or ""
    except Exception:
        pass
    try:
        item_size = int(ida_bytes.get_item_size(ea))
    except Exception:
        item_size = 0
    bytes_hex = get_bytes_preview(ea, max_bytes)
    value_hint = ""
    type_hint = "data"
    try:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_byte(flags):
            type_hint = "byte"
            value_hint = "0x%02X" % int(idc.get_wide_byte(ea))
        elif ida_bytes.is_word(flags):
            type_hint = "word"
            value_hint = "0x%04X" % int(idc.get_wide_word(ea))
        elif ida_bytes.is_dword(flags):
            type_hint = "dword"
            value = int(idc.get_wide_dword(ea))
            value_hint = "0x%08X / %d" % (value, value)
        elif ida_bytes.is_qword(flags):
            type_hint = "qword"
            value = int(idc.get_qword(ea))
            value_hint = "0x%X" % value
        elif ida_bytes.is_float(flags):
            type_hint = "float"
        elif ida_bytes.is_double(flags):
            type_hint = "double"
    except Exception:
        pass
    if not value_hint and bytes_hex:
        value_hint = bytes_hex
    return {
        "name": name,
        "segment": segment_name_at(ea),
        "item_size": item_size,
        "type_hint": type_hint,
        "bytes": bytes_hex,
        "value_hint": value_hint,
    }


def get_func_name(ea: int) -> str:
    try:
        name = ida_name.get_name(ea)
        if name:
            return name
    except Exception:
        pass
    return idc.get_func_name(ea) or fmt_ea(ea)


def decompile_function(func, max_chars: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "available": False,
        "error": None,
        "lines": [],
        "truncated": False,
    }
    if ida_hexrays is None:
        result["error"] = "ida_hexrays module unavailable"
        return result
    try:
        if not ida_hexrays.init_hexrays_plugin():
            result["error"] = "Hex-Rays plugin is not initialized"
            return result
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc is None:
            result["error"] = "Hex-Rays returned no cfunc"
            return result
        lines: List[str] = []
        total = 0
        for line in cfunc.get_pseudocode():
            clean = clean_line(line.line)
            total += len(clean) + 1
            if total > max_chars:
                result["truncated"] = True
                break
            lines.append(clean)
        result["available"] = bool(lines)
        result["lines"] = lines
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


def assembly_context(start: int, end: int, max_lines: int) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for ea in iter_heads_limited(start, end, max_lines):
        try:
            mnem = idc.print_insn_mnem(ea)
            disasm = clean_line(idc.GetDisasm(ea))
            row = {
                "address": fmt_ea(ea),
                "mnemonic": mnem,
                "disasm": disasm,
                "bytes": get_bytes_preview(ea),
            }
            rows.append(row)
        except Exception:
            continue
    return rows


def local_instruction_window(ea: int, max_lines: int = 48) -> List[Dict[str, Any]]:
    try:
        head = ida_bytes.get_item_head(ea)
        if head == idaapi.BADADDR:
            head = ea
    except Exception:
        head = ea
    seg = ida_segment.getseg(head)
    if not seg:
        return assembly_context(head, head + 0x40, max_lines)
    before = max(4, max_lines // 2)
    start = head
    for _ in range(before):
        prev = idc.prev_head(start, seg.start_ea)
        if prev == idaapi.BADADDR or prev >= start:
            break
        start = prev
    end = head
    for _ in range(max_lines - before):
        nxt = idc.next_head(end, seg.end_ea)
        if nxt == idaapi.BADADDR or nxt <= end:
            break
        end = nxt
    final = idc.next_head(end, seg.end_ea)
    if final == idaapi.BADADDR:
        final = min(seg.end_ea, end + ida_bytes.get_item_size(end))
    return assembly_context(start, final, max_lines)


def focused_xrefs(ea: int, max_items: int = 24) -> Dict[str, Any]:
    out = {"code_from": [], "code_to": [], "data_from": [], "data_to": []}
    try:
        for dst in idautils.CodeRefsFrom(ea, 0):
            out["code_from"].append({"to": fmt_ea(dst), "name": get_func_name(dst)})
            if len(out["code_from"]) >= max_items:
                break
    except Exception:
        pass
    try:
        for src in idautils.CodeRefsTo(ea, 0):
            out["code_to"].append({"from": fmt_ea(src), "function": get_func_name(src)})
            if len(out["code_to"]) >= max_items:
                break
    except Exception:
        pass
    try:
        for dst in idautils.DataRefsFrom(ea):
            out["data_from"].append({"to": fmt_ea(dst), "string": get_string_at(dst)})
            if len(out["data_from"]) >= max_items:
                break
    except Exception:
        pass
    try:
        for src in idautils.DataRefsTo(ea):
            out["data_to"].append({"from": fmt_ea(src), "function": get_func_name(src)})
            if len(out["data_to"]) >= max_items:
                break
    except Exception:
        pass
    return out


def focused_item_context(ea: int, focus: Dict[str, Any], max_lines: int = 48) -> Dict[str, Any]:
    try:
        head = ida_bytes.get_item_head(ea)
        if head == idaapi.BADADDR:
            head = ea
    except Exception:
        head = ea
    try:
        seg = ida_segment.getseg(head)
        seg_name = ida_segment.get_segm_name(seg) if seg else ""
    except Exception:
        seg_name = ""
    try:
        item_size = ida_bytes.get_item_size(head)
    except Exception:
        item_size = 0
    data_artifact = focused_data_artifact(ea)
    return {
        "source": focus.get("source"),
        "source_age_seconds": focus.get("age_seconds"),
        "ea": fmt_ea(ea),
        "item_head": fmt_ea(head),
        "segment": seg_name,
        "name": get_func_name(head),
        "mouse_or_cursor_line": focus.get("line") or "",
        "highlight": focus.get("highlight") or {},
        "widget": focus.get("widget") or {},
        "disasm": clean_line(idc.GetDisasm(head)),
        "mnemonic": idc.print_insn_mnem(head),
        "bytes": get_bytes_preview(head, 24),
        "item_size": item_size,
        "data_artifact": data_artifact or {},
        "comment": (idc.get_cmt(head, 0) or idc.get_cmt(head, 1) or "")[:500],
        "xrefs": focused_xrefs(head),
        "nearby_assembly": local_instruction_window(head, max_lines),
    }


def code_ref_count_to(ea: int, limit: int = 200) -> int:
    count = 0
    try:
        for _ in idautils.CodeRefsTo(ea, 0):
            count += 1
            if count >= limit:
                break
    except Exception:
        pass
    return count


def code_ref_count_from(start: int, end: int, limit: int = 200) -> int:
    count = 0
    try:
        for ea in iter_heads_limited(start, end, limit * 4):
            for _ in idautils.CodeRefsFrom(ea, 0):
                count += 1
                if count >= limit:
                    return count
    except Exception:
        pass
    return count


def mini_function_context(target_ea: int, role: str, callsite_ea: Optional[int] = None, max_lines: int = 36) -> Dict[str, Any]:
    func = ida_funcs.get_func(target_ea)
    start = int(func.start_ea) if func else target_ea
    end = int(func.end_ea) if func else target_ea + 0x40
    xrefs = xrefs_context(start, start, end, max_items=18)
    item = {
        "role": role,
        "function_start": fmt_ea(start),
        "function_end": fmt_ea(end),
        "function_name": get_func_name(start),
        "target_ea": fmt_ea(target_ea),
        "callsite_ea": fmt_ea(callsite_ea) if callsite_ea is not None else None,
        "callsite_disasm": clean_line(idc.GetDisasm(callsite_ea)) if callsite_ea is not None else "",
        "incoming_ref_count": code_ref_count_to(start, limit=80),
        "outgoing_call_count": code_ref_count_from(start, end, limit=80),
        "strings": xrefs.get("strings", [])[:10],
        "callees": xrefs.get("callees", [])[:12],
        "local_assembly": local_instruction_window(callsite_ea if callsite_ea is not None else start, max_lines),
    }
    return item


def xref_expansion_context(func_start: int, xrefs: Dict[str, Any], caller_limit: int = 6, callee_limit: int = 6) -> Dict[str, Any]:
    callers = []
    callees = []
    seen_callers = set()
    seen_callees = set()

    for item in xrefs.get("callers", [])[:max(0, caller_limit)]:
        ea = parse_ea(item.get("address"))
        if ea is None:
            continue
        func = ida_funcs.get_func(ea)
        key = int(func.start_ea) if func else ea
        if key in seen_callers:
            continue
        seen_callers.add(key)
        callers.append(mini_function_context(key, "caller", callsite_ea=ea, max_lines=28))

    for item in xrefs.get("callees", [])[:max(0, callee_limit)]:
        target = parse_ea(item.get("to"))
        callsite = parse_ea(item.get("from"))
        if target is None:
            continue
        func = ida_funcs.get_func(target)
        key = int(func.start_ea) if func else target
        if key in seen_callees or key == func_start:
            continue
        seen_callees.add(key)
        callees.append(mini_function_context(key, "callee", callsite_ea=callsite, max_lines=24))

    return {
        "policy": "limited callers/callees around the focused function; use as context, not proof",
        "callers": callers,
        "callees": callees,
    }


def xrefs_context(func_start: int, start: int, end: int, max_items: int = 80) -> Dict[str, Any]:
    callers = []
    callees = []
    data_refs = []
    strings = []
    seen_callers = set()
    seen_callees = set()
    seen_data = set()

    try:
        for src in idautils.CodeRefsTo(func_start, 0):
            src_func = ida_funcs.get_func(src)
            item = {
                "address": fmt_ea(src),
                "function": get_func_name(src_func.start_ea) if src_func else get_func_name(src),
            }
            key = (item["address"], item["function"])
            if key not in seen_callers:
                callers.append(item)
                seen_callers.add(key)
            if len(callers) >= max_items:
                break
    except Exception:
        pass

    for ea in iter_heads_limited(start, end, max_items * 4):
        try:
            for dst in idautils.CodeRefsFrom(ea, 0):
                name = get_func_name(dst)
                key = (int(dst), name)
                if key not in seen_callees:
                    callees.append({"from": fmt_ea(ea), "to": fmt_ea(dst), "name": name})
                    seen_callees.add(key)
                if len(callees) >= max_items:
                    break
            for dst in idautils.DataRefsFrom(ea):
                if int(dst) in seen_data:
                    continue
                seen_data.add(int(dst))
                s = get_string_at(dst)
                preview = data_ref_preview(int(dst))
                row = {"from": fmt_ea(ea), "to": fmt_ea(dst), "string": s}
                row.update(preview)
                data_refs.append(row)
                if s:
                    strings.append({"address": fmt_ea(dst), "from": fmt_ea(ea), "value": s[:240]})
                if len(data_refs) >= max_items:
                    break
        except Exception:
            continue
        if len(callees) >= max_items and len(data_refs) >= max_items:
            break

    return {
        "callers": callers[:max_items],
        "callees": callees[:max_items],
        "data_refs": data_refs[:max_items],
        "strings": strings[:max_items],
    }


def data_xrefs_context(data_artifact: Dict[str, Any], max_items: int = 80) -> Dict[str, Any]:
    start = parse_ea(data_artifact.get("start_ea") or data_artifact.get("address"))
    if start is None:
        return {"callers": [], "callees": [], "data_refs": [], "strings": []}
    text = str(data_artifact.get("value") or "") if data_artifact.get("kind") == "ascii_string" else None
    callers = []
    data_refs = []
    seen = set()
    try:
        for xref in idautils.XrefsTo(start, 0):
            src = int(xref.frm)
            if src in seen:
                continue
            seen.add(src)
            src_func = ida_funcs.get_func(src)
            callers.append({
                "address": fmt_ea(src),
                "function": get_func_name(src_func.start_ea) if src_func else get_func_name(src),
            })
            row = {"from": fmt_ea(src), "to": fmt_ea(start), "string": text, "xref_type": str(getattr(xref, "type", ""))}
            row.update(data_ref_preview(start))
            data_refs.append(row)
            if len(data_refs) >= max_items:
                break
    except Exception:
        pass
    try:
        for src in idautils.DataRefsTo(start):
            src = int(src)
            if src in seen:
                continue
            seen.add(src)
            src_func = ida_funcs.get_func(src)
            callers.append({
                "address": fmt_ea(src),
                "function": get_func_name(src_func.start_ea) if src_func else get_func_name(src),
            })
            row = {"from": fmt_ea(src), "to": fmt_ea(start), "string": text}
            row.update(data_ref_preview(start))
            data_refs.append(row)
            if len(data_refs) >= max_items:
                break
    except Exception:
        pass
    strings = []
    if text:
        strings.append({"address": fmt_ea(start), "from": "", "value": text[:240]})
    return {
        "callers": callers[:max_items],
        "callees": [],
        "data_refs": data_refs[:max_items],
        "strings": strings[:max_items],
    }


def comments_context(start: int, end: int, max_items: int = 40) -> List[Dict[str, str]]:
    comments = []
    for ea in iter_heads_limited(start, end, max_items * 8):
        try:
            cmt = idc.get_cmt(ea, 0) or idc.get_cmt(ea, 1)
            if cmt:
                comments.append({"address": fmt_ea(ea), "text": cmt[:500]})
            if len(comments) >= max_items:
                break
        except Exception:
            continue
    return comments


def segment_window(ea: int, max_lines: int) -> Tuple[int, int]:
    seg = ida_segment.getseg(ea)
    if not seg:
        return ea, ea + 0x80
    half = max(8, max_lines // 2)
    start = ea
    for _ in range(half):
        prev = idc.prev_head(start, seg.start_ea)
        if prev == idaapi.BADADDR or prev >= start:
            break
        start = prev
    end = ea
    for _ in range(half):
        nxt = idc.next_head(end, seg.end_ea)
        if nxt == idaapi.BADADDR or nxt <= end:
            break
        end = nxt
    return max(seg.start_ea, start), min(seg.end_ea, idc.next_head(end, seg.end_ea))


def simple_engine_hints(strings: List[Dict[str, Any]], callees: List[Dict[str, Any]], names: List[str]) -> List[str]:
    hay = " ".join([s.get("value", "") for s in strings] + [c.get("name", "") for c in callees] + names).lower()
    hints = []
    checks = [
        ("Unreal", ["uobject", "ufunction", "uclass", "process_event", "processevent", "blueprint", "gworld", "fname"]),
        ("Unity IL2CPP", ["il2cpp", "mono", "gameassembly", "global-metadata", "fixedupdate", "lateupdate"]),
        ("Source", ["createinterface", "convar", "client.dll", "server.dll", "entitylist"]),
        ("Rendering", ["render", "shader", "swapchain", "present", "directx", "vulkan", "opengl"]),
        ("Input", ["input", "keyboard", "mouse", "gamepad", "controller"]),
        ("Networking", ["socket", "send", "recv", "packet", "http", "steamnetworking"]),
    ]
    for label, needles in checks:
        if any(needle in hay for needle in needles):
            hints.append(label)
    return hints


def parse_int_literal(text: Any) -> Optional[int]:
    value = str(text or "").strip().rstrip("uUlLiI64")
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value, 10)
    except Exception:
        return None


def integer_literals(text: str) -> List[Dict[str, Any]]:
    out = []
    for match in INTEGER_LITERAL_RE.finditer(text):
        raw = match.group(0)
        value = parse_int_literal(raw)
        if value is None:
            continue
        out.append({"raw": raw, "value": value})
    return out


def source_lines_for_semantics(pseudocode: Dict[str, Any], asm: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    lines = []
    for idx, text in enumerate(pseudocode.get("lines") or []):
        clean = semantic_code_text(text)
        if clean:
            lines.append({"source": "pseudocode", "index": idx, "address": "", "text": clean})
    for row in asm[:260]:
        if not isinstance(row, dict):
            continue
        clean = semantic_code_text(row.get("disasm") or "")
        if not clean:
            continue
        lines.append({
            "source": "asm",
            "index": len(lines),
            "address": row.get("address") or "",
            "text": clean,
        })
    return lines


def collect_semantic_cues(
    pseudocode: Dict[str, Any],
    asm: List[Dict[str, Any]],
    xrefs: Dict[str, Any],
    max_items: int = 48,
) -> Dict[str, Any]:
    lines = source_lines_for_semantics(pseudocode, asm)
    reader_calls: List[Dict[str, Any]] = []
    output_writes: List[Dict[str, Any]] = []
    structure_reads: List[Dict[str, Any]] = []
    dirty_masks: List[Dict[str, Any]] = []
    numeric_ops: List[Dict[str, Any]] = []
    mode_checks: List[Dict[str, Any]] = []
    bitwise_ops: List[Dict[str, Any]] = []
    bounds_checks: List[Dict[str, Any]] = []
    magic_constants: List[Dict[str, Any]] = []
    sanitization_idioms: List[Dict[str, Any]] = []
    driver_api_calls: List[Dict[str, Any]] = []
    ioctl_code_checks: List[Dict[str, Any]] = []
    ioctl_buffer_access: List[Dict[str, Any]] = []
    ioctl_validation_checks: List[Dict[str, Any]] = []
    ioctl_rw_primitives: List[Dict[str, Any]] = []
    ioctl_method_hints: List[Dict[str, Any]] = []
    seen_magic = set()

    for item in lines:
        text = item.get("text") or ""
        if not text:
            continue
        low = text.lower()
        for match in READER_CALL_RE.finditer(text):
            bits = parse_int_literal(match.group(3))
            if bits is None:
                continue
            if 1 <= bits <= 128:
                reader_calls.append({
                    "call": match.group(1),
                    "stream_arg": match.group(2),
                    "bit_or_field_width": bits,
                    "line": text[:260],
                    "address": item.get("address") or "",
                })
                if len(reader_calls) >= max_items:
                    break

        if "=" in text and "==" not in text:
            for pattern in OUTPUT_WRITE_RES:
                match = pattern.search(text)
                if not match:
                    continue
                offset = match.group(2) if len(match.groups()) >= 2 else "0"
                output_writes.append({
                    "base": match.group(1).replace(" ", ""),
                    "offset_or_index": offset,
                    "line": text[:260],
                    "address": item.get("address") or "",
                })
                break

        for match in FIELD_ACCESS_RE.finditer(text):
            if len(structure_reads) >= max_items:
                break
            structure_reads.append({
                "base": match.group(1),
                "offset": match.group(2),
                "line": text[:260],
                "address": item.get("address") or "",
            })

        for match in ASM_FLOAT_MEM_READ_RE.finditer(text):
            if len(structure_reads) >= max_items:
                break
            structure_reads.append({
                "base": match.group(1),
                "offset": match.group(2) or "0",
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "SSE float memory operand read",
            })

        for match in ASM_FLOAT_MEM_WRITE_RE.finditer(text):
            if len(output_writes) >= max_items:
                break
            output_writes.append({
                "base": match.group(1),
                "offset_or_index": match.group(2) or "0",
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "SSE float output slot write",
            })

        dirty_match = DIRTY_MASK_RE.search(text)
        if dirty_match:
            dirty_masks.append({
                "target": dirty_match.group(1).strip(),
                "mask": dirty_match.group(2),
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "output dirty/update mask candidate",
            })

        if (
            "fmaxf" in text
            or "fminf" in text
            or "(float)" in text
            or "float *" in text
            or ASM_FLOAT_OP_RE.search(low)
            or SIMD_VECTOR_OP_RE.search(text)
            or ACCUMULATOR_ASSIGN_RE.search(text)
        ):
            numeric_ops.append({
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "float/SIMD numeric accumulator or modifier candidate",
            })

        selector_match = BYTE_SELECTOR_RE.search(text)
        if selector_match:
            mode_checks.append({
                "selector": selector_match.group(1).strip(),
                "operator": selector_match.group(2),
                "value": selector_match.group(3),
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "byte selector / operation mode candidate",
            })

        if any(token in text for token in ("^", "<<", ">>", "~")) or "__ROL" in text or "__ROR" in text:
            bitwise_ops.append({
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "bitwise/checksum/hash/obfuscation candidate",
            })

        for match in COMPARE_LITERAL_RE.finditer(text):
            value = parse_int_literal(match.group(2))
            if value is None:
                continue
            if value in (0xFF, 0xFFFF, 0xFFFFFFFF) or value <= 128:
                bounds_checks.append({
                    "operator": match.group(1),
                    "value": match.group(2),
                    "line": text[:260],
                    "address": item.get("address") or "",
                })

        if "- 1" in text and ("0xFF" in text or "<= 0x1F" in text or "<= 31" in text):
            sanitization_idioms.append({
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "read-value-minus-one sentinel/bounds idiom candidate",
            })

        if any(token in low for token in DRIVER_API_TOKENS):
            driver_api_calls.append({
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "Windows driver dispatch/API cue",
            })

        if IOCTL_CODE_RE.search(text):
            ioctl_code_checks.append({
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "IOCTL code/dispatch selector candidate",
            })

        if any(token in low for token in IOCTL_BUFFER_TOKENS):
            ioctl_buffer_access.append({
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "IOCTL buffer or IRP stack field access",
            })

        if any(token in low for token in IOCTL_VALIDATION_TOKENS) or IOCTL_LENGTH_GUARD_RE.search(text):
            ioctl_validation_checks.append({
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "buffer/probe/status validation cue",
            })

        strong_driver_memory = any(token in low for token in IOCTL_RW_PRIMITIVE_TOKENS)
        generic_driver_copy = (
            any(token in low for token in GENERIC_COPY_TOKENS)
            and (
                any(token in low for token in IOCTL_BUFFER_TOKENS)
                or any(token in low for token in DRIVER_API_TOKENS)
                or IOCTL_CODE_RE.search(text)
                or ioctl_code_checks
                or ioctl_buffer_access
                or driver_api_calls
            )
        )
        if strong_driver_memory or generic_driver_copy:
            ioctl_rw_primitives.append({
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "kernel read/write or memory copy primitive candidate",
            })

        if any(token in low for token in IOCTL_METHOD_TOKENS):
            ioctl_method_hints.append({
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "IOCTL transfer method / buffer source cue",
            })

        for literal in integer_literals(text):
            value = int(literal["value"])
            if value <= 255:
                continue
            if item.get("address") and literal["raw"].lower() == str(item.get("address")).lower():
                continue
            if value > 0x100000000:
                continue
            if value in seen_magic:
                continue
            seen_magic.add(value)
            magic_constants.append({
                "constant": literal["raw"],
                "decimal": value,
                "line": text[:260],
                "address": item.get("address") or "",
                "meaning": "magic/hash/checksum/seed/field-size constant candidate",
            })
            if len(magic_constants) >= max_items:
                break

    strings = []
    driver_strings = []
    for s in xrefs.get("strings", [])[:40]:
        if not isinstance(s, dict):
            continue
        value = str(s.get("value") or "")
        if not value:
            continue
        low = value.lower()
        priority = bool(any(token in low for token in ("bungie", "player", "name", "network", "packet", "steam", "account", "id", "clan")))
        row = {
            "address": s.get("address") or "",
            "from": s.get("from") or "",
            "value": value[:240],
            "priority": priority,
        }
        strings.append(row)
        if any(token in low for token in ("\\device\\", "\\dosdevices\\", "\\\\.\\", "ioctl", "deviceiocontrol", "driver", "kernel")):
            driver_strings.append(dict(row))

    for c in xrefs.get("callees", [])[:80]:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or c.get("to") or "")
        low = name.lower()
        if any(token in low for token in DRIVER_API_TOKENS + IOCTL_VALIDATION_TOKENS + IOCTL_RW_PRIMITIVE_TOKENS):
            driver_api_calls.append({
                "line": name[:260],
                "address": c.get("from") or c.get("to") or "",
                "meaning": "driver/import/callee cue",
            })
        if any(token in low for token in IOCTL_RW_PRIMITIVE_TOKENS):
            ioctl_rw_primitives.append({
                "line": name[:260],
                "address": c.get("from") or c.get("to") or "",
                "meaning": "kernel read/write primitive callee",
            })
        if any(token in low for token in IOCTL_VALIDATION_TOKENS):
            ioctl_validation_checks.append({
                "line": name[:260],
                "address": c.get("from") or c.get("to") or "",
                "meaning": "buffer/probe validation callee",
            })

    grouped = {}
    for call in reader_calls:
        key = (call.get("call"), call.get("stream_arg"))
        grouped.setdefault(key, set()).add(call.get("bit_or_field_width"))
    likely_readers = [
        {"call": key[0], "stream_arg": key[1], "widths": sorted(widths)}
        for key, widths in grouped.items()
        if len(widths) >= 2 or any(width in (1, 5, 6, 8, 9, 16, 32, 64) for width in widths)
    ]

    bitstream_score = 0
    bitstream_score += min(4, len(likely_readers))
    bitstream_score += 2 if dirty_masks else 0
    bitstream_score += 1 if output_writes else 0
    bitstream_score += 1 if strings else 0
    bitstream_likelihood = "high" if bitstream_score >= 5 else "medium" if bitstream_score >= 3 else "low"

    ioctl_score = 0
    ioctl_score += min(3, len(ioctl_code_checks))
    ioctl_score += 2 if ioctl_buffer_access else 0
    ioctl_score += 2 if driver_api_calls else 0
    ioctl_score += 2 if ioctl_rw_primitives else 0
    ioctl_score += 1 if driver_strings else 0
    ioctl_likelihood = "high" if ioctl_score >= 6 else "medium" if ioctl_score >= 3 else "low" if ioctl_score else "none"

    return {
        "policy": "heuristics extracted locally before LLM; use as clues, not proof",
        "bitstream_or_structured_reader_likelihood": bitstream_likelihood,
        "driver_ioctl_likelihood": ioctl_likelihood,
        "likely_reader_calls": likely_readers[:12],
        "reader_call_evidence": reader_calls[:max_items],
        "structure_reads": structure_reads[:max_items],
        "output_layout_writes": output_writes[:max_items],
        "dirty_masks": dirty_masks[:max_items],
        "numeric_ops": numeric_ops[:max_items],
        "mode_checks": mode_checks[:max_items],
        "bitwise_or_checksum_ops": bitwise_ops[:max_items],
        "bounds_checks": bounds_checks[:max_items],
        "sanitization_idioms": sanitization_idioms[:max_items],
        "magic_constants": magic_constants[:max_items],
        "string_anchors": strings[:max_items],
        "driver_api_calls": driver_api_calls[:max_items],
        "ioctl_code_checks": ioctl_code_checks[:max_items],
        "ioctl_buffer_access": ioctl_buffer_access[:max_items],
        "ioctl_validation_checks": ioctl_validation_checks[:max_items],
        "ioctl_rw_primitives": ioctl_rw_primitives[:max_items],
        "ioctl_method_hints": ioctl_method_hints[:max_items],
        "driver_strings": driver_strings[:max_items],
        "anti_misread_notes": [
            "Repeated calls with a stream-like first argument and small integer widths often indicate bitstream/file/network deserialization, not memcpy.",
            "Writes to many explicit offsets of an output parameter imply structure population; map offsets before naming behavior.",
            "Float min/max/multiply/add loops that write to an output index are numeric accumulators/modifiers until strings or xrefs prove a gameplay name.",
            "Byte selector comparisons often describe operation modes; explain the modes mechanically before guessing a system name.",
            "Param/output '|=' operations are dirty/update masks until proven otherwise.",
            "Strings are high-confidence anchors for semantics; prioritize them over generic engine guesses.",
            "For Windows drivers, IOCTL code dispatch, buffer source, length checks, probes, and copy primitives must be mapped before calling a path vulnerable.",
        ],
    }


def database_context() -> Dict[str, Any]:
    root_filename = ""
    input_file = ""
    try:
        root_filename = idc.get_root_filename() or ""
    except Exception:
        pass
    try:
        input_file = ida_nalt.get_input_file_path() or ""
    except Exception:
        pass
    try:
        imagebase = fmt_ea(idaapi.get_imagebase())
    except Exception:
        imagebase = ""
    return {
        "root_filename": root_filename,
        "input_file": input_file,
        "imagebase": imagebase,
    }


def attach_pseudocode_focus(pseudocode: Dict[str, Any], nav: Dict[str, Any]) -> None:
    lines = pseudocode.get("lines") or []
    if not lines:
        return
    pseudo = nav.get("pseudocode_cursor") or {}
    cpos = pseudo.get("cpos") or {}
    try:
        lnnum = int(cpos.get("lnnum"))
    except Exception:
        return
    if lnnum < 0 or lnnum >= len(lines):
        return
    start = max(0, lnnum - 10)
    end = min(len(lines), lnnum + 11)
    pseudocode["focus"] = {
        "line_number": lnnum,
        "cursor_x": cpos.get("x"),
        "cursor_y": cpos.get("y"),
        "line": lines[lnnum],
        "nearby_lines": [{"line_number": idx, "text": lines[idx]} for idx in range(start, end)],
        "highlight": pseudo.get("highlight") or {},
    }


def collect_context(force_asm: bool = False, cfg: Any = None) -> Dict[str, Any]:
    t0 = time.perf_counter()
    timings: Dict[str, float] = {}

    def mark(name: str, start_time: float) -> None:
        timings[name] = round(time.perf_counter() - start_time, 3)

    budget = cfg.depth_budget() if cfg is not None and hasattr(cfg, "depth_budget") else {}
    max_asm_lines = int(budget.get("max_asm_lines", getattr(cfg, "max_asm_lines", 220)))
    max_pseudocode_chars = int(budget.get("max_pseudocode_chars", getattr(cfg, "max_pseudocode_chars", 14000)))
    max_decompile_instructions = int(budget.get("max_decompile_instructions", getattr(cfg, "max_decompile_instructions", 700)))
    max_decompile_bytes = int(budget.get("max_decompile_bytes", getattr(cfg, "max_decompile_bytes", 32768)))
    max_xref_items = int(budget.get("max_xref_items", getattr(cfg, "max_xref_items", 48)))
    max_xref_expansion_items = int(budget.get("max_xref_expansion_items", getattr(cfg, "max_xref_expansion_items", 6)))
    analysis_depth = str(getattr(cfg, "analysis_depth", "Fast"))
    t = time.perf_counter()
    nav = navigation_snapshot()
    focus = preferred_focus_ea(nav)
    screen_ea = int(ida_kernwin.get_screen_ea())
    focus_ea = parse_ea(focus.get("ea"))
    ea = focus_ea if focus_ea is not None else screen_ea
    if ea == idaapi.BADADDR:
        raise RuntimeError("No current address in IDA")
    mark("navigation", t)

    t = time.perf_counter()
    selection = current_selection()
    func = get_function_at(ea)
    data_artifact = focused_data_artifact(ea)
    data_focus = bool(data_artifact and not func and not selection)

    if force_asm:
        if selection:
            start, end = selection
            region_kind = "selection"
        elif func:
            start, end = int(func.start_ea), int(func.end_ea)
            region_kind = "function_asm"
        elif data_focus:
            start = parse_ea(data_artifact.get("start_ea")) or ea
            end = parse_ea(data_artifact.get("end_ea")) or (start + max(1, int(data_artifact.get("length") or 1)))
            region_kind = data_artifact.get("kind") or "data_item"
        else:
            start, end = segment_window(ea, max_asm_lines)
            region_kind = "segment_window"
    elif func:
        start, end = int(func.start_ea), int(func.end_ea)
        region_kind = "function"
    elif selection:
        start, end = selection
        region_kind = "selection_no_function"
    elif data_focus:
        start = parse_ea(data_artifact.get("start_ea")) or ea
        end = parse_ea(data_artifact.get("end_ea")) or (start + max(1, int(data_artifact.get("length") or 1)))
        region_kind = data_artifact.get("kind") or "data_item"
    else:
        start, end = segment_window(ea, max_asm_lines)
        region_kind = "segment_window_no_function"

    func_name = (
        get_func_name(start)
        if func and start == int(func.start_ea)
        else str((data_artifact or {}).get("label") or ("region_%X" % start))
    )
    pseudocode = {"available": False, "error": "not requested", "lines": [], "truncated": False}
    metrics = function_metrics(start, end, max(max_decompile_instructions + 1, max_asm_lines + 1)) if func else function_metrics(start, end, max_asm_lines + 1)
    mark("function_metrics", t)
    t = time.perf_counter()
    skip_decompile, skip_reason = should_skip_decompile(metrics, max_decompile_instructions, max_decompile_bytes)
    if func and not force_asm:
        if skip_decompile:
            pseudocode = {
                "available": False,
                "error": "skipped by performance budget: %s" % skip_reason,
                "lines": [],
                "truncated": False,
                "skipped_by_budget": True,
            }
        else:
            pseudocode = decompile_function(func, max_pseudocode_chars)
            attach_pseudocode_focus(pseudocode, nav)
    mark("decompile", t)

    t = time.perf_counter()
    asm = assembly_context(start, end, max_asm_lines)
    mark("assembly", t)
    t = time.perf_counter()
    xrefs = (
        data_xrefs_context(data_artifact, max_items=max_xref_items)
        if data_focus
        else xrefs_context(int(func.start_ea) if func else start, start, end, max_items=max_xref_items)
    )
    mark("xrefs", t)
    func_start = int(func.start_ea) if func else start
    t = time.perf_counter()
    if max_xref_expansion_items > 0:
        xref_expansion = xref_expansion_context(
            func_start,
            xrefs,
            caller_limit=max_xref_expansion_items,
            callee_limit=max_xref_expansion_items,
        )
    else:
        xref_expansion = {
            "policy": "disabled by analysis depth for speed",
            "callers": [],
            "callees": [],
        }
    mark("xref_expansion", t)
    t = time.perf_counter()
    comments = comments_context(start, end)
    mark("comments", t)
    mode = "data" if data_focus else "pseudocode" if pseudocode.get("available") else "asm_fallback"
    t = time.perf_counter()
    focus_ctx = focused_item_context(ea, focus, max(32, min(80, max_asm_lines // 3)))
    mark("focus_context", t)
    t = time.perf_counter()
    db_context = database_context()
    game_context = collect_game_context(db_context, cfg, xrefs.get("strings", []))
    mark("game_context", t)
    t = time.perf_counter()
    semantic_cues = collect_semantic_cues(pseudocode, asm, xrefs)
    if data_focus:
        semantic_cues["data_artifact"] = data_artifact or {}
        semantic_cues["bitstream_or_structured_reader_likelihood"] = "none"
        if data_artifact and data_artifact.get("kind") == "ascii_string" and data_artifact.get("value"):
            anchor = {
                "address": data_artifact.get("start_ea") or data_artifact.get("address") or "",
                "from": "",
                "value": str(data_artifact.get("value") or "")[:240],
                "priority": True,
            }
            existing = {
                (str(item.get("address") or ""), str(item.get("value") or ""))
                for item in semantic_cues.get("string_anchors", [])
                if isinstance(item, dict)
            }
            key = (str(anchor.get("address") or ""), str(anchor.get("value") or ""))
            if key not in existing:
                semantic_cues.setdefault("string_anchors", []).insert(0, anchor)
    mark("semantic_cues", t)

    t = time.perf_counter()
    names = [func_name] + [item.get("name", "") for item in xrefs.get("callees", [])]
    hints = simple_engine_hints(xrefs.get("strings", []), xrefs.get("callees", []), names)
    mark("engine_hints", t)
    timings["total_context"] = round(time.perf_counter() - t0, 3)

    context = {
        "mode": mode,
        "requested_analysis_profile": getattr(cfg, "analysis_profile", "Trainer / Modding"),
        "analysis_profile": getattr(cfg, "analysis_profile", "Trainer / Modding"),
        "region_kind": region_kind,
        "current_ea": fmt_ea(ea),
        "screen_ea": fmt_ea(screen_ea),
        "focus": focus_ctx,
        "data_artifact": data_artifact or {},
        "navigation": nav,
        "start_ea": fmt_ea(start),
        "end_ea": fmt_ea(end),
        "database": db_context,
        "game_context": game_context,
        "function_name": func_name,
        "has_function": bool(func),
        "decompiler": pseudocode,
        "assembly": asm,
        "xrefs": xrefs,
        "xref_expansion": xref_expansion,
        "semantic_cues": semantic_cues,
        "existing_comments": comments,
        "engine_hints_from_ida": hints,
        "performance_budget": {
            "analysis_depth": analysis_depth,
            "max_asm_lines": max_asm_lines,
            "max_pseudocode_chars": max_pseudocode_chars,
            "max_decompile_instructions": max_decompile_instructions,
            "max_decompile_bytes": max_decompile_bytes,
            "max_xref_items": max_xref_items,
            "max_xref_expansion_items": max_xref_expansion_items,
            "function_metrics": metrics,
            "pseudocode_skipped": bool(pseudocode.get("skipped_by_budget")),
            "skip_reason": skip_reason,
            "timings_seconds": timings,
        },
        "notes": [
            "asm_fallback is expected for red/non-decompilable regions or decompiler failures"
            if mode == "asm_fallback"
            else "Hex-Rays pseudocode is available"
        ],
    }
    apply_effective_analysis_profile(context, getattr(cfg, "analysis_profile", "Trainer / Modding"))
    return context
