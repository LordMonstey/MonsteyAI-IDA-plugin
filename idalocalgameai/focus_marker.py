"""Temporary IDA item highlight for the live AI focus."""

from __future__ import annotations

from typing import Any, Optional

import ida_bytes
import idaapi
import idc


_last_ea: Optional[int] = None
_last_color: Optional[int] = None


def _rgb(r: int, g: int, b: int) -> int:
    """IDA item colors use COLORREF/BGR ordering."""
    return (int(b) << 16) | (int(g) << 8) | int(r)


FOCUS_COLOR = _rgb(70, 210, 115)
DEFAULT_COLOR = getattr(ida_bytes, "DEFCOLOR", getattr(idc, "DEFCOLOR", 0xFFFFFFFF))


def parse_ea(value: Any) -> Optional[int]:
    if value in (None, "", "-"):
        return None
    try:
        if isinstance(value, int):
            ea = value
        else:
            text = str(value).strip()
            ea = int(text, 16) if text.lower().startswith("0x") else int(text, 16)
        if ea == int(idaapi.BADADDR):
            return None
        return ea
    except Exception:
        return None


def _get_color(ea: int) -> int:
    try:
        return int(ida_bytes.get_color(ea, ida_bytes.CIC_ITEM))
    except Exception:
        try:
            return int(idc.get_color(ea, idc.CIC_ITEM))
        except Exception:
            return int(DEFAULT_COLOR)


def _set_color(ea: int, color: int) -> bool:
    try:
        ida_bytes.set_color(ea, ida_bytes.CIC_ITEM, int(color))
        return True
    except Exception:
        try:
            idc.set_color(ea, idc.CIC_ITEM, int(color))
            return True
        except Exception:
            return False


def refresh_ida() -> None:
    try:
        idaapi.refresh_idaview_anyway()
    except Exception:
        pass


def clear_focus_marker() -> None:
    global _last_color, _last_ea
    if _last_ea is not None and _last_color is not None:
        _set_color(_last_ea, _last_color)
        refresh_ida()
    _last_ea = None
    _last_color = None


def set_focus_marker(value: Any) -> bool:
    """Move the temporary focus marker to an address."""
    global _last_color, _last_ea
    ea = parse_ea(value)
    if ea is None:
        clear_focus_marker()
        return False
    if _last_ea == ea:
        return True
    if _last_ea is not None and _last_color is not None:
        _set_color(_last_ea, _last_color)
    _last_ea = ea
    _last_color = _get_color(ea)
    ok = _set_color(ea, FOCUS_COLOR)
    refresh_ida()
    return ok
