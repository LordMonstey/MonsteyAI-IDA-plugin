"""IDA navigation and mouse-focus tracking."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import ida_kernwin
import ida_lines
import idaapi

from .compat.qt import QtCore, QtWidgets

try:
    import ida_hexrays
except Exception:
    ida_hexrays = None


MAX_HISTORY = 24
MOUSE_MAX_AGE_SECONDS = 30.0

_ui_hooks = None
_view_hooks = None
_hexrays_hooks = None
_key_filter = None
_last_mouse_update = 0.0

_state: Dict[str, Any] = {
    "installed": False,
    "active_widget": {},
    "screen": {},
    "mouse": {},
    "last_click": {},
    "pseudocode_cursor": {},
    "focus_lock": {},
    "history": [],
}


def _now() -> float:
    return time.time()


def _clean_line(text: Any) -> str:
    try:
        return ida_lines.tag_remove(str(text))
    except Exception:
        return str(text or "")


def _fmt_ea(ea: Any) -> Optional[str]:
    try:
        value = int(ea)
    except Exception:
        return None
    if value == int(idaapi.BADADDR):
        return None
    return "0x%X" % value


def _widget_info(widget: Any) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    if not widget:
        return info
    try:
        info["title"] = str(ida_kernwin.get_widget_title(widget))
    except Exception:
        info["title"] = ""
    try:
        info["type"] = int(ida_kernwin.get_widget_type(widget))
    except Exception:
        info["type"] = None
    return info


def _highlight(view: Any) -> Dict[str, Any]:
    try:
        result = ida_kernwin.get_highlight(view)
        if result:
            text, flags = result
            return {"text": str(text), "flags": int(flags)}
    except Exception:
        pass
    return {}


def _current_line(view: Any, mouse: bool) -> str:
    try:
        line = ida_kernwin.get_custom_viewer_curline(view, mouse)
        return _clean_line(line)
    except Exception:
        return ""


def _place_snapshot(view: Any, mouse: bool) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        place, x, y = ida_kernwin.get_custom_viewer_place(view, mouse)
        out["x"] = int(x)
        out["y"] = int(y)
        out["place"] = str(place)
        try:
            out["ea"] = _fmt_ea(place.toea())
        except Exception:
            pass
    except Exception:
        pass
    return out


def _event_position(event: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for attr in ("x", "y", "rtype", "button"):
        try:
            out[attr] = int(getattr(event, attr))
        except Exception:
            pass
    try:
        out["renderer_x"] = int(event.renderer_pos.x)
        out["renderer_y"] = int(event.renderer_pos.y)
    except Exception:
        pass
    return out


def _push_history(kind: str, ea: Optional[str], widget: Dict[str, Any], line: str = "") -> None:
    if not ea and not line:
        return
    item = {
        "time": round(_now(), 3),
        "kind": kind,
        "ea": ea,
        "widget": widget,
        "line": line[:240],
    }
    hist: List[Dict[str, Any]] = _state.setdefault("history", [])
    if hist and hist[-1].get("kind") == kind and hist[-1].get("ea") == ea and hist[-1].get("line") == item["line"]:
        return
    hist.append(item)
    del hist[:-MAX_HISTORY]


def _current_focus_candidates(snapshot: Dict[str, Any]) -> List[tuple]:
    return [
        ("mouse", snapshot.get("mouse") or {}),
        ("last_click", snapshot.get("last_click") or {}),
        ("pseudocode_cursor", snapshot.get("pseudocode_cursor") or {}),
        ("cursor", snapshot.get("cursor") or {}),
        ("screen", snapshot.get("screen") or {}),
    ]


def _preferred_focus_from_snapshot(snapshot: Dict[str, Any], include_lock: bool = True) -> Dict[str, Any]:
    now = _now()
    if include_lock:
        lock = snapshot.get("focus_lock") or {}
        if lock.get("ea"):
            return {
                "source": "locked",
                "ea": lock.get("ea"),
                "line": lock.get("line") or "",
                "highlight": lock.get("highlight") or {},
                "widget": lock.get("widget") or {},
                "age_seconds": round(max(0.0, now - float(lock.get("time") or now)), 3),
                "lock_reason": lock.get("reason") or "manual",
                "locked_from": lock.get("locked_from") or "",
            }
    for source, item in _current_focus_candidates(snapshot):
        ea = item.get("ea")
        if not ea:
            continue
        age = float(item.get("age_seconds") or 0.0)
        if source in ("mouse", "last_click") and age > MOUSE_MAX_AGE_SECONDS:
            continue
        return {
            "source": source,
            "ea": ea,
            "line": item.get("line") or "",
            "highlight": item.get("highlight") or {},
            "widget": item.get("widget") or {},
            "age_seconds": age,
        }
    return {"source": "none", "ea": None}


def clear_focus_lock() -> bool:
    had_lock = bool((_state.get("focus_lock") or {}).get("ea"))
    _state["focus_lock"] = {}
    if had_lock:
        try:
            ida_kernwin.msg("[Monstey-AI-plugin] AI focus lock cleared\n")
        except Exception:
            pass
    return had_lock


def lock_current_focus(reason: str = "manual") -> Optional[Dict[str, Any]]:
    snap = navigation_snapshot()
    focus = _preferred_focus_from_snapshot(snap, include_lock=False)
    ea = focus.get("ea")
    if not ea:
        try:
            screen_ea = ida_kernwin.get_screen_ea()
            ea = _fmt_ea(screen_ea)
        except Exception:
            ea = None
    if not ea:
        return None
    widget = focus.get("widget") or _widget_info(ida_kernwin.get_current_widget())
    lock = {
        "time": round(_now(), 3),
        "ea": ea,
        "line": focus.get("line") or "",
        "highlight": focus.get("highlight") or {},
        "widget": widget,
        "reason": reason,
        "locked_from": focus.get("source") or "screen",
    }
    _state["focus_lock"] = lock
    _push_history("focus_lock", ea, widget, lock.get("line") or "")
    try:
        ida_kernwin.msg("[Monstey-AI-plugin] AI focus locked at %s. Press A again to unlock.\n" % ea)
    except Exception:
        pass
    return dict(lock)


class MonsteyKeyFilter(QtCore.QObject):
    HOLD_SECONDS = 1.5

    def __init__(self):
        QtCore.QObject.__init__(self)
        self._a_down = False
        self._a_seq = 0

    def _is_text_input(self, obj: Any) -> bool:
        try:
            return isinstance(
                obj,
                (
                    QtWidgets.QLineEdit,
                    QtWidgets.QTextEdit,
                    QtWidgets.QPlainTextEdit,
                    QtWidgets.QSpinBox,
                    QtWidgets.QDoubleSpinBox,
                    QtWidgets.QComboBox,
                ),
            )
        except Exception:
            return False

    def eventFilter(self, obj, event):
        try:
            event_type = event.type()
            if event_type not in (QtCore.QEvent.KeyPress, QtCore.QEvent.KeyRelease):
                return False
            if int(event.key()) != int(QtCore.Qt.Key_A):
                return False
            if int(event.modifiers()) != int(QtCore.Qt.NoModifier):
                return False
            if self._is_text_input(obj):
                return False
            if event_type == QtCore.QEvent.KeyPress:
                if bool((_state.get("focus_lock") or {}).get("ea")):
                    clear_focus_lock()
                    self._a_down = False
                    self._a_seq += 1
                    return True
                if getattr(event, "isAutoRepeat", lambda: False)():
                    return False
                self._a_down = True
                self._a_seq += 1
                seq = self._a_seq
                QtCore.QTimer.singleShot(int(self.HOLD_SECONDS * 1000), lambda: self._finish_a_hold(seq))
                return False
            if event_type == QtCore.QEvent.KeyRelease:
                if getattr(event, "isAutoRepeat", lambda: False)():
                    return False
                self._a_down = False
                self._a_seq += 1
                return False
        except Exception:
            return False
        return False

    def _finish_a_hold(self, seq: int) -> None:
        try:
            if not self._a_down or seq != self._a_seq:
                return
            lock_current_focus("hold_a_1_5s")
        except Exception:
            pass


def _update_screen(ea: Any, prev_ea: Any = None) -> None:
    now = _now()
    current = _fmt_ea(ea)
    prev = _fmt_ea(prev_ea)
    widget = _widget_info(ida_kernwin.get_current_widget())
    _state["screen"] = {
        "time": round(now, 3),
        "ea": current,
        "previous_ea": prev,
        "widget": widget,
    }
    _state["active_widget"] = widget
    _push_history("screen_ea", current, widget)


def _update_mouse(view: Any, event: Any, kind: str) -> None:
    widget = _widget_info(view)
    place = _place_snapshot(view, True)
    line = _current_line(view, True)
    current = {
        "time": round(_now(), 3),
        "kind": kind,
        "widget": widget,
        "event": _event_position(event),
        "line": line[:700],
        "highlight": _highlight(view),
        "place": place,
        "ea": place.get("ea"),
    }
    _state["mouse"] = current
    _state["active_widget"] = widget
    if kind in ("click", "double_click"):
        _state["last_click"] = current
    _push_history("mouse_%s" % kind, current.get("ea"), widget, line)


class MonsteyUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

    def current_widget_changed(self, widget, prev_widget):
        try:
            _state["active_widget"] = _widget_info(widget)
        except Exception:
            pass

    def screen_ea_changed(self, ea, prev_ea):
        try:
            _update_screen(ea, prev_ea)
        except Exception:
            pass


class MonsteyViewHooks(ida_kernwin.View_Hooks):
    def __init__(self):
        ida_kernwin.View_Hooks.__init__(self)

    def view_activated(self, view):
        try:
            _state["active_widget"] = _widget_info(view)
        except Exception:
            pass

    def view_curpos(self, view):
        try:
            place = _place_snapshot(view, False)
            line = _current_line(view, False)
            widget = _widget_info(view)
            ea = place.get("ea")
            _state["cursor"] = {
                "time": round(_now(), 3),
                "widget": widget,
                "line": line[:700],
                "highlight": _highlight(view),
                "place": place,
                "ea": ea,
            }
            _push_history("view_curpos", ea, widget, line)
        except Exception:
            pass

    def view_click(self, view, event):
        try:
            _update_mouse(view, event, "click")
        except Exception:
            pass

    def view_dblclick(self, view, event):
        try:
            _update_mouse(view, event, "double_click")
        except Exception:
            pass

    def view_mouse_moved(self, view, event):
        global _last_mouse_update
        now = _now()
        if now - _last_mouse_update < 0.10:
            return
        _last_mouse_update = now
        try:
            _update_mouse(view, event, "move")
        except Exception:
            pass


if ida_hexrays is not None:
    class MonsteyHexraysHooks(ida_hexrays.Hexrays_Hooks):
        def __init__(self):
            ida_hexrays.Hexrays_Hooks.__init__(self)

        def curpos(self, vu):
            try:
                line = _current_line(vu.ct, False)
                ea = None
                try:
                    if vu.item and vu.item.is_citem():
                        ea = _fmt_ea(vu.item.e.ea)
                except Exception:
                    pass
                widget = _widget_info(vu.ct)
                _state["pseudocode_cursor"] = {
                    "time": round(_now(), 3),
                    "widget": widget,
                    "ea": ea,
                    "line": line[:700],
                    "cpos": {
                        "lnnum": int(vu.cpos.lnnum),
                        "x": int(vu.cpos.x),
                        "y": int(vu.cpos.y),
                    },
                    "highlight": _highlight(vu.ct),
                }
                _push_history("pseudocode_curpos", ea, widget, line)
            except Exception:
                pass
            return 0
else:
    MonsteyHexraysHooks = None


def install_navigation_hooks() -> bool:
    global _ui_hooks, _view_hooks, _hexrays_hooks, _key_filter
    ok = True
    if _ui_hooks is None:
        try:
            _ui_hooks = MonsteyUIHooks()
            ok = bool(_ui_hooks.hook()) and ok
        except Exception:
            ok = False
            _ui_hooks = None
    if _view_hooks is None:
        try:
            _view_hooks = MonsteyViewHooks()
            ok = bool(_view_hooks.hook()) and ok
        except Exception:
            ok = False
            _view_hooks = None
    if _hexrays_hooks is None and MonsteyHexraysHooks is not None:
        try:
            _hexrays_hooks = MonsteyHexraysHooks()
            ok = bool(_hexrays_hooks.hook()) and ok
        except Exception:
            _hexrays_hooks = None
    if _key_filter is None:
        try:
            app = QtWidgets.QApplication.instance()
            if app is not None:
                _key_filter = MonsteyKeyFilter()
                app.installEventFilter(_key_filter)
        except Exception:
            _key_filter = None
    try:
        ea = ida_kernwin.get_screen_ea()
        if int(ea) != int(idaapi.BADADDR):
            _update_screen(ea)
    except Exception:
        pass
    _state["installed"] = bool(_ui_hooks or _view_hooks or _hexrays_hooks)
    return ok


def uninstall_navigation_hooks() -> None:
    global _ui_hooks, _view_hooks, _hexrays_hooks, _key_filter
    try:
        app = QtWidgets.QApplication.instance()
        if app is not None and _key_filter is not None:
            app.removeEventFilter(_key_filter)
    except Exception:
        pass
    _key_filter = None
    for hook in (_hexrays_hooks, _view_hooks, _ui_hooks):
        try:
            if hook:
                hook.unhook()
        except Exception:
            pass
    _hexrays_hooks = None
    _view_hooks = None
    _ui_hooks = None
    _state["installed"] = False


def navigation_snapshot() -> Dict[str, Any]:
    install_navigation_hooks()
    now = _now()
    out = {
        "installed": bool(_state.get("installed")),
        "active_widget": dict(_state.get("active_widget") or {}),
        "screen": dict(_state.get("screen") or {}),
        "cursor": dict(_state.get("cursor") or {}),
        "mouse": dict(_state.get("mouse") or {}),
        "last_click": dict(_state.get("last_click") or {}),
        "pseudocode_cursor": dict(_state.get("pseudocode_cursor") or {}),
        "focus_lock": dict(_state.get("focus_lock") or {}),
        "history": list(_state.get("history") or [])[-12:],
    }
    for key in ("screen", "cursor", "mouse", "last_click", "pseudocode_cursor", "focus_lock"):
        item = out.get(key) or {}
        if item.get("time"):
            item["age_seconds"] = round(max(0.0, now - float(item["time"])), 3)
    return out


def preferred_focus_ea(snapshot: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    snap = snapshot or navigation_snapshot()
    return _preferred_focus_from_snapshot(snap, include_lock=True)
