"""IDA entry point for MonsteyAI-IDA-plugin."""

from __future__ import annotations

import os
import sys

import ida_idaapi
import ida_kernwin

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

try:
    from idalocalgameai import PLUGIN_NAME
except Exception:
    PLUGIN_NAME = "MonsteyAI-IDA-plugin"


ACTION_NAME = "idalocalgameai:show"
ACTION_ANALYZE_SELECTION = "idalocalgameai:analyze_selection"
ACTION_RECONSTRUCT_PSEUDO = "idalocalgameai:reconstruct_pseudocode"
_popup_hooks = None


def _supported_popup_widget(widget_type):
    return widget_type in (
        getattr(ida_kernwin, "BWN_DISASM", -1),
        getattr(ida_kernwin, "BWN_PSEUDOCODE", -1),
        getattr(ida_kernwin, "BWN_HEXVIEW", -1),
        getattr(ida_kernwin, "BWN_CUSTVIEW", -1),
    )


def open_panel():
    try:
        from idalocalgameai.ui.panel import show_panel

        show_panel()
    except Exception as exc:
        ida_kernwin.warning("%s failed to open:\n%s" % (PLUGIN_NAME, exc))
        ida_kernwin.msg("[%s] UI error: %s\n" % (PLUGIN_NAME, exc))


class ShowPanelAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        open_panel()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class AnalyzeSelectionAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            from idalocalgameai.ui.panel import analyze_focus

            analyze_focus(force_asm=True)
        except Exception as exc:
            ida_kernwin.warning("MonsteyAI-Analyse failed:\n%s" % exc)
            ida_kernwin.msg("[%s] MonsteyAI-Analyse error: %s\n" % (PLUGIN_NAME, exc))
        return 1

    def update(self, ctx):
        widget_type = getattr(ctx, "widget_type", None)
        if _supported_popup_widget(widget_type):
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class ReconstructPseudocodeAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            from idalocalgameai.ui.panel import reconstruct_focus_pseudocode

            reconstruct_focus_pseudocode()
        except Exception as exc:
            ida_kernwin.warning("MonsteyAI-Rebuild Pseudocode failed:\n%s" % exc)
            ida_kernwin.msg("[%s] MonsteyAI-Rebuild Pseudocode error: %s\n" % (PLUGIN_NAME, exc))
        return 1

    def update(self, ctx):
        widget_type = getattr(ctx, "widget_type", None)
        if _supported_popup_widget(widget_type):
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class MonsteyPopupHooks(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

    def populating_widget_popup(self, widget, popup_handle, ctx):
        try:
            if _supported_popup_widget(getattr(ctx, "widget_type", None)):
                ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_ANALYZE_SELECTION, None)
                ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_RECONSTRUCT_PSEUDO, None)
        except Exception:
            pass


class IDALocalGameAIPlugmod(ida_idaapi.plugmod_t):
    def run(self, arg):
        open_panel()


class IDALocalGameAIPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Local AI assistant for game-modding reverse engineering"
    help = "Local AI assistant for IDA Pro + Hex-Rays"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl+Alt+G"

    def init(self):
        global _popup_hooks
        try:
            from idalocalgameai.navigation import install_navigation_hooks

            install_navigation_hooks()
        except Exception as exc:
            ida_kernwin.msg("[%s] Navigation hooks unavailable: %s\n" % (PLUGIN_NAME, exc))
        desc = ida_kernwin.action_desc_t(
            ACTION_NAME,
            PLUGIN_NAME,
            ShowPanelAction(),
            self.wanted_hotkey,
            "Open %s" % PLUGIN_NAME,
            -1,
        )
        ida_kernwin.register_action(desc)
        analyze_desc = ida_kernwin.action_desc_t(
            ACTION_ANALYZE_SELECTION,
            "MonsteyAI-Analyse",
            AnalyzeSelectionAction(),
            "",
            "Analyze current IDA selection or focused instruction with %s" % PLUGIN_NAME,
            -1,
        )
        ida_kernwin.register_action(analyze_desc)
        rebuild_desc = ida_kernwin.action_desc_t(
            ACTION_RECONSTRUCT_PSEUDO,
            "MonsteyAI-Rebuild Pseudocode",
            ReconstructPseudocodeAction(),
            "",
            "Capture current IDA selection/focus and rebuild approximate pseudo-C from assembly",
            -1,
        )
        ida_kernwin.register_action(rebuild_desc)
        if _popup_hooks is None:
            _popup_hooks = MonsteyPopupHooks()
            _popup_hooks.hook()
        ida_kernwin.attach_action_to_menu("Edit/Plugins/", ACTION_NAME, ida_kernwin.SETMENU_APP)
        ida_kernwin.msg("[%s] Loaded. Use Ctrl+Alt+G or Edit > Plugins.\n" % PLUGIN_NAME)
        return IDALocalGameAIPlugmod()

    def term(self):
        global _popup_hooks
        try:
            from idalocalgameai.navigation import uninstall_navigation_hooks

            uninstall_navigation_hooks()
        except Exception:
            pass
        try:
            if _popup_hooks is not None:
                _popup_hooks.unhook()
                _popup_hooks = None
        except Exception:
            pass
        try:
            ida_kernwin.unregister_action(ACTION_NAME)
        except Exception:
            pass
        try:
            ida_kernwin.unregister_action(ACTION_ANALYZE_SELECTION)
        except Exception:
            pass
        try:
            ida_kernwin.unregister_action(ACTION_RECONSTRUCT_PSEUDO)
        except Exception:
            pass


def PLUGIN_ENTRY():
    return IDALocalGameAIPlugin()
