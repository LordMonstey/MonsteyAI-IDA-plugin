"""Bootstrap loaded from idauser.idc when IDA does not enumerate Python plugins."""

from __future__ import annotations

import os
import sys
import traceback

import ida_kernwin


ACTION_NAME = "idalocalgameai:bootstrap_show"
PLUGIN_NAME = "MonsteyAI-IDA-plugin"


def _candidate_roots():
    roots = []
    here = os.path.dirname(os.path.abspath(__file__))
    if here:
        roots.append(here)
        roots.append(os.path.join(here, "Monstey-AI-plugin"))
        roots.append(os.path.dirname(here))

    appdata = os.environ.get("APPDATA")
    if appdata:
        user_plugins = os.path.join(appdata, "Hex-Rays", "IDA Pro", "plugins")
        roots.append(os.path.join(user_plugins, "Monstey-AI-plugin"))
        roots.append(user_plugins)

    try:
        import ida_diskio

        user_idadir = ida_diskio.get_user_idadir()
        if user_idadir:
            user_plugins = os.path.join(user_idadir, "plugins")
            roots.append(os.path.join(user_plugins, "Monstey-AI-plugin"))
            roots.append(user_plugins)
    except Exception:
        pass

    ida_dir = os.environ.get("IDADIR")
    if ida_dir:
        ida_plugins = os.path.join(ida_dir, "plugins")
        roots.append(os.path.join(ida_plugins, "Monstey-AI-plugin"))
        roots.append(ida_plugins)
    return roots


def _prepare_path():
    for root in _candidate_roots():
        if os.path.isdir(root) and root not in sys.path:
            sys.path.insert(0, root)


def _open_panel():
    _prepare_path()
    from idalocalgameai.ui.panel import show_panel

    show_panel()


class BootstrapAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            _open_panel()
        except Exception as exc:
            ida_kernwin.warning("%s failed to open:\n%s" % (PLUGIN_NAME, exc))
            ida_kernwin.msg("[%s] bootstrap error:\n%s\n" % (PLUGIN_NAME, traceback.format_exc()))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def install():
    try:
        _prepare_path()
        ida_kernwin.unregister_action(ACTION_NAME)
    except Exception:
        pass

    desc = ida_kernwin.action_desc_t(
        ACTION_NAME,
        PLUGIN_NAME,
        BootstrapAction(),
        "Ctrl+Alt+G",
        "Open %s" % PLUGIN_NAME,
        -1,
    )
    ok = ida_kernwin.register_action(desc)
    try:
        ida_kernwin.attach_action_to_menu("Edit/Plugins/", ACTION_NAME, ida_kernwin.SETMENU_APP)
    except Exception:
        pass
    ida_kernwin.msg("[%s] idauser bootstrap installed (action=%s). Use Ctrl+Alt+G.\n" % (PLUGIN_NAME, ok))


install()
