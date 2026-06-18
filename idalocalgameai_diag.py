"""Minimal diagnostic plugin for IDA Python plugin loading."""

from __future__ import annotations

import ida_idaapi
import ida_kernwin


class DiagPlugmod(ida_idaapi.plugmod_t):
    def run(self, arg):
        ida_kernwin.info("AI Plugin Diagnostic loaded and executed.")


class DiagPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Diagnostic Python plugin for MonsteyAI-IDA-plugin"
    help = "Verifies that IDA can load Python plugins"
    wanted_name = "AI Plugin Diagnostic"
    wanted_hotkey = "Ctrl-Alt-D"

    def init(self):
        ida_kernwin.msg("[AI Plugin Diagnostic] init ok\n")
        return DiagPlugmod()


def PLUGIN_ENTRY():
    return DiagPlugin()
