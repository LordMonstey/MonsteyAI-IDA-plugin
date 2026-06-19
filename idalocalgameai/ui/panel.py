"""Dockable IDA UI for MonsteyAI-IDA-plugin."""

from __future__ import annotations

import html
import json
import os
import re
import time
import traceback
from typing import Any, Dict, Optional

import ida_kernwin
import ida_name
import ida_idp
import idaapi

from .. import PLUGIN_NAME, PLUGIN_VERSION
from ..analysis_policy import agent_policy, model_policy, watchdog_seconds
from ..apply import apply_colored_annotations, apply_function_name, mark_review_item, refresh_ida
from ..asm_pseudocode import attach_reconstruction_to_context, reconstruct_pseudocode_from_context, render_asm_source
from ..compat.qt import QT_BINDING, QtCore, QtGui, QtWidgets
from ..config import GEMINI_MODEL_PRESETS, MODEL_PRESETS, PluginConfig, config_dir, config_path, load_config, save_config
from ..dump_context import dump_context_path, dump_context_payload, load_dump_context, save_dump_context
from ..external_evidence import (
    apply_external_evidence_to_analysis,
    external_evidence_path,
    external_evidence_payload,
    load_external_evidence,
    render_external_evidence_text,
    save_external_evidence,
    template_text as external_evidence_template_text,
)
from ..focus_marker import clear_focus_marker, parse_ea as parse_focus_ea, set_focus_marker
from ..game_profiles import profile_names
from ..ida_context import collect_context, database_context
from ..integrations import (
    INTEGRATION_PRESETS,
    build_all_local_scouts_text,
    build_signature_scout_text,
    build_structure_scout_text,
    integration_template_text,
    normalize_integration_text,
    render_integration_preview,
)
from ..memory import (
    clear_review_marks,
    game_map_path,
    load_game_map,
    prompt_memory,
    remove_review_mark,
    render_game_map,
    sorted_review_marks,
    upsert_analysis,
    upsert_feedback,
    upsert_review_mark,
)
from ..navigation import clear_focus_lock, install_navigation_hooks, navigation_snapshot, preferred_focus_ea
from ..pseudodiff import local_pseudocode_diff, render_local_pseudocode_diff_text
from ..prompts import compact_analysis_context
from ..sanitize import append_block, read_text_file_safely, sanitize_label, sanitize_text
from ..schemas import normalize_analysis, validate_function_name
from ..enrichment import enrich_analysis_with_local_cues
from ..trainer_intel import build_trainer_intel
from ..workers import (
    ActionWorker,
    LLMWorker,
    PseudoDiffWorker,
    TestLLMWorker,
    ToolchainWorker,
    ensure_function_questions,
    ensure_user_context_alignment,
)


PANEL_STYLE = """
QWidget#IDALocalGameAIWidget {
    background: #202124;
    color: #eceff4;
}
QLabel {
    color: #eceff4;
}
QLabel#SubsectionLabel {
    color: #9bd7ff;
    font-weight: 700;
    padding-top: 7px;
}
QPushButton {
    background: #2f343a;
    color: #f4f7fb;
    border: 1px solid #49515a;
    border-radius: 4px;
    padding: 5px 9px;
}
QPushButton:hover {
    background: #3a4650;
    border-color: #62c7d8;
}
QPushButton:pressed {
    background: #24343a;
}
QPushButton:disabled {
    color: #737b84;
    background: #25282c;
    border-color: #343940;
}
QTabWidget::pane {
    border: 1px solid #3a4048;
    background: #24272b;
}
QTabBar::tab {
    background: #2b3036;
    color: #d5dbe3;
    padding: 5px 10px;
    border: 1px solid #3a4048;
}
QTabBar::tab:selected {
    background: #32404a;
    color: #ffffff;
    border-bottom-color: #62c7d8;
}
QPlainTextEdit, QTextBrowser, QTextEdit, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QTableWidget {
    background: #1b1d20;
    color: #edf1f5;
    border: 1px solid #3b424a;
    selection-background-color: #28566a;
    selection-color: #ffffff;
}
QHeaderView::section {
    background: #30363d;
    color: #ffffff;
    border: 1px solid #454c54;
    padding: 4px;
}
QTableWidget::item {
    padding: 3px;
}
"""

KIND_COLORS = {
    "asm": ("#2b3540", "#9bd7ff"),
    "call": ("#283a30", "#9af2b2"),
    "xref": ("#362f45", "#d2b6ff"),
    "string": ("#3f3524", "#ffd58a"),
    "import": ("#2e3d3c", "#98f0df"),
    "pseudocode": ("#303845", "#b8d6ff"),
    "constant": ("#3c3038", "#f0a7c6"),
    "candidate": ("#24382b", "#9af2b2"),
    "experiment": ("#263640", "#9bd7ff"),
    "structure": ("#3c3038", "#f0a7c6"),
    "external_diff": ("#3a3323", "#ffd58a"),
    "external_capability": ("#263640", "#9bd7ff"),
    "external_signature": ("#2e3d3c", "#98f0df"),
    "external_crypto_signature": ("#3c3038", "#f0a7c6"),
    "external_deobf": ("#362f45", "#d2b6ff"),
    "external_structure": ("#303845", "#b8d6ff"),
    "external_xref": ("#362f45", "#d2b6ff"),
    "external_string": ("#3f3524", "#ffd58a"),
    "external_note": ("#303234", "#d7dde5"),
    "note": ("#303234", "#d7dde5"),
}


IDB_HOOKS_BASE = getattr(ida_idp, "IDB_Hooks", object)


def info(message: str) -> None:
    try:
        ida_kernwin.msg("[%s] %s\n" % (PLUGIN_NAME, message))
    except Exception:
        pass


class DebugTraceDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("%s - Analysis Debug Trace" % PLUGIN_NAME)
        self.resize(980, 440)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        self.trace_browser = QtWidgets.QTextBrowser()
        self.trace_browser.setReadOnly(True)
        self.trace_browser.setOpenExternalLinks(False)
        self.trace_browser.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard
        )
        toolbar = QtWidgets.QHBoxLayout()
        self.copy_button = QtWidgets.QPushButton("Copy Debug Trace")
        self.close_button = QtWidgets.QPushButton("Hide")
        self.copy_button.clicked.connect(self.copy_trace)
        self.close_button.clicked.connect(self.hide)
        toolbar.addStretch(1)
        toolbar.addWidget(self.copy_button)
        toolbar.addWidget(self.close_button)
        layout.addWidget(self.trace_browser, 1)
        layout.addLayout(toolbar)

    def set_trace_html(self, text: str) -> None:
        self.trace_browser.setHtml(text)

    def copy_trace(self) -> None:
        QtWidgets.QApplication.clipboard().setText(self.trace_browser.toPlainText())

    def closeEvent(self, event) -> None:
        event.ignore()
        self.hide()


class TrainerRadarDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("%s - Trainer Radar" % PLUGIN_NAME)
        self.resize(1080, 680)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        self.browser = QtWidgets.QTextBrowser()
        self.browser.setReadOnly(True)
        self.browser.setOpenExternalLinks(False)
        self.browser.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard
        )
        toolbar = QtWidgets.QHBoxLayout()
        self.copy_button = QtWidgets.QPushButton("Copy Trainer Radar")
        self.close_button = QtWidgets.QPushButton("Hide")
        self.copy_button.clicked.connect(self.copy_text)
        self.close_button.clicked.connect(self.hide)
        toolbar.addStretch(1)
        toolbar.addWidget(self.copy_button)
        toolbar.addWidget(self.close_button)
        layout.addWidget(self.browser, 1)
        layout.addLayout(toolbar)

    def set_radar_html(self, text: str) -> None:
        self.browser.setHtml(text)

    def copy_text(self) -> None:
        QtWidgets.QApplication.clipboard().setText(self.browser.toPlainText())

    def closeEvent(self, event) -> None:
        event.ignore()
        self.hide()


class MonsteyMadeOverlay(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents, True)
        self.setAttribute(QtCore.Qt.WA_StyledBackground, True)
        self.setStyleSheet(
            "QWidget#MonsteyMadeOverlay {"
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #101317, stop:1 #1f2933);"
            "border: 1px solid #425468;"
            "}"
            "QLabel#MadeKicker { color:#80ffb0; font-size:13px; font-weight:700; letter-spacing:0px; }"
            "QLabel#MadeTitle { color:#f7fbff; font-size:28px; font-weight:900; letter-spacing:0px; }"
            "QLabel#MadeSub { color:#aeb9c5; font-size:12px; font-weight:600; }"
        )
        self.setObjectName("MonsteyMadeOverlay")
        self.opacity_effect = QtWidgets.QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        self.opacity_effect.setOpacity(0.0)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.addStretch(1)
        kicker = QtWidgets.QLabel("MONSTEY IDA SYMBIOTE")
        kicker.setObjectName("MadeKicker")
        kicker.setAlignment(QtCore.Qt.AlignCenter)
        title = QtWidgets.QLabel("LordMonstey Made That")
        title.setObjectName("MadeTitle")
        title.setAlignment(QtCore.Qt.AlignCenter)
        subtitle = QtWidgets.QLabel("focus-aware reverse engineering | evidence packs | trainer radar")
        subtitle.setObjectName("MadeSub")
        subtitle.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(kicker)
        layout.addWidget(title)
        layout.addSpacing(6)
        layout.addWidget(subtitle)
        layout.addStretch(1)
        self.anim = QtCore.QSequentialAnimationGroup(self)
        fade_in = QtCore.QPropertyAnimation(self.opacity_effect, b"opacity")
        fade_in.setDuration(280)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(0.96)
        fade_in.setEasingCurve(QtCore.QEasingCurve.OutCubic)
        pause = QtCore.QPauseAnimation(850)
        fade_out = QtCore.QPropertyAnimation(self.opacity_effect, b"opacity")
        fade_out.setDuration(620)
        fade_out.setStartValue(0.96)
        fade_out.setEndValue(0.0)
        fade_out.setEasingCurve(QtCore.QEasingCurve.InOutCubic)
        self.anim.addAnimation(fade_in)
        self.anim.addAnimation(pause)
        self.anim.addAnimation(fade_out)
        self.anim.finished.connect(self.hide)

    def play(self) -> None:
        parent = self.parentWidget()
        if parent is not None:
            self.setGeometry(parent.rect())
        self.raise_()
        self.show()
        self.anim.stop()
        self.opacity_effect.setOpacity(0.0)
        self.anim.start()


class StatusToast(QtWidgets.QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents, True)
        self.setObjectName("MonsteyStatusToast")
        self.setStyleSheet(
            "QFrame#MonsteyStatusToast { background:#11161b; border:1px solid #40505f; border-radius:6px; }"
            "QLabel { color:#edf1f5; font-weight:700; padding:7px 10px; }"
        )
        self.opacity_effect = QtWidgets.QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        self.opacity_effect.setOpacity(0.0)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.label = QtWidgets.QLabel("")
        self.label.setTextFormat(QtCore.Qt.RichText)
        layout.addWidget(self.label)
        self.anim = QtCore.QSequentialAnimationGroup(self)
        fade_in = QtCore.QPropertyAnimation(self.opacity_effect, b"opacity")
        fade_in.setDuration(130)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(0.96)
        pause = QtCore.QPauseAnimation(1450)
        fade_out = QtCore.QPropertyAnimation(self.opacity_effect, b"opacity")
        fade_out.setDuration(340)
        fade_out.setStartValue(0.96)
        fade_out.setEndValue(0.0)
        self.anim.addAnimation(fade_in)
        self.anim.addAnimation(pause)
        self.anim.addAnimation(fade_out)
        self.anim.finished.connect(self.hide)
        self.hide()

    def show_message(self, message: str, ok: bool = True) -> None:
        safe = html.escape(sanitize_text(message, max_chars=180, collapse_ws=True))
        color = "#8df29b" if ok else "#ff9f9f"
        self.label.setText("<span style='color:%s;'>%s</span>" % (color, safe))
        self.adjustSize()
        self.reposition()
        self.raise_()
        self.show()
        self.anim.stop()
        self.opacity_effect.setOpacity(0.0)
        self.anim.start()

    def reposition(self) -> None:
        parent = self.parentWidget()
        if parent is not None:
            margin = 14
            width = min(max(self.sizeHint().width(), 240), max(260, parent.width() - 40))
            height = self.sizeHint().height()
            self.resize(width, height)
            self.move(max(margin, parent.width() - width - margin), max(margin, parent.height() - height - margin))


class MonsteyIDBHooks(IDB_HOOKS_BASE):
    def __init__(self, panel):
        try:
            IDB_HOOKS_BASE.__init__(self)
        except Exception:
            pass
        self.panel = panel

    def renamed(self, *args):
        try:
            ea = args[0] if args else None
            new_name = args[1] if len(args) > 1 else ""
            self.panel._schedule_idb_rename_refresh(ea, new_name)
        except Exception:
            pass
        return 0


class MainWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        install_navigation_hooks()
        self.cfg: PluginConfig = load_config()
        self.visible_provider = self.cfg.provider
        self._settings_loading = False
        self.current_context: Optional[Dict[str, Any]] = None
        self.current_analysis: Optional[Dict[str, Any]] = None
        self.rebuild_context: Optional[Dict[str, Any]] = None
        self.rebuild_result: Optional[Dict[str, Any]] = None
        self.worker = None
        self.analysis_run_id = 0
        self.analysis_log_active = False
        self.analysis_log_lines = []
        self.analysis_started_at = 0.0
        self.analysis_log_last_tick = -1
        self.analysis_timeout_last_warn = -1
        self.focus_highlight_enabled = True
        self._last_focus_marker_ea = None
        self.analysis_debug_timer = QtCore.QTimer(self)
        self.analysis_debug_timer.setInterval(1000)
        self.analysis_debug_timer.timeout.connect(self._analysis_debug_tick)
        self.pipeline_pulse = 0
        self.pipeline_timer = QtCore.QTimer(self)
        self.pipeline_timer.setInterval(360)
        self.pipeline_timer.timeout.connect(self._pipeline_tick)
        self.focus_indicator_timer = QtCore.QTimer(self)
        self.focus_indicator_timer.setInterval(350)
        self.focus_indicator_timer.timeout.connect(self._refresh_focus_indicator)
        self.debug_dialog = None
        self.trainer_radar_dialog = None
        self.idb_hooks = MonsteyIDBHooks(self)
        try:
            self.idb_hooks.hook()
        except Exception as exc:
            info("IDB rename hook unavailable: %s" % exc)
            self.idb_hooks = None
        self.last_summary_text = ""
        self.test_worker = None
        self.action_worker = None
        self.pseudodiff_worker = None
        self.toolchain_worker = None
        self.current_action_kind: Optional[str] = None
        self.action_history = ""
        self.last_action_code = ""
        self.pipeline_labels = {}
        self.pipeline_state = {}
        self._build_ui()
        self.focus_indicator_timer.start()
        self._refresh_focus_indicator()
        self._load_settings_into_ui()
        self._load_dump_context_into_ui()
        self._load_external_evidence_into_ui()
        self._refresh_game_map()
        self._refresh_review_queue()
        self._set_status("Ready", ok=True)
        self.made_overlay = MonsteyMadeOverlay(self)
        self.made_overlay.hide()
        self.toast = StatusToast(self)
        QtCore.QTimer.singleShot(260, self._show_made_overlay)

    def _build_ui(self) -> None:
        self.setObjectName("IDALocalGameAIWidget")
        self.setStyleSheet(PANEL_STYLE)
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        header = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel(
            "<span style='color:#f6f8fb;'>MonsteyAI IDA</span> "
            "<span style='color:#8a929c;'>v%s</span> "
            "<span style='color:#80ffb0; font-size:11px; font-weight:800;'>LordMonstey Made</span>"
            % html.escape(str(PLUGIN_VERSION))
        )
        title.setTextFormat(QtCore.Qt.RichText)
        title_font = QtGui.QFont()
        title_font.setBold(True)
        title.setFont(title_font)
        self.game_label = QtWidgets.QLabel("Process: unknown")
        self.game_label.setTextFormat(QtCore.Qt.PlainText)
        self.game_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.game_label.setStyleSheet("color:#ffd58a; font-weight:600;")
        self.automation_label = QtWidgets.QLabel("")
        self.automation_label.setTextFormat(QtCore.Qt.PlainText)
        self.automation_label.setStyleSheet("color:#9af2b2; font-weight:600;")
        self.automation_label.setToolTip("Shows which automatic IDA apply actions are enabled.")
        self.status_label = QtWidgets.QLabel("")
        self.status_label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        header.addWidget(title, 1)
        header.addWidget(self.game_label, 2)
        header.addWidget(self.automation_label, 1)
        header.addWidget(self.status_label, 1)
        root.addLayout(header)

        focus_row = QtWidgets.QHBoxLayout()
        focus_row.setSpacing(6)
        self.focus_indicator_label = QtWidgets.QLabel("AI focus: none")
        self.focus_indicator_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.focus_indicator_label.setToolTip("Live IDA focus used by Analyze buttons. Hover/click in IDA to move it.")
        self.focus_indicator_label.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        self.focus_highlight_check = QtWidgets.QCheckBox("Highlight in IDA")
        self.focus_highlight_check.setChecked(True)
        self.focus_highlight_check.setToolTip("Temporarily colors the item currently used as AI focus. The previous color is restored when focus moves.")
        self.focus_highlight_check.toggled.connect(self._on_focus_highlight_toggled)
        self.btn_jump_focus = QtWidgets.QPushButton("Jump")
        self.btn_jump_focus.setMaximumWidth(72)
        self.btn_jump_focus.setToolTip("Jump to the current AI focus address.")
        self.btn_jump_focus.clicked.connect(self._jump_to_ai_focus)
        self.btn_mark_review = QtWidgets.QPushButton("Mark Review")
        self.btn_mark_review.setMaximumWidth(102)
        self.btn_mark_review.setToolTip("Write a Monstey review comment and color marker at the current AI focus in IDA.")
        self.btn_mark_review.clicked.connect(self._mark_ai_focus_review)
        focus_row.addWidget(self.focus_indicator_label, 1)
        focus_row.addWidget(self.focus_highlight_check)
        focus_row.addWidget(self.btn_jump_focus)
        focus_row.addWidget(self.btn_mark_review)
        root.addLayout(focus_row)

        controls = QtWidgets.QHBoxLayout()
        self.btn_analyze_func = QtWidgets.QPushButton("Analyze Focus Function")
        self.btn_analyze_asm = QtWidgets.QPushButton("Analyze Focus ASM/Red")
        self.btn_rebuild_pseudo = QtWidgets.QPushButton("Rebuild ASM -> Pseudo")
        self.btn_quick_local = QtWidgets.QPushButton("Quick Local Pass")
        self.btn_preview_focus = QtWidgets.QPushButton("Preview Focus")
        self.btn_test_llm = QtWidgets.QPushButton("Test LLM")
        self.btn_analyze_func.setToolTip("Uses the recent mouse hover/click, pseudocode cursor, view cursor, then screen EA.")
        self.btn_analyze_asm.setToolTip("Uses selection when available, otherwise the focused function or a local window around the focused address.")
        self.btn_rebuild_pseudo.setToolTip("Capture selected/focused ASM or red code and build an approximate pseudo-C view before AI analysis.")
        self.btn_quick_local.setToolTip("No LLM call. Uses local IDA semantic cues for a fast trainer/mapping pass.")
        self.btn_preview_focus.setToolTip("Shows the current navigation snapshot without calling the LLM.")
        self.btn_analyze_func.clicked.connect(lambda checked=False: self._start_analysis_safely(force_asm=False))
        self.btn_analyze_asm.clicked.connect(lambda checked=False: self._start_analysis_safely(force_asm=True))
        self.btn_rebuild_pseudo.clicked.connect(self._capture_asm_reconstruction)
        self.btn_quick_local.clicked.connect(lambda checked=False: self._start_analysis_safely(force_asm=True, local_only=True))
        self.btn_preview_focus.clicked.connect(self._preview_focus)
        self.btn_test_llm.clicked.connect(self._test_llm)
        controls.addWidget(self.btn_analyze_func)
        controls.addWidget(self.btn_analyze_asm)
        controls.addWidget(self.btn_rebuild_pseudo)
        controls.addWidget(self.btn_quick_local)
        controls.addWidget(self.btn_preview_focus)
        controls.addWidget(self.btn_test_llm)
        root.addLayout(controls)

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(self._build_function_tab(), "Function")
        self.tabs.addTab(self._build_pseudo_rebuild_tab(), "Pseudo Rebuild")
        self.tabs.addTab(self._build_review_queue_tab(), "Review Queue")
        self.tabs.addTab(self._build_dump_context_tab(), "Dump Context")
        self.tabs.addTab(self._build_external_evidence_tab(), "Evidence Sources")
        self.tabs.addTab(self._build_integrations_tab(), "Integrations")
        self.tabs.addTab(self._build_action_tab(), "Action Lab")
        self.tabs.addTab(self._build_feedback_tab(), "Feedback")
        self.tabs.addTab(self._build_pseudodiff_tab(), "Pseudo Diff")
        self.tabs.addTab(self._build_game_map_tab(), "Process Map")
        self.tabs.addTab(self._build_settings_tab(), "Settings")
        root.addWidget(self.tabs, 1)

    def _build_function_tab(self) -> QtWidgets.QWidget:
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        self.context_label = QtWidgets.QLabel("No analysis yet")
        self.context_label.setTextFormat(QtCore.Qt.PlainText)
        self.context_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        layout.addWidget(self.context_label)

        self.pipeline_frame = QtWidgets.QFrame()
        self.pipeline_frame.setObjectName("AnalysisPipeline")
        self.pipeline_frame.setStyleSheet(
            "QFrame#AnalysisPipeline { background:#181d22; border:1px solid #303943; border-radius:6px; }"
        )
        pipeline_layout = QtWidgets.QHBoxLayout(self.pipeline_frame)
        pipeline_layout.setContentsMargins(8, 5, 8, 5)
        pipeline_layout.setSpacing(5)
        self.pipeline_labels = {}
        for key, label in [
            ("focus", "Focus"),
            ("context", "Context"),
            ("evidence", "Evidence"),
            ("provider", "Provider"),
            ("llm", "LLM"),
            ("parse", "Parse"),
            ("enrich", "Enrich"),
            ("ready", "Ready"),
        ]:
            chip = QtWidgets.QLabel(label)
            chip.setAlignment(QtCore.Qt.AlignCenter)
            chip.setMinimumWidth(72)
            chip.setToolTip("Analysis pipeline step: %s" % label)
            self.pipeline_labels[key] = chip
            pipeline_layout.addWidget(chip)
        pipeline_layout.addStretch(1)
        layout.addWidget(self.pipeline_frame)
        self._reset_pipeline()

        action_row = QtWidgets.QHBoxLayout()
        self.btn_apply_name = QtWidgets.QPushButton("Apply Name")
        self.btn_apply_comments = QtWidgets.QPushButton("Apply Comments + Colors")
        self.btn_copy_summary = QtWidgets.QPushButton("Copy Summary")
        self.btn_debug_trace = QtWidgets.QPushButton("Debug Trace")
        self.btn_trainer_radar = QtWidgets.QPushButton("Trainer Radar")
        self.btn_apply_name.setToolTip("Manually apply the current suggested_function_name.")
        self.btn_apply_comments.setToolTip("Manually apply bounded AI comments and item colors to the IDA listing.")
        self.btn_copy_summary.setToolTip("Copy the visible analysis summary as plain text.")
        self.btn_debug_trace.setToolTip("Open the dedicated live processing/debug trace window.")
        self.btn_trainer_radar.setToolTip("Open the dedicated trainer/modding decision radar window.")
        self.btn_apply_name.setEnabled(False)
        self.btn_apply_comments.setEnabled(False)
        self.btn_copy_summary.setEnabled(False)
        self.btn_trainer_radar.setEnabled(False)
        self.btn_apply_name.clicked.connect(self._apply_name)
        self.btn_apply_comments.clicked.connect(self._apply_comments)
        self.btn_copy_summary.clicked.connect(self._copy_summary)
        self.btn_debug_trace.clicked.connect(self._show_debug_trace)
        self.btn_trainer_radar.clicked.connect(self._show_trainer_radar)
        self.btn_call_returns = QtWidgets.QPushButton("Lets call it and see the returns")
        self.btn_hook_modify = QtWidgets.QPushButton("Lets hook it and modify something")
        self.btn_call_returns.setToolTip("Open Action Lab with a __fastcall call/logging plan.")
        self.btn_hook_modify.setToolTip("Open Action Lab with a MinHook-style hook/modification plan.")
        self.btn_call_returns.setEnabled(False)
        self.btn_hook_modify.setEnabled(False)
        self.btn_call_returns.clicked.connect(lambda: self._open_action_lab("call"))
        self.btn_hook_modify.clicked.connect(lambda: self._open_action_lab("hook"))
        action_row.addWidget(self.btn_apply_name)
        action_row.addWidget(self.btn_apply_comments)
        action_row.addWidget(self.btn_copy_summary)
        action_row.addWidget(self.btn_debug_trace)
        action_row.addWidget(self.btn_trainer_radar)
        action_row.addWidget(self.btn_call_returns)
        action_row.addWidget(self.btn_hook_modify)
        action_row.addStretch(1)
        layout.addLayout(action_row)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        self.summary_edit = QtWidgets.QTextBrowser()
        self.summary_edit.setReadOnly(True)
        self.summary_edit.setOpenExternalLinks(False)
        self.summary_edit.setOpenLinks(False)
        self.summary_edit.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard
            | QtCore.Qt.LinksAccessibleByMouse | QtCore.Qt.LinksAccessibleByKeyboard
        )
        self.summary_edit.anchorClicked.connect(self._on_summary_anchor_clicked)
        self.summary_edit.setPlaceholderText("Analysis summary")

        self.evidence_table = QtWidgets.QTableWidget(0, 3)
        self.evidence_table.setHorizontalHeaderLabels(["Kind", "Address", "Text"])
        self.evidence_table.horizontalHeader().setStretchLastSection(True)
        self.evidence_table.verticalHeader().setVisible(False)
        self.evidence_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.evidence_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.evidence_table.setAlternatingRowColors(True)
        self.evidence_table.cellClicked.connect(self._on_evidence_cell_clicked)
        self.evidence_table.cellDoubleClicked.connect(self._on_evidence_cell_double_clicked)

        self.raw_edit = QtWidgets.QPlainTextEdit()
        self.raw_edit.setReadOnly(True)
        self.raw_edit.setPlaceholderText("Raw JSON")

        splitter.addWidget(self.summary_edit)
        splitter.addWidget(self.evidence_table)
        splitter.addWidget(self.raw_edit)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setStretchFactor(2, 2)
        layout.addWidget(splitter, 1)
        return tab

    def _build_pseudo_rebuild_tab(self) -> QtWidgets.QWidget:
        tab = QtWidgets.QWidget()
        self.pseudo_rebuild_tab = tab
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(7)

        header = QtWidgets.QFrame()
        header.setObjectName("PseudoRebuildHeader")
        header.setStyleSheet(
            "QFrame#PseudoRebuildHeader { background:#181d22; border:1px solid #303943; border-radius:6px; }"
        )
        header_layout = QtWidgets.QHBoxLayout(header)
        header_layout.setContentsMargins(9, 7, 9, 7)
        self.pseudo_rebuild_status_label = QtWidgets.QLabel(
            "Capture selected or focused ASM/red code to build approximate pseudo-C."
        )
        self.pseudo_rebuild_status_label.setTextFormat(QtCore.Qt.PlainText)
        self.pseudo_rebuild_status_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.pseudo_rebuild_status_label.setStyleSheet("color:#b8d6ff; font-weight:600;")
        self.pseudo_rebuild_conf_label = QtWidgets.QLabel("Ready")
        self.pseudo_rebuild_conf_label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        self.pseudo_rebuild_conf_label.setStyleSheet("color:#9af2b2; font-weight:700;")
        header_layout.addWidget(self.pseudo_rebuild_status_label, 1)
        header_layout.addWidget(self.pseudo_rebuild_conf_label)
        layout.addWidget(header)

        toolbar = QtWidgets.QHBoxLayout()
        self.btn_pseudo_rebuild_capture = QtWidgets.QPushButton("Capture ASM/Red -> Pseudo")
        self.btn_pseudo_rebuild_analyze = QtWidgets.QPushButton("Analyze Generated Pseudo")
        self.btn_pseudo_rebuild_local = QtWidgets.QPushButton("Quick Local Pass")
        self.btn_pseudo_rebuild_copy = QtWidgets.QPushButton("Copy Pseudocode")
        self.btn_pseudo_rebuild_capture.setToolTip("Collect the current selection/focus from IDA and rebuild approximate pseudo-C from its assembly rows.")
        self.btn_pseudo_rebuild_analyze.setToolTip("Send this generated pseudo-C plus original ASM evidence to the selected LLM provider.")
        self.btn_pseudo_rebuild_local.setToolTip("Analyze the generated pseudo-C with the local deterministic pass only.")
        self.btn_pseudo_rebuild_copy.setToolTip("Copy the generated pseudo-C to clipboard.")
        self.btn_pseudo_rebuild_capture.clicked.connect(self._capture_asm_reconstruction)
        self.btn_pseudo_rebuild_analyze.clicked.connect(lambda checked=False: self._analyze_reconstructed_pseudocode(local_only=False))
        self.btn_pseudo_rebuild_local.clicked.connect(lambda checked=False: self._analyze_reconstructed_pseudocode(local_only=True))
        self.btn_pseudo_rebuild_copy.clicked.connect(self._copy_rebuild_pseudocode)
        self.btn_pseudo_rebuild_analyze.setEnabled(False)
        self.btn_pseudo_rebuild_local.setEnabled(False)
        self.btn_pseudo_rebuild_copy.setEnabled(False)
        toolbar.addWidget(self.btn_pseudo_rebuild_capture)
        toolbar.addWidget(self.btn_pseudo_rebuild_analyze)
        toolbar.addWidget(self.btn_pseudo_rebuild_local)
        toolbar.addWidget(self.btn_pseudo_rebuild_copy)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        asm_panel = QtWidgets.QWidget()
        asm_layout = QtWidgets.QVBoxLayout(asm_panel)
        asm_layout.setContentsMargins(0, 0, 0, 0)
        asm_label = QtWidgets.QLabel("Captured ASM evidence")
        asm_label.setStyleSheet("color:#ffd58a; font-weight:700;")
        self.pseudo_rebuild_asm_edit = QtWidgets.QPlainTextEdit()
        self.pseudo_rebuild_asm_edit.setReadOnly(True)
        self.pseudo_rebuild_asm_edit.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self.pseudo_rebuild_asm_edit.setPlaceholderText("IDA assembly capture appears here.")

        pseudo_panel = QtWidgets.QWidget()
        pseudo_layout = QtWidgets.QVBoxLayout(pseudo_panel)
        pseudo_layout.setContentsMargins(0, 0, 0, 0)
        pseudo_label = QtWidgets.QLabel("Generated pseudo-C workspace")
        pseudo_label.setStyleSheet("color:#9af2b2; font-weight:700;")
        self.pseudo_rebuild_edit = QtWidgets.QPlainTextEdit()
        self.pseudo_rebuild_edit.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self.pseudo_rebuild_edit.setPlaceholderText("Approximate pseudo-C generated from ASM appears here. You can edit it before analysis.")

        code_font = QtGui.QFont("Consolas")
        code_font.setStyleHint(QtGui.QFont.Monospace)
        self.pseudo_rebuild_asm_edit.setFont(code_font)
        self.pseudo_rebuild_edit.setFont(code_font)
        asm_layout.addWidget(asm_label)
        asm_layout.addWidget(self.pseudo_rebuild_asm_edit, 1)
        pseudo_layout.addWidget(pseudo_label)
        pseudo_layout.addWidget(self.pseudo_rebuild_edit, 1)
        splitter.addWidget(asm_panel)
        splitter.addWidget(pseudo_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        self.pseudo_rebuild_warning_label = QtWidgets.QLabel("")
        self.pseudo_rebuild_warning_label.setTextFormat(QtCore.Qt.PlainText)
        self.pseudo_rebuild_warning_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.pseudo_rebuild_warning_label.setStyleSheet("color:#ffcf6e;")
        layout.addWidget(self.pseudo_rebuild_warning_label)
        return tab

    def _build_review_queue_tab(self) -> QtWidgets.QWidget:
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        toolbar = QtWidgets.QHBoxLayout()
        self.btn_refresh_review_queue = QtWidgets.QPushButton("Refresh")
        self.btn_jump_review_queue = QtWidgets.QPushButton("Jump")
        self.btn_copy_review_queue = QtWidgets.QPushButton("Copy Queue")
        self.btn_remove_review_queue = QtWidgets.QPushButton("Remove")
        self.btn_clear_review_queue = QtWidgets.QPushButton("Clear")
        self.review_queue_path_label = QtWidgets.QLabel("")
        self.review_queue_path_label.setTextFormat(QtCore.Qt.PlainText)
        self.review_queue_path_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.btn_refresh_review_queue.clicked.connect(self._refresh_review_queue)
        self.btn_jump_review_queue.clicked.connect(self._jump_selected_review_mark)
        self.btn_copy_review_queue.clicked.connect(self._copy_review_queue)
        self.btn_remove_review_queue.clicked.connect(self._remove_selected_review_mark)
        self.btn_clear_review_queue.clicked.connect(self._clear_review_queue)
        toolbar.addWidget(self.btn_refresh_review_queue)
        toolbar.addWidget(self.btn_jump_review_queue)
        toolbar.addWidget(self.btn_copy_review_queue)
        toolbar.addWidget(self.btn_remove_review_queue)
        toolbar.addWidget(self.btn_clear_review_queue)
        toolbar.addWidget(self.review_queue_path_label, 1)
        layout.addLayout(toolbar)

        self.review_queue_table = QtWidgets.QTableWidget(0, 5)
        self.review_queue_table.setHorizontalHeaderLabels(["Address", "Name", "Status", "Source", "Note"])
        self.review_queue_table.horizontalHeader().setStretchLastSection(True)
        self.review_queue_table.verticalHeader().setVisible(False)
        self.review_queue_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.review_queue_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.review_queue_table.setAlternatingRowColors(True)
        self.review_queue_table.cellDoubleClicked.connect(lambda row, col: self._jump_review_row(row))
        layout.addWidget(self.review_queue_table, 1)
        return tab

    def _build_action_tab(self) -> QtWidgets.QWidget:
        tab = QtWidgets.QWidget()
        self.action_tab = tab
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        self.action_mode_label = QtWidgets.QLabel("Choose a Call/Hook action after an analysis.")
        self.action_mode_label.setTextFormat(QtCore.Qt.PlainText)
        self.action_mode_label.setStyleSheet("color:#9bd7ff; font-weight:600;")
        layout.addWidget(self.action_mode_label)

        self.action_goal_edit = QtWidgets.QPlainTextEdit()
        self.action_goal_edit.setPlaceholderText("Tell the AI what you want to observe or modify for this function.")
        self.action_goal_edit.setMaximumHeight(90)
        layout.addWidget(self.action_goal_edit)

        row = QtWidgets.QHBoxLayout()
        self.btn_send_action = QtWidgets.QPushButton("Ask AI")
        self.btn_clear_action = QtWidgets.QPushButton("Clear")
        self.btn_send_action.clicked.connect(self._send_action_chat)
        self.btn_clear_action.clicked.connect(self._clear_action_chat)
        self.btn_send_action.setEnabled(False)
        row.addWidget(self.btn_send_action)
        row.addWidget(self.btn_clear_action)
        row.addStretch(1)
        layout.addLayout(row)

        workspace = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        chat_panel = QtWidgets.QWidget()
        chat_layout = QtWidgets.QVBoxLayout(chat_panel)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_label = QtWidgets.QLabel("Chat")
        chat_label.setStyleSheet("color:#9bd7ff; font-weight:600;")
        self.action_chat_edit = QtWidgets.QTextBrowser()
        self.action_chat_edit.setReadOnly(True)
        self.action_chat_edit.setOpenExternalLinks(False)
        self.action_chat_edit.setPlaceholderText("Call/hook planning appears here.")
        chat_layout.addWidget(chat_label)
        chat_layout.addWidget(self.action_chat_edit, 1)

        code_panel = QtWidgets.QWidget()
        code_layout = QtWidgets.QVBoxLayout(code_panel)
        code_layout.setContentsMargins(0, 0, 0, 0)
        code_toolbar = QtWidgets.QHBoxLayout()
        code_label = QtWidgets.QLabel("Code Workspace")
        code_label.setStyleSheet("color:#9af2b2; font-weight:600;")
        self.btn_copy_code = QtWidgets.QPushButton("Copy Code")
        self.btn_save_code = QtWidgets.QPushButton("Save .hpp")
        self.btn_copy_code.clicked.connect(self._copy_action_code)
        self.btn_save_code.clicked.connect(self._save_action_code)
        code_toolbar.addWidget(code_label)
        code_toolbar.addStretch(1)
        code_toolbar.addWidget(self.btn_copy_code)
        code_toolbar.addWidget(self.btn_save_code)
        self.action_code_edit = QtWidgets.QPlainTextEdit()
        self.action_code_edit.setReadOnly(True)
        self.action_code_edit.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        code_font = QtGui.QFont("Consolas")
        code_font.setStyleHint(QtGui.QFont.Monospace)
        self.action_code_edit.setFont(code_font)
        self.action_code_edit.setPlaceholderText("The first C++ code block returned by the AI is extracted here.")
        code_layout.addLayout(code_toolbar)
        code_layout.addWidget(self.action_code_edit, 1)

        workspace.addWidget(chat_panel)
        workspace.addWidget(code_panel)
        workspace.setStretchFactor(0, 3)
        workspace.setStretchFactor(1, 4)
        layout.addWidget(workspace, 1)
        return tab

    def _build_feedback_tab(self) -> QtWidgets.QWidget:
        tab = QtWidgets.QWidget()
        self.feedback_tab = tab
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(7)

        title = QtWidgets.QLabel("Correct the current analysis so future passes do not repeat the same mistake.")
        title.setStyleSheet("color:#9bd7ff; font-weight:600;")
        title.setWordWrap(True)
        layout.addWidget(title)

        form = QtWidgets.QFormLayout()
        form.setFieldGrowthPolicy(QtWidgets.QFormLayout.AllNonFixedFieldsGrow)
        self.feedback_name_edit = QtWidgets.QLineEdit()
        self.feedback_name_edit.setPlaceholderText("correct_snake_case_name if you know it")
        self.feedback_role_combo = QtWidgets.QComboBox()
        self.feedback_role_combo.addItems([
            "",
            "damage",
            "stat",
            "inventory",
            "identity",
            "network",
            "input",
            "render",
            "telemetry",
            "parser",
            "validation",
            "helper",
            "unknown",
        ])
        self.feedback_usefulness_combo = QtWidgets.QComboBox()
        self.feedback_usefulness_combo.addItems(["", "high", "medium", "low", "none", "unknown"])
        self.feedback_strategy_combo = QtWidgets.QComboBox()
        self.feedback_strategy_combo.addItems([
            "",
            "observe_only",
            "log_then_compare",
            "modify_output",
            "modify_argument",
            "hook_caller",
            "hook_callee",
            "not_recommended",
        ])
        form.addRow("Correct name", self.feedback_name_edit)
        form.addRow("Correct role", self.feedback_role_combo)
        form.addRow("Usefulness", self.feedback_usefulness_combo)
        form.addRow("Best strategy", self.feedback_strategy_combo)
        layout.addLayout(form)

        self.feedback_notes_edit = QtWidgets.QPlainTextEdit()
        self.feedback_notes_edit.setPlaceholderText(
            "Why was the analysis wrong or incomplete?\n"
            "Example: This is not a damage handler; it only maps player identity. The real mutation target is the caller that consumes output +0x28."
        )
        layout.addWidget(self.feedback_notes_edit, 1)

        row = QtWidgets.QHBoxLayout()
        self.btn_seed_feedback = QtWidgets.QPushButton("Seed From Current")
        self.btn_save_feedback = QtWidgets.QPushButton("Save Feedback")
        self.btn_clear_feedback = QtWidgets.QPushButton("Clear")
        self.btn_seed_feedback.clicked.connect(self._seed_feedback_from_current)
        self.btn_save_feedback.clicked.connect(self._save_feedback)
        self.btn_clear_feedback.clicked.connect(self._clear_feedback)
        row.addWidget(self.btn_seed_feedback)
        row.addWidget(self.btn_save_feedback)
        row.addWidget(self.btn_clear_feedback)
        row.addStretch(1)
        layout.addLayout(row)

        self.feedback_status_label = QtWidgets.QLabel("")
        self.feedback_status_label.setTextFormat(QtCore.Qt.PlainText)
        self.feedback_status_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.feedback_status_label.setStyleSheet("color:#7f8994;")
        layout.addWidget(self.feedback_status_label)
        return tab

    def _build_pseudodiff_tab(self) -> QtWidgets.QWidget:
        tab = QtWidgets.QWidget()
        self.pseudodiff_tab = tab
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(7)

        header = QtWidgets.QHBoxLayout()
        label = QtWidgets.QLabel("Paste old/new pseudocode to see what changed between game versions.")
        label.setStyleSheet("color:#9bd7ff; font-weight:600;")
        self.pseudodiff_goal_edit = QtWidgets.QLineEdit()
        self.pseudodiff_goal_edit.setPlaceholderText("Porting goal, e.g. revalidate old hook, compare damage path, update offsets")
        header.addWidget(label, 1)
        header.addWidget(self.pseudodiff_goal_edit, 2)
        layout.addLayout(header)

        editor_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        old_panel = QtWidgets.QWidget()
        old_layout = QtWidgets.QVBoxLayout(old_panel)
        old_layout.setContentsMargins(0, 0, 0, 0)
        old_label = QtWidgets.QLabel("Old version pseudocode")
        old_label.setStyleSheet("color:#ffd58a; font-weight:700;")
        self.pseudodiff_old_edit = QtWidgets.QPlainTextEdit()
        self.pseudodiff_old_edit.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self.pseudodiff_old_edit.setPlaceholderText("Paste old Hex-Rays pseudocode here.")
        new_panel = QtWidgets.QWidget()
        new_layout = QtWidgets.QVBoxLayout(new_panel)
        new_layout.setContentsMargins(0, 0, 0, 0)
        new_label = QtWidgets.QLabel("New version pseudocode")
        new_label.setStyleSheet("color:#9af2b2; font-weight:700;")
        self.pseudodiff_new_edit = QtWidgets.QPlainTextEdit()
        self.pseudodiff_new_edit.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self.pseudodiff_new_edit.setPlaceholderText("Paste new Hex-Rays pseudocode here.")
        code_font = QtGui.QFont("Consolas")
        code_font.setStyleHint(QtGui.QFont.Monospace)
        self.pseudodiff_old_edit.setFont(code_font)
        self.pseudodiff_new_edit.setFont(code_font)
        old_layout.addWidget(old_label)
        old_layout.addWidget(self.pseudodiff_old_edit, 1)
        new_layout.addWidget(new_label)
        new_layout.addWidget(self.pseudodiff_new_edit, 1)
        editor_splitter.addWidget(old_panel)
        editor_splitter.addWidget(new_panel)
        editor_splitter.setStretchFactor(0, 1)
        editor_splitter.setStretchFactor(1, 1)
        layout.addWidget(editor_splitter, 2)

        toolbar = QtWidgets.QHBoxLayout()
        self.btn_pseudodiff_local = QtWidgets.QPushButton("Run Local Diff")
        self.btn_pseudodiff_ai = QtWidgets.QPushButton("Ask AI Diff")
        self.btn_pseudodiff_copy = QtWidgets.QPushButton("Copy Result")
        self.btn_pseudodiff_clear = QtWidgets.QPushButton("Clear")
        self.btn_pseudodiff_local.clicked.connect(self._run_pseudodiff_local)
        self.btn_pseudodiff_ai.clicked.connect(self._run_pseudodiff_ai)
        self.btn_pseudodiff_copy.clicked.connect(self._copy_pseudodiff_result)
        self.btn_pseudodiff_clear.clicked.connect(self._clear_pseudodiff)
        toolbar.addWidget(self.btn_pseudodiff_local)
        toolbar.addWidget(self.btn_pseudodiff_ai)
        toolbar.addWidget(self.btn_pseudodiff_copy)
        toolbar.addWidget(self.btn_pseudodiff_clear)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        self.pseudodiff_result = QtWidgets.QTextBrowser()
        self.pseudodiff_result.setReadOnly(True)
        self.pseudodiff_result.setOpenExternalLinks(False)
        self.pseudodiff_result.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard
        )
        self.pseudodiff_result.setPlaceholderText("Diff result appears here.")
        self.pseudodiff_last_text = ""
        layout.addWidget(self.pseudodiff_result, 2)
        return tab

    def _build_dump_context_tab(self) -> QtWidgets.QWidget:
        tab = QtWidgets.QWidget()
        self.dump_context_tab = tab
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        toolbar = QtWidgets.QHBoxLayout()
        self.btn_save_dump_context = QtWidgets.QPushButton("Save Dump Context")
        self.btn_reload_dump_context = QtWidgets.QPushButton("Reload")
        self.btn_save_dump_context.clicked.connect(lambda: self._save_dump_context_from_ui(silent=False))
        self.btn_reload_dump_context.clicked.connect(self._load_dump_context_into_ui)
        self.dump_context_path_label = QtWidgets.QLabel("")
        self.dump_context_path_label.setTextFormat(QtCore.Qt.PlainText)
        self.dump_context_path_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        toolbar.addWidget(self.btn_save_dump_context)
        toolbar.addWidget(self.btn_reload_dump_context)
        toolbar.addWidget(self.dump_context_path_label, 1)
        layout.addLayout(toolbar)

        self.dump_context_edit = QtWidgets.QPlainTextEdit()
        self.dump_context_edit.setPlaceholderText(
            "Optional analyst context for this dump/process. Example:\n"
            "Process: process_name\n"
            "Engine: engine/runtime if known\n"
            "Reverse goal: inventory stack / player controller / input mapping\n"
            "Known addresses, classes, globals, naming rules, notes..."
        )
        layout.addWidget(self.dump_context_edit, 1)
        return tab

    def _build_external_evidence_tab(self) -> QtWidgets.QWidget:
        tab = QtWidgets.QWidget()
        self.external_evidence_tab = tab
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        toolbar = QtWidgets.QHBoxLayout()
        self.btn_save_external_evidence = QtWidgets.QPushButton("Save Evidence")
        self.btn_reload_external_evidence = QtWidgets.QPushButton("Reload")
        self.btn_import_external_evidence = QtWidgets.QPushButton("Import File")
        self.btn_template_external_evidence = QtWidgets.QPushButton("Insert Template")
        self.btn_preview_external_evidence = QtWidgets.QPushButton("Preview")
        self.btn_save_external_evidence.clicked.connect(lambda: self._save_external_evidence_from_ui(silent=False))
        self.btn_reload_external_evidence.clicked.connect(self._load_external_evidence_into_ui)
        self.btn_import_external_evidence.clicked.connect(self._import_external_evidence_file)
        self.btn_template_external_evidence.clicked.connect(self._insert_external_evidence_template)
        self.btn_preview_external_evidence.clicked.connect(self._refresh_external_evidence_preview)
        self.external_evidence_path_label = QtWidgets.QLabel("")
        self.external_evidence_path_label.setTextFormat(QtCore.Qt.PlainText)
        self.external_evidence_path_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        toolbar.addWidget(self.btn_save_external_evidence)
        toolbar.addWidget(self.btn_reload_external_evidence)
        toolbar.addWidget(self.btn_import_external_evidence)
        toolbar.addWidget(self.btn_template_external_evidence)
        toolbar.addWidget(self.btn_preview_external_evidence)
        toolbar.addWidget(self.external_evidence_path_label, 1)
        layout.addLayout(toolbar)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        self.external_evidence_edit = QtWidgets.QPlainTextEdit()
        self.external_evidence_edit.setPlaceholderText(
            "Static evidence for this dump. Paste JSON/JSONL or lines like:\n"
            "diff 0x140123456 changed constant from 100.0 to 85.0 in new dump\n"
            "capability 0x140222000 capa: packed-data parser / network-like strings\n"
            "deobf 0x140333000 D-810: opaque predicate removed, simplified path reaches value clamp\n"
            "structure 0x140444000 recovered fields +0x28 +0x30 look like player state values\n"
            "signature 0x140555000 old dump matched accumulate_damage_modifiers confidence=0.82"
        )
        self.external_evidence_preview = QtWidgets.QPlainTextEdit()
        self.external_evidence_preview.setReadOnly(True)
        self.external_evidence_preview.setPlaceholderText("Normalized evidence preview appears here.")
        code_font = QtGui.QFont("Consolas")
        code_font.setStyleHint(QtGui.QFont.Monospace)
        self.external_evidence_edit.setFont(code_font)
        self.external_evidence_preview.setFont(code_font)
        splitter.addWidget(self.external_evidence_edit)
        splitter.addWidget(self.external_evidence_preview)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)
        return tab

    def _build_integrations_tab(self) -> QtWidgets.QWidget:
        tab = QtWidgets.QWidget()
        self.integrations_tab = tab
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        grid = QtWidgets.QGridLayout()
        grid.setSpacing(6)
        for index, preset in enumerate(INTEGRATION_PRESETS):
            card = QtWidgets.QFrame()
            card.setFrameShape(QtWidgets.QFrame.StyledPanel)
            card.setStyleSheet(
                "QFrame { background:#20252a; border:1px solid #333b44; border-radius:4px; }"
                "QLabel { background:transparent; }"
            )
            card_layout = QtWidgets.QVBoxLayout(card)
            card_layout.setContentsMargins(8, 6, 8, 6)
            title = QtWidgets.QLabel(
                "<span style='color:%s; font-weight:700;'>%s</span>"
                % (preset.get("accent") or "#edf1f5", html.escape(str(preset.get("title") or "")))
            )
            hint = QtWidgets.QLabel(html.escape(str(preset.get("hint") or "")))
            hint.setWordWrap(True)
            hint.setStyleSheet("color:#aeb7c2;")
            card_layout.addWidget(title)
            card_layout.addWidget(hint)
            grid.addWidget(card, index // 4, index % 4)
        layout.addLayout(grid)

        toolbar = QtWidgets.QHBoxLayout()
        self.integration_preset_combo = QtWidgets.QComboBox()
        for preset in INTEGRATION_PRESETS:
            self.integration_preset_combo.addItem(str(preset.get("title") or preset.get("key")), str(preset.get("key")))
        self.integration_preset_combo.currentIndexChanged.connect(self._refresh_integration_preview)
        self.btn_import_integration = QtWidgets.QPushButton("Import File")
        self.btn_template_integration = QtWidgets.QPushButton("Insert Template")
        self.btn_preview_integration = QtWidgets.QPushButton("Preview")
        self.btn_push_integration = QtWidgets.QPushButton("Push to Evidence Sources")
        self.btn_structure_scout = QtWidgets.QPushButton("Structure Scout")
        self.btn_signature_scout = QtWidgets.QPushButton("Signature Scout")
        self.btn_all_static_scouts = QtWidgets.QPushButton("Run Static Scouts")
        self.btn_import_integration.clicked.connect(self._import_integration_file)
        self.btn_template_integration.clicked.connect(self._insert_integration_template)
        self.btn_preview_integration.clicked.connect(self._refresh_integration_preview)
        self.btn_push_integration.clicked.connect(self._push_integration_to_evidence)
        self.btn_structure_scout.clicked.connect(self._run_structure_scout)
        self.btn_signature_scout.clicked.connect(self._run_signature_scout)
        self.btn_all_static_scouts.clicked.connect(self._run_all_static_scouts)
        toolbar.addWidget(self.integration_preset_combo)
        toolbar.addWidget(self.btn_import_integration)
        toolbar.addWidget(self.btn_template_integration)
        toolbar.addWidget(self.btn_preview_integration)
        toolbar.addWidget(self.btn_push_integration)
        toolbar.addWidget(self.btn_structure_scout)
        toolbar.addWidget(self.btn_signature_scout)
        toolbar.addWidget(self.btn_all_static_scouts)
        layout.addLayout(toolbar)

        toolchain_bar = QtWidgets.QHBoxLayout()
        self.btn_toolchain_check = QtWidgets.QPushButton("Toolchain Check")
        self.btn_obfuscation_scout = QtWidgets.QPushButton("Obfuscation Scout")
        self.btn_toolchain_scouts = QtWidgets.QPushButton("Run Toolchain Scouts")
        self.btn_toolchain_check.setToolTip("Check optional sidecar libraries: Capstone, LIEF, YARA, Unicorn, Miasm, angr, Triton.")
        self.btn_obfuscation_scout.setToolTip("Run bounded obfuscation heuristics plus Capstone evidence when available.")
        self.btn_toolchain_scouts.setToolTip("Run sidecar scouts for obfuscation, Capstone, LIEF, and YARA where available.")
        self.btn_toolchain_check.clicked.connect(self._run_toolchain_check)
        self.btn_obfuscation_scout.clicked.connect(lambda checked=False: self._run_toolchain_scout("obfuscation"))
        self.btn_toolchain_scouts.clicked.connect(lambda checked=False: self._run_toolchain_scout("all"))
        self.toolchain_status_label = QtWidgets.QLabel("Optional sidecar: not checked")
        self.toolchain_status_label.setTextFormat(QtCore.Qt.PlainText)
        self.toolchain_status_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.toolchain_status_label.setStyleSheet("color:#aeb7c2;")
        toolchain_bar.addWidget(self.btn_toolchain_check)
        toolchain_bar.addWidget(self.btn_obfuscation_scout)
        toolchain_bar.addWidget(self.btn_toolchain_scouts)
        toolchain_bar.addWidget(self.toolchain_status_label, 1)
        layout.addLayout(toolchain_bar)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        self.integration_raw_edit = QtWidgets.QPlainTextEdit()
        self.integration_raw_edit.setPlaceholderText(
            "Paste external static output here, then Preview or Push to Evidence Sources."
        )
        self.integration_preview_edit = QtWidgets.QPlainTextEdit()
        self.integration_preview_edit.setReadOnly(True)
        self.integration_preview_edit.setPlaceholderText("Normalized integration evidence appears here.")
        code_font = QtGui.QFont("Consolas")
        code_font.setStyleHint(QtGui.QFont.Monospace)
        self.integration_raw_edit.setFont(code_font)
        self.integration_preview_edit.setFont(code_font)
        splitter.addWidget(self.integration_raw_edit)
        splitter.addWidget(self.integration_preview_edit)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)
        return tab

    def _build_game_map_tab(self) -> QtWidgets.QWidget:
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)

        toolbar = QtWidgets.QHBoxLayout()
        self.btn_refresh_map = QtWidgets.QPushButton("Refresh")
        self.btn_refresh_map.clicked.connect(self._refresh_game_map)
        self.map_path_label = QtWidgets.QLabel("")
        self.map_path_label.setTextFormat(QtCore.Qt.PlainText)
        self.map_path_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        toolbar.addWidget(self.btn_refresh_map)
        toolbar.addWidget(self.map_path_label, 1)
        layout.addLayout(toolbar)

        self.game_map_edit = QtWidgets.QPlainTextEdit()
        self.game_map_edit.setReadOnly(True)
        layout.addWidget(self.game_map_edit, 1)
        return tab

    def _build_settings_tab(self) -> QtWidgets.QWidget:
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.AllNonFixedFieldsGrow)

        self.provider_combo = QtWidgets.QComboBox()
        self.provider_combo.addItem("Local / Ollama", "local")
        self.provider_combo.addItem("Gemini hosted", "gemini")
        self.provider_combo.setToolTip("Choose whether analysis uses your local OpenAI-compatible server or Google's hosted Gemini API.")
        self.provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        self.base_url_edit = QtWidgets.QLineEdit()
        self.model_preset_combo = QtWidgets.QComboBox()
        self.model_edit = QtWidgets.QLineEdit()
        self.api_key_edit = QtWidgets.QLineEdit()
        self.api_key_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.temp_spin = QtWidgets.QDoubleSpinBox()
        self.temp_spin.setRange(0.0, 2.0)
        self.temp_spin.setSingleStep(0.05)
        self.temp_spin.setDecimals(2)
        self.timeout_spin = QtWidgets.QSpinBox()
        self.timeout_spin.setRange(5, 600)
        self.analysis_timeout_spin = QtWidgets.QSpinBox()
        self.analysis_timeout_spin.setRange(15, 300)
        self.analysis_timeout_spin.setSuffix(" sec")
        self.analysis_timeout_spin.setToolTip("Timeout for real analyses. If reached, the plugin falls back to local semantic cues instead of staying stuck.")
        self.analysis_depth_combo = QtWidgets.QComboBox()
        self.analysis_depth_combo.addItems(["Fast", "Balanced", "Deep"])
        self.analysis_depth_combo.setToolTip(
            "Fast skips XREF expansion and uses tight prompt/token budgets. Balanced restores limited expansion. Deep is slower but richer."
        )
        self.agent_mode_combo = QtWidgets.QComboBox()
        self.agent_mode_combo.addItems(["Single", "Duo", "Council"])
        self.agent_mode_combo.setToolTip(
            "Single uses one analyst pass. Duo adds a shared local Evidence Pack. Council adds context scouts for XREF/caller/callee/string evidence, then keeps the solo analyst as final source."
        )
        self.max_analysis_tokens_spin = QtWidgets.QSpinBox()
        self.max_analysis_tokens_spin.setRange(600, 5000)
        self.max_analysis_tokens_spin.setSingleStep(100)
        self.max_analysis_tokens_spin.setToolTip("Upper bound for analysis JSON response tokens. Fast mode caps this internally.")
        self.max_asm_spin = QtWidgets.QSpinBox()
        self.max_asm_spin.setRange(40, 2000)
        self.max_pseudo_spin = QtWidgets.QSpinBox()
        self.max_pseudo_spin.setRange(2000, 80000)
        self.max_decompile_instr_spin = QtWidgets.QSpinBox()
        self.max_decompile_instr_spin.setRange(80, 10000)
        self.max_decompile_instr_spin.setToolTip("Functions above this instruction budget skip Hex-Rays and use bounded ASM context.")
        self.max_decompile_bytes_spin = QtWidgets.QSpinBox()
        self.max_decompile_bytes_spin.setRange(1024, 1048576)
        self.max_decompile_bytes_spin.setSingleStep(1024)
        self.max_decompile_bytes_spin.setToolTip("Functions above this byte budget skip Hex-Rays to avoid very slow decompile attempts.")
        self.max_xref_items_spin = QtWidgets.QSpinBox()
        self.max_xref_items_spin.setRange(8, 300)
        self.max_xref_expansion_spin = QtWidgets.QSpinBox()
        self.max_xref_expansion_spin.setRange(0, 40)
        self.engine_combo = QtWidgets.QComboBox()
        self.engine_combo.addItems(profile_names())
        self.auto_rename_check = QtWidgets.QCheckBox("Rename valid suggested functions automatically")
        self.auto_rename_check.setToolTip("After each successful analysis, apply suggested_function_name if it passes local validation.")
        self.auto_comment_check = QtWidgets.QCheckBox("Apply AI comments and colors automatically")
        self.auto_comment_check.setToolTip("After each successful analysis, write bounded AI comments and evidence colors into IDA.")
        self.game_research_check = QtWidgets.QCheckBox("Use minimal cached online lookup")
        self.game_research_check.setToolTip("Uses the process/dump name and IDB strings to fetch a small cached context.")
        self.global_string_scan_check = QtWidgets.QCheckBox("Scan global IDB strings for process hints")
        self.global_string_scan_check.setToolTip("Can trigger IDA 'Generating a list of strings' on large dumps. Leave off for faster analysis.")
        self.auto_toolchain_check = QtWidgets.QCheckBox("Auto sidecar scouts when useful")
        self.auto_toolchain_check.setToolTip("During LLM analysis, automatically run bounded sidecar scouts when ASM/obfuscation/file evidence suggests they are useful.")
        self.game_research_ttl_spin = QtWidgets.QSpinBox()
        self.game_research_ttl_spin.setRange(1, 90)
        self.game_research_ttl_spin.setSuffix(" days")

        self.model_preset_combo.currentIndexChanged.connect(self._on_model_preset_changed)
        self.model_preset_combo.setToolTip("Deep is best for hard reverse engineering. Balanced/Fast are useful for quick passes.")
        self.base_url_edit.setToolTip("Gemini OpenAI-compatible endpoint defaults to https://generativelanguage.googleapis.com/v1beta/openai")
        self.api_key_edit.setToolTip("Local usually uses 'ollama'. Gemini needs a Gemini API key from Google AI Studio.")

        layout.addRow("", self._subsection_label("LLM"))
        layout.addRow("Provider", self.provider_combo)
        layout.addRow("Base URL", self.base_url_edit)
        layout.addRow("Model preset", self.model_preset_combo)
        layout.addRow("Model", self.model_edit)
        layout.addRow("API key", self.api_key_edit)
        layout.addRow("Temperature", self.temp_spin)
        layout.addRow("Timeout seconds", self.timeout_spin)
        layout.addRow("Analysis timeout", self.analysis_timeout_spin)
        self.llm_detail_label = QtWidgets.QLabel("")
        self.llm_detail_label.setTextFormat(QtCore.Qt.PlainText)
        self.llm_detail_label.setWordWrap(True)
        self.llm_detail_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.llm_detail_label.setStyleSheet("color:#9bd7ff; padding:4px 0;")
        layout.addRow("LLM detail", self.llm_detail_label)

        layout.addRow("", self._subsection_label("Context Budget"))
        layout.addRow("Analysis speed", self.analysis_depth_combo)
        layout.addRow("Agent mode", self.agent_mode_combo)
        layout.addRow("Max answer tokens", self.max_analysis_tokens_spin)
        layout.addRow("Max ASM lines", self.max_asm_spin)
        layout.addRow("Max pseudocode chars", self.max_pseudo_spin)
        layout.addRow("Max decompile instructions", self.max_decompile_instr_spin)
        layout.addRow("Max decompile bytes", self.max_decompile_bytes_spin)
        layout.addRow("Max XREF items", self.max_xref_items_spin)
        layout.addRow("Max XREF expansions", self.max_xref_expansion_spin)

        layout.addRow("", self._subsection_label("Reverse Context"))
        layout.addRow("Engine profile", self.engine_combo)
        layout.addRow("Process lookup", self.game_research_check)
        layout.addRow("Global strings", self.global_string_scan_check)
        layout.addRow("Sidecar scouts", self.auto_toolchain_check)
        layout.addRow("Lookup cache TTL", self.game_research_ttl_spin)

        layout.addRow("", self._subsection_label("Automation"))
        layout.addRow("Auto rename", self.auto_rename_check)
        layout.addRow("Auto comments/colors", self.auto_comment_check)

        self.config_path_label = QtWidgets.QLabel(config_path())
        self.config_path_label.setTextFormat(QtCore.Qt.PlainText)
        self.config_path_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        layout.addRow("Config file", self.config_path_label)

        self.btn_save_settings = QtWidgets.QPushButton("Save Settings")
        self.btn_save_settings.clicked.connect(self._save_settings_from_ui)
        layout.addRow("", self.btn_save_settings)
        return tab

    def _subsection_label(self, text: str) -> QtWidgets.QLabel:
        label = QtWidgets.QLabel(text)
        label.setObjectName("SubsectionLabel")
        return label

    def _provider_presets(self, provider: Optional[str] = None) -> list:
        provider = provider or self.visible_provider or "local"
        return GEMINI_MODEL_PRESETS if provider == "gemini" else MODEL_PRESETS

    def _set_provider_fields(self, provider: str) -> None:
        if provider == "gemini":
            base_url = self.cfg.gemini_base_url
            model = self.cfg.gemini_model
            api_key = self.cfg.gemini_api_key
        else:
            base_url = self.cfg.base_url
            model = self.cfg.model
            api_key = self.cfg.api_key

        self.base_url_edit.setText(base_url)
        self._populate_model_presets(provider, model)
        self.model_edit.setText(model)
        self.api_key_edit.setText(api_key)

    def _populate_model_presets(self, provider: str, selected_model: str) -> None:
        self.model_preset_combo.blockSignals(True)
        self.model_preset_combo.clear()
        for preset in self._provider_presets(provider):
            self.model_preset_combo.addItem(preset["label"], preset["model"])
        self.model_preset_combo.addItem("Manual / custom model", "")
        preset_idx = self.model_preset_combo.count() - 1
        for idx in range(self.model_preset_combo.count()):
            if self.model_preset_combo.itemData(idx) == selected_model:
                preset_idx = idx
                break
        self.model_preset_combo.setCurrentIndex(preset_idx)
        self.model_preset_combo.blockSignals(False)
        self.model_edit.setReadOnly(bool(self.model_preset_combo.itemData(preset_idx)))

    def _store_visible_provider_fields(self) -> None:
        provider = self.visible_provider or "local"
        if provider == "gemini":
            self.cfg.gemini_base_url = self.base_url_edit.text().strip()
            self.cfg.gemini_model = self.model_edit.text().strip()
            self.cfg.gemini_api_key = self.api_key_edit.text()
        else:
            self.cfg.base_url = self.base_url_edit.text().strip()
            self.cfg.model = self.model_edit.text().strip()
            self.cfg.api_key = self.api_key_edit.text()

    def _load_settings_into_ui(self) -> None:
        self._settings_loading = True
        self.visible_provider = self.cfg.provider
        idx_provider = self.provider_combo.findData(self.cfg.provider)
        self.provider_combo.setCurrentIndex(idx_provider if idx_provider >= 0 else 0)
        self._set_provider_fields(self.visible_provider)
        self._settings_loading = False
        self.temp_spin.setValue(float(self.cfg.temperature))
        self.timeout_spin.setValue(int(self.cfg.timeout_seconds))
        self.analysis_timeout_spin.setValue(int(self.cfg.analysis_timeout_seconds))
        idx_depth = self.analysis_depth_combo.findText(self.cfg.analysis_depth)
        self.analysis_depth_combo.setCurrentIndex(idx_depth if idx_depth >= 0 else 0)
        idx_agent = self.agent_mode_combo.findText(getattr(self.cfg, "agent_mode", "Single"))
        self.agent_mode_combo.setCurrentIndex(idx_agent if idx_agent >= 0 else 0)
        self.max_analysis_tokens_spin.setValue(int(self.cfg.max_analysis_tokens))
        self.max_asm_spin.setValue(int(self.cfg.max_asm_lines))
        self.max_pseudo_spin.setValue(int(self.cfg.max_pseudocode_chars))
        self.max_decompile_instr_spin.setValue(int(self.cfg.max_decompile_instructions))
        self.max_decompile_bytes_spin.setValue(int(self.cfg.max_decompile_bytes))
        self.max_xref_items_spin.setValue(int(self.cfg.max_xref_items))
        self.max_xref_expansion_spin.setValue(int(self.cfg.max_xref_expansion_items))
        self.auto_rename_check.setChecked(bool(self.cfg.auto_rename_after_analysis))
        self.auto_comment_check.setChecked(bool(self.cfg.auto_comment_after_analysis))
        self.game_research_check.setChecked(bool(self.cfg.enable_game_research))
        self.global_string_scan_check.setChecked(bool(self.cfg.enable_global_string_scan))
        self.auto_toolchain_check.setChecked(bool(getattr(self.cfg, "auto_toolchain_scouts", True)))
        self.game_research_ttl_spin.setValue(int(self.cfg.game_research_ttl_days))
        idx = self.engine_combo.findText(self.cfg.engine_profile)
        self.engine_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self._update_automation_label()

    def _on_provider_changed(self) -> None:
        provider = str(self.provider_combo.currentData() or "local")
        if self._settings_loading:
            self.visible_provider = provider
            return
        self._store_visible_provider_fields()
        self.visible_provider = provider
        self.cfg.provider = provider
        self._set_provider_fields(provider)
        self._set_status("Provider: %s" % self.cfg.active_provider_label(), ok=True)

    def _on_model_preset_changed(self) -> None:
        model = self.model_preset_combo.currentData()
        if not model:
            self.model_edit.setReadOnly(False)
            return
        self.model_edit.setText(str(model))
        self.model_edit.setReadOnly(True)
        for preset in self._provider_presets():
            if preset["model"] == model:
                timeout = int(preset["timeout_seconds"])
                if self.timeout_spin.value() < timeout:
                    self.timeout_spin.setValue(timeout)
                break

    def _read_settings_from_ui(self) -> PluginConfig:
        self._store_visible_provider_fields()
        data = self.cfg.to_dict()
        data.update({
            "provider": str(self.provider_combo.currentData() or self.visible_provider or "local"),
            "temperature": float(self.temp_spin.value()),
            "timeout_seconds": int(self.timeout_spin.value()),
            "analysis_timeout_seconds": int(self.analysis_timeout_spin.value()),
            "engine_profile": self.engine_combo.currentText(),
            "analysis_depth": self.analysis_depth_combo.currentText(),
            "agent_mode": self.agent_mode_combo.currentText(),
            "max_analysis_tokens": int(self.max_analysis_tokens_spin.value()),
            "max_asm_lines": int(self.max_asm_spin.value()),
            "max_pseudocode_chars": int(self.max_pseudo_spin.value()),
            "max_decompile_instructions": int(self.max_decompile_instr_spin.value()),
            "max_decompile_bytes": int(self.max_decompile_bytes_spin.value()),
            "max_xref_items": int(self.max_xref_items_spin.value()),
            "max_xref_expansion_items": int(self.max_xref_expansion_spin.value()),
            "auto_rename_after_analysis": bool(self.auto_rename_check.isChecked()),
            "auto_comment_after_analysis": bool(self.auto_comment_check.isChecked()),
            "auto_toolchain_scouts": bool(self.auto_toolchain_check.isChecked()),
            "enable_game_research": bool(self.game_research_check.isChecked()),
            "enable_global_string_scan": bool(self.global_string_scan_check.isChecked()),
            "game_research_ttl_days": int(self.game_research_ttl_spin.value()),
        })
        return PluginConfig.from_dict(data)

    def _save_settings_from_ui(self) -> None:
        self.cfg = self._read_settings_from_ui()
        save_config(self.cfg)
        self._update_automation_label()
        self._set_status("Settings saved", ok=True)

    def _update_automation_label(self) -> None:
        bits = []
        if bool(getattr(self.cfg, "auto_rename_after_analysis", True)):
            bits.append("rename")
        if bool(getattr(self.cfg, "auto_comment_after_analysis", True)):
            bits.append("comments")
        provider = "Gemini" if getattr(self.cfg, "provider", "local") == "gemini" else "Local"
        text = "LLM: %s | Agents: %s | Auto: %s" % (
            provider,
            getattr(self.cfg, "agent_mode", "Single"),
            ", ".join(bits) if bits else "off",
        )
        color = "#9af2b2" if bits else "#ffb3a7"
        self.automation_label.setText(text)
        self.automation_label.setStyleSheet("color:%s; font-weight:600;" % color)

    def _current_database(self) -> Dict[str, Any]:
        if self.current_context and self.current_context.get("database"):
            return self.current_context.get("database") or {}
        try:
            return database_context()
        except Exception:
            return {}

    def _load_dump_context_into_ui(self) -> None:
        db = self._current_database()
        text = load_dump_context(db)
        self.dump_context_edit.setPlainText(text)
        self.dump_context_path_label.setText(dump_context_path(db))

    def _save_dump_context_from_ui(self, silent: bool = False) -> str:
        db = self._current_database()
        path = save_dump_context(db, self.dump_context_edit.toPlainText())
        self.dump_context_path_label.setText(path)
        if not silent:
            self._set_status("Dump context saved", ok=True)
        return path

    def _dump_context_for_prompt(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        db = ctx.get("database") or self._current_database()
        text = self.dump_context_edit.toPlainText()
        return dump_context_payload(db, text)

    def _load_external_evidence_into_ui(self) -> None:
        db = self._current_database()
        text = load_external_evidence(db)
        self.external_evidence_edit.setPlainText(text)
        self.external_evidence_path_label.setText(external_evidence_path(db))
        self._refresh_external_evidence_preview()

    def _save_external_evidence_from_ui(self, silent: bool = False) -> str:
        db = self._current_database()
        path = save_external_evidence(db, self.external_evidence_edit.toPlainText())
        self.external_evidence_path_label.setText(path)
        self._refresh_external_evidence_preview()
        if not silent:
            self._set_status("External evidence saved", ok=True)
        return path

    def _external_evidence_for_prompt(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        db = ctx.get("database") or self._current_database()
        text = self.external_evidence_edit.toPlainText()
        return external_evidence_payload(db, text, ctx)

    def _refresh_external_evidence_preview(self) -> None:
        try:
            ctx = self.current_context or {}
            payload = external_evidence_payload(self._current_database(), self.external_evidence_edit.toPlainText(), ctx)
            self.external_evidence_preview.setPlainText(render_external_evidence_text(payload))
        except Exception as exc:
            self.external_evidence_preview.setPlainText("External evidence parse error: %s" % exc)

    def _insert_external_evidence_template(self) -> None:
        current = self.external_evidence_edit.toPlainText().strip()
        template = external_evidence_template_text()
        if current:
            self.external_evidence_edit.appendPlainText("\n\n" + template)
        else:
            self.external_evidence_edit.setPlainText(template)
        self._refresh_external_evidence_preview()

    def _import_external_evidence_file(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Import external evidence",
            os.path.expanduser("~"),
            "Evidence files (*.json *.jsonl *.txt *.csv *.log);;All files (*.*)",
        )
        if not path:
            return
        try:
            text, truncated = read_text_file_safely(path)
            combined = append_block(
                self.external_evidence_edit.toPlainText(),
                "Imported from %s" % path,
                text,
            )
            self.external_evidence_edit.setPlainText(combined)
            self._save_external_evidence_from_ui(silent=True)
            suffix = " (truncated)" if truncated else ""
            self._set_status("External evidence imported%s" % suffix, ok=True)
        except Exception as exc:
            self._set_status("External evidence import failed", ok=False)
            info("External evidence import failed: %s" % exc)

    def _selected_integration_key(self) -> str:
        try:
            return str(self.integration_preset_combo.currentData() or "notes")
        except Exception:
            return "notes"

    def _integration_context(self) -> Dict[str, Any]:
        if self.current_context:
            return self.current_context
        try:
            self._save_settings_from_ui()
            ctx = collect_context(force_asm=True, cfg=self.cfg)
            self.current_context = ctx
            self._update_game_label(ctx)
            self._refresh_context_label(ctx)
            return ctx
        except Exception as exc:
            info("Integration context capture failed: %s" % exc)
            return {}

    def _refresh_integration_preview(self) -> None:
        try:
            key = self._selected_integration_key()
            text = self.integration_raw_edit.toPlainText()
            ctx = self.current_context or {}
            self.integration_preview_edit.setPlainText(render_integration_preview(key, text, ctx))
        except Exception as exc:
            self.integration_preview_edit.setPlainText("Integration preview failed: %s" % exc)

    def _insert_integration_template(self) -> None:
        key = self._selected_integration_key()
        template = integration_template_text(key)
        current = self.integration_raw_edit.toPlainText().strip()
        if current:
            self.integration_raw_edit.appendPlainText("\n" + template)
        else:
            self.integration_raw_edit.setPlainText(template)
        self._refresh_integration_preview()

    def _import_integration_file(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Import integration output",
            os.path.expanduser("~"),
            "Static outputs (*.json *.jsonl *.csv *.txt *.md *.log);;All files (*.*)",
        )
        if not path:
            return
        try:
            text, truncated = read_text_file_safely(path)
            combined = append_block(
                self.integration_raw_edit.toPlainText(),
                "Imported from %s" % path,
                text,
            )
            self.integration_raw_edit.setPlainText(combined)
            self._refresh_integration_preview()
            suffix = " (truncated)" if truncated else ""
            self._set_status("Integration output imported%s" % suffix, ok=True)
        except Exception as exc:
            self._set_status("Integration import failed", ok=False)
            info("Integration import failed: %s" % exc)

    def _append_to_external_evidence(self, text: str, source_label: str) -> None:
        block = sanitize_text(text).strip()
        if not block:
            self._set_status("No integration evidence to append", ok=False)
            return
        next_text = append_block(
            self.external_evidence_edit.toPlainText(),
            "From Integrations: %s" % sanitize_label(source_label or "static", 120),
            block,
        )
        self.external_evidence_edit.setPlainText(next_text)
        self._save_external_evidence_from_ui(silent=True)
        self._refresh_external_evidence_preview()
        self.tabs.setCurrentWidget(self.external_evidence_tab)
        count = len([line for line in block.splitlines() if line.strip() and not line.strip().startswith("#")])
        self._set_status("Added %d integration evidence row(s)" % count, ok=True)

    def _push_integration_to_evidence(self) -> None:
        key = self._selected_integration_key()
        ctx = self.current_context or {}
        text = self.integration_raw_edit.toPlainText()
        normalized = normalize_integration_text(key, text, ctx)
        self.integration_preview_edit.setPlainText(render_integration_preview(key, text, ctx))
        self._append_to_external_evidence(normalized, key)

    def _run_structure_scout(self) -> None:
        ctx = self._integration_context()
        text = build_structure_scout_text(ctx)
        index = self.integration_preset_combo.findData("structure")
        if index >= 0:
            self.integration_preset_combo.setCurrentIndex(index)
        self.integration_raw_edit.setPlainText(text)
        self.integration_preview_edit.setPlainText(render_integration_preview("structure", text, ctx))
        self._append_to_external_evidence(text, "local structure scout")

    def _run_signature_scout(self) -> None:
        ctx = self._integration_context()
        text = build_signature_scout_text(ctx)
        index = self.integration_preset_combo.findData("signature")
        if index >= 0:
            self.integration_preset_combo.setCurrentIndex(index)
        self.integration_raw_edit.setPlainText(text)
        self.integration_preview_edit.setPlainText(render_integration_preview("signature", text, ctx))
        self._append_to_external_evidence(text, "local signature scout")

    def _run_all_static_scouts(self) -> None:
        ctx = self._integration_context()
        text = build_all_local_scouts_text(ctx)
        self.integration_raw_edit.setPlainText(text)
        self.integration_preview_edit.setPlainText(render_integration_preview("notes", text, ctx))
        self._append_to_external_evidence(text, "local static scouts")

    def _run_toolchain_check(self) -> None:
        self._set_busy(True)
        self._set_status("Checking optional sidecar toolchain...", ok=True)
        self.toolchain_status_label.setText("Checking sidecar...")
        self.toolchain_worker = ToolchainWorker("check", timeout=20, parent=self)
        self.toolchain_worker.progress.connect(lambda message: self._set_status(message, ok=True))
        self.toolchain_worker.succeeded.connect(self._on_toolchain_check_ok)
        self.toolchain_worker.failed.connect(self._on_toolchain_failed)
        self.toolchain_worker.finished.connect(lambda: self._set_busy(False))
        self.toolchain_worker.start()

    def _run_toolchain_scout(self, scout: str) -> None:
        ctx = self._integration_context()
        timeout = 60 if scout == "all" else 35
        self._set_busy(True)
        self._set_status("Running %s sidecar scout..." % scout, ok=True)
        self.toolchain_status_label.setText("Running %s scout..." % scout)
        self.toolchain_worker = ToolchainWorker("scout_context", context=ctx, scout=scout, timeout=timeout, parent=self)
        self.toolchain_worker.progress.connect(lambda message: self._set_status(message, ok=True))
        self.toolchain_worker.succeeded.connect(lambda data, text, selected=scout, captured_ctx=ctx: self._on_toolchain_scout_ok(data, text, selected, captured_ctx))
        self.toolchain_worker.failed.connect(self._on_toolchain_failed)
        self.toolchain_worker.finished.connect(lambda: self._set_busy(False))
        self.toolchain_worker.start()

    def _toolchain_library_summary(self, data: Dict[str, Any]) -> str:
        libraries = data.get("libraries") or []
        available = [str(item.get("name")) for item in libraries if isinstance(item, dict) and item.get("available")]
        missing = [str(item.get("name")) for item in libraries if isinstance(item, dict) and not item.get("available")]
        return "available: %s | missing: %s" % (", ".join(available) if available else "-", ", ".join(missing) if missing else "-")

    def _on_toolchain_check_ok(self, data: Dict[str, Any], text: str) -> None:
        summary = self._toolchain_library_summary(data)
        self.toolchain_status_label.setText(summary)
        self.integration_raw_edit.setPlainText(text or summary)
        self.integration_preview_edit.setPlainText(text or summary)
        self._set_status("Toolchain check ready | %s" % summary, ok=True)
        try:
            self.toast.show_message("Toolchain check ready", ok=True)
        except Exception:
            pass

    def _on_toolchain_scout_ok(self, data: Dict[str, Any], text: str, scout: str, ctx: Dict[str, Any]) -> None:
        if not text.strip():
            text = "note sidecar %s scout returned no evidence rows" % scout
        preset = "deobf" if scout in ("obfuscation", "deobf") else "notes"
        index = self.integration_preset_combo.findData(preset)
        if index >= 0:
            self.integration_preset_combo.setCurrentIndex(index)
        self.integration_raw_edit.setPlainText(text)
        self.integration_preview_edit.setPlainText(render_integration_preview(preset, text, ctx))
        summary = self._toolchain_library_summary(data)
        elapsed = float(data.get("elapsed_seconds") or 0.0)
        self.toolchain_status_label.setText("%s | %.2fs" % (summary, elapsed))
        self._append_to_external_evidence(text, "sidecar %s scout" % scout)
        try:
            self.toast.show_message("Sidecar scout added evidence", ok=True)
        except Exception:
            pass

    def _on_toolchain_failed(self, message: str) -> None:
        self.toolchain_status_label.setText("Sidecar failed")
        self.integration_preview_edit.setPlainText("Toolchain sidecar failed:\n%s" % message)
        self._set_status("Toolchain sidecar failed", ok=False)
        info("Toolchain sidecar failed: %s" % message)

    def _refresh_game_map(self) -> None:
        context = self.current_context if self.current_context else None
        data = load_game_map(context)
        self.game_map_edit.setPlainText(render_game_map(data))
        self.map_path_label.setText(game_map_path(context))

    def _map_context(self) -> Dict[str, Any]:
        if isinstance(self.current_context, dict) and self.current_context:
            return self.current_context
        return {"database": database_context()}

    def _review_rows(self) -> list:
        data = load_game_map(self._map_context())
        return sorted_review_marks(data)

    def _refresh_review_queue(self) -> None:
        if not hasattr(self, "review_queue_table"):
            return
        context = self._map_context()
        rows = sorted_review_marks(load_game_map(context))
        self.review_queue_table.setRowCount(0)
        for row_idx, row in enumerate(rows):
            self.review_queue_table.insertRow(row_idx)
            values = [
                row.get("address") or "-",
                row.get("name") or "-",
                row.get("status") or "review",
                row.get("source") or "-",
                row.get("note") or row.get("line") or "-",
            ]
            for col, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(str(value))
                item.setData(QtCore.Qt.UserRole, row.get("address") or "")
                if col == 0:
                    item.setForeground(QtGui.QBrush(QtGui.QColor("#9bd7ff")))
                elif col == 2:
                    item.setForeground(QtGui.QBrush(QtGui.QColor("#ffd58a")))
                self.review_queue_table.setItem(row_idx, col, item)
        self.review_queue_table.resizeColumnsToContents()
        self.review_queue_path_label.setText("%d review mark(s) | %s" % (len(rows), game_map_path(context)))
        for button in (
            self.btn_jump_review_queue,
            self.btn_copy_review_queue,
            self.btn_remove_review_queue,
            self.btn_clear_review_queue,
        ):
            button.setEnabled(bool(rows))

    def _selected_review_address(self) -> Optional[str]:
        if not hasattr(self, "review_queue_table"):
            return None
        indexes = self.review_queue_table.selectionModel().selectedRows()
        if not indexes:
            return None
        item = self.review_queue_table.item(indexes[0].row(), 0)
        if not item:
            return None
        return str(item.data(QtCore.Qt.UserRole) or item.text() or "").strip()

    def _jump_review_row(self, row: int) -> None:
        item = self.review_queue_table.item(row, 0)
        address = str((item.data(QtCore.Qt.UserRole) if item else "") or (item.text() if item else "") or "")
        ea = parse_focus_ea(address)
        if ea is None:
            self._set_status("Review mark has no valid address", ok=False)
            return
        try:
            ida_kernwin.jumpto(ea)
            self._set_status("Jumped to review mark 0x%X" % ea, ok=True)
        except Exception as exc:
            self._set_status("Review jump failed", ok=False)
            info("Review jump failed: %s" % exc)

    def _jump_selected_review_mark(self) -> None:
        address = self._selected_review_address()
        if not address:
            self._set_status("Select a review mark first", ok=False)
            return
        ea = parse_focus_ea(address)
        if ea is None:
            self._set_status("Selected review mark has no valid address", ok=False)
            return
        try:
            ida_kernwin.jumpto(ea)
            self._set_status("Jumped to review mark 0x%X" % ea, ok=True)
        except Exception as exc:
            self._set_status("Review jump failed", ok=False)
            info("Review jump failed: %s" % exc)

    def _copy_review_queue(self) -> None:
        rows = self._review_rows()
        if not rows:
            self._set_status("Review queue is empty", ok=False)
            return
        lines = ["MonsteyAI review queue"]
        for row in rows:
            lines.append(
                "%s | %s | %s | %s"
                % (
                    row.get("address") or "-",
                    row.get("name") or "-",
                    row.get("status") or "review",
                    sanitize_text(row.get("note") or "", max_chars=500, collapse_ws=True),
                )
            )
        QtWidgets.QApplication.clipboard().setText("\n".join(lines))
        self._set_status("Review queue copied", ok=True)

    def _remove_selected_review_mark(self) -> None:
        address = self._selected_review_address()
        if not address:
            self._set_status("Select a review mark first", ok=False)
            return
        remove_review_mark(self._map_context(), address)
        self._refresh_review_queue()
        self._refresh_game_map()
        self._set_status("Review mark removed", ok=True)

    def _clear_review_queue(self) -> None:
        answer = QtWidgets.QMessageBox.question(self, PLUGIN_NAME, "Clear all review marks for this dump?")
        if answer != QtWidgets.QMessageBox.Yes:
            return
        clear_review_marks(self._map_context())
        self._refresh_review_queue()
        self._refresh_game_map()
        self._set_status("Review queue cleared", ok=True)

    def _set_status(self, text: str, ok: bool = True) -> None:
        color = "#8df29b" if ok else "#ff8c8c"
        safe_text = html.escape(sanitize_text(text, max_chars=900, collapse_ws=True))
        self.status_label.setText('<span style="color:%s; font-weight:600">%s</span> | %s' % (color, safe_text, QT_BINDING))
        if self._should_toast_status(text):
            self._show_toast(text, ok=ok)

    def _should_toast_status(self, text: str) -> bool:
        value = str(text or "").strip()
        if not value or value == "Ready":
            return False
        low = value.lower()
        noisy = (
            "analyzing with",
            "collecting ida context",
            "testing llm",
            "action chat",
            "pseudo diff ai",
            "provider timeout threshold",
        )
        if any(part in low for part in noisy):
            return False
        if low.endswith("..."):
            return False
        return True

    def _show_toast(self, text: str, ok: bool = True) -> None:
        toast = getattr(self, "toast", None)
        if toast is not None:
            toast.show_message(text, ok=ok)

    def resizeEvent(self, event) -> None:
        try:
            super().resizeEvent(event)
        except Exception:
            pass
        overlay = getattr(self, "made_overlay", None)
        if overlay is not None:
            overlay.setGeometry(self.rect())
        toast = getattr(self, "toast", None)
        if toast is not None and toast.isVisible():
            toast.reposition()

    def _show_made_overlay(self) -> None:
        overlay = getattr(self, "made_overlay", None)
        if overlay is not None:
            overlay.play()

    def _refresh_focus_indicator(self) -> None:
        try:
            snap = navigation_snapshot()
            focus = preferred_focus_ea(snap)
        except Exception as exc:
            self.focus_indicator_label.setText("AI focus: unavailable")
            self.focus_indicator_label.setStyleSheet(
                "color:#ff9f9f; font-weight:700; padding:3px 7px; border:1px solid #553030; background:#271c1e;"
            )
            self.focus_indicator_label.setToolTip("Focus tracker error: %s" % exc)
            self.btn_jump_focus.setEnabled(False)
            self.btn_mark_review.setEnabled(False)
            return
        source = str(focus.get("source") or "none")
        ea = focus.get("ea") or "-"
        marker_ea = parse_focus_ea(ea)
        symbol = ""
        if marker_ea is not None:
            try:
                symbol = str(ida_name.get_name(marker_ea) or "").strip()
            except Exception:
                symbol = ""
        try:
            age = float(focus.get("age_seconds") or 0.0)
        except Exception:
            age = 0.0
        if source == "none" or not focus.get("ea"):
            color = "#7f8994"
            bg = "#1d2023"
            border = "#343940"
            label = "none"
            clear_focus_marker()
            self._last_focus_marker_ea = None
        elif source == "locked":
            color = "#d7a8bb"
            bg = "#2a2228"
            border = "#5a3b49"
            label = "LOCKED  %s  %.1fs" % (ea, age)
        elif source == "mouse" and age <= 2.0:
            color = "#a9cdb6"
            bg = "#202823"
            border = "#34473b"
            label = "active mouse  %s  %.1fs" % (ea, age)
        elif source in ("mouse", "last_click") and age <= 30.0:
            color = "#d2c394"
            bg = "#27251e"
            border = "#514a32"
            label = "cached %s  %s  %.1fs" % (source, ea, age)
        else:
            color = "#adc7d7"
            bg = "#20272c"
            border = "#344955"
            label = "%s  %s  %.1fs" % (source, ea, age)
        if symbol:
            label = "%s  %s" % (label, symbol)
        if marker_ea is not None and bool(getattr(self, "focus_highlight_enabled", True)):
            if self._last_focus_marker_ea != marker_ea:
                set_focus_marker(marker_ea)
                self._last_focus_marker_ea = marker_ea
        elif marker_ea is None or not bool(getattr(self, "focus_highlight_enabled", True)):
            clear_focus_marker()
            self._last_focus_marker_ea = None
        self.focus_indicator_label.setText(
            "<span style='color:%s; font-weight:900;'>●</span> "
            "<span style='color:%s; font-weight:700;'>AI focus</span> "
            "<span style='color:#edf1f5; font-weight:700;'>%s</span>"
            % (color, color, html.escape(label))
        )
        self.focus_indicator_label.setText(
            "<span style='color:%s; font-weight:700;'>AI focus</span> "
            "<span style='color:#dfe5ea; font-weight:600;'>%s</span>"
            % (color, html.escape(label))
        )
        self.focus_indicator_label.setStyleSheet(
            "padding:3px 7px; border:1px solid %s; border-radius:4px; background:%s;" % (border, bg)
        )
        line = str(focus.get("line") or "").strip()
        widget = focus.get("widget") if isinstance(focus.get("widget"), dict) else {}
        highlight = focus.get("highlight") if isinstance(focus.get("highlight"), dict) else {}
        tip = [
            "Source: %s" % source,
            "Address: %s" % ea,
            "Name: %s" % (symbol or "-"),
            "Age: %.2fs" % age,
            "Widget: %s" % (widget.get("title") or "-"),
            "Lock shortcut: hold A for 1.5s to lock here; press A again to unlock.",
        ]
        if source == "locked":
            tip.append("Locked from: %s" % (focus.get("locked_from") or "-"))
            tip.append("Lock reason: %s" % (focus.get("lock_reason") or "-"))
        if highlight.get("text"):
            tip.append("Highlight: %s" % highlight.get("text"))
        if line:
            tip.append("Line: %s" % line[:700])
        self.focus_indicator_label.setToolTip("\n".join(tip))
        self.btn_jump_focus.setEnabled(marker_ea is not None)
        self.btn_mark_review.setEnabled(marker_ea is not None)

    def _on_focus_highlight_toggled(self, checked: bool) -> None:
        self.focus_highlight_enabled = bool(checked)
        if not self.focus_highlight_enabled:
            clear_focus_marker()
            self._last_focus_marker_ea = None
        self._refresh_focus_indicator()

    def _jump_to_ai_focus(self) -> None:
        snap = navigation_snapshot()
        focus = preferred_focus_ea(snap)
        ea = parse_focus_ea(focus.get("ea"))
        if ea is None:
            self._set_status("No AI focus address", ok=False)
            return
        try:
            ida_kernwin.jumpto(ea)
            self._set_status("Jumped to AI focus 0x%X" % ea, ok=True)
        except Exception as exc:
            self._set_status("Jump to AI focus failed", ok=False)
            info("Jump to AI focus failed: %s" % exc)

    def _mark_ai_focus_review(self) -> None:
        snap = navigation_snapshot()
        focus = preferred_focus_ea(snap)
        ea = parse_focus_ea(focus.get("ea"))
        if ea is None:
            self._set_status("No AI focus address to mark", ok=False)
            return
        source = str(focus.get("source") or "focus")
        line = sanitize_text(str(focus.get("line") or ""), max_chars=260, collapse_ws=True)
        note = "Monstey review point from %s focus. Next: inspect XREFs/callers, run Quick Local Pass, and decide hook/map usefulness." % source
        if line:
            note += " Focus line: %s" % line
        result = mark_review_item(ea, note)
        try:
            name = str(ida_name.get_name(ea) or "").strip()
        except Exception:
            name = ""
        upsert_review_mark(
            self._map_context(),
            {
                "address": "0x%X" % ea,
                "name": name,
                "source": source,
                "status": "review",
                "note": note,
                "line": line,
            },
        )
        refresh_ida()
        self._refresh_review_queue()
        self._refresh_game_map()
        self._set_status(result.get("message", "Marked review point"), ok=bool(result.get("ok")))
        info(result.get("message", "Marked review point"))

    def _schedule_idb_rename_refresh(self, ea: Any, new_name: Any = "") -> None:
        try:
            QtCore.QTimer.singleShot(90, lambda: self._refresh_after_idb_rename(ea, new_name))
        except Exception:
            pass

    def _refresh_after_idb_rename(self, ea: Any = None, new_name: Any = "") -> None:
        changed = False
        ea_int = parse_focus_ea(ea)
        name = str(new_name or "").strip()
        if ea_int is not None and not name:
            try:
                name = str(ida_name.get_name(ea_int) or "").strip()
            except Exception:
                name = ""
        if ea_int is not None and name and self.current_context:
            changed = self._patch_context_name_for_ea(self.current_context, ea_int, name)
            if changed:
                self._refresh_context_label(self.current_context)
                if self.current_analysis:
                    self._render_analysis(self.current_analysis)
        self._refresh_focus_indicator()
        try:
            self._refresh_game_map()
        except Exception:
            pass
        refresh_ida()

    def _patch_context_name_for_ea(self, ctx: Dict[str, Any], ea: int, name: str) -> bool:
        target = "0x%X" % int(ea)
        changed = False

        def addr_matches(value: Any) -> bool:
            parsed = parse_focus_ea(value)
            return parsed is not None and int(parsed) == int(ea)

        def patch_named_dict(data: Dict[str, Any]) -> None:
            nonlocal changed
            address_keys = (
                "address",
                "ea",
                "from",
                "to",
                "start_ea",
                "function_start",
                "target_ea",
                "callsite_ea",
                "item_head",
            )
            if not any(addr_matches(data.get(key)) for key in address_keys):
                return
            for key in ("name", "function", "function_name", "label"):
                if key in data and data.get(key) != name:
                    data[key] = name
                    changed = True

        start_ea = parse_focus_ea(ctx.get("start_ea"))
        if start_ea is not None and int(start_ea) == int(ea):
            if ctx.get("function_name") != name:
                ctx["function_name"] = name
                changed = True
            artifact = ctx.get("data_artifact")
            if isinstance(artifact, dict):
                for key in ("name", "label"):
                    if artifact.get(key) != name:
                        artifact[key] = name
                        changed = True

        stack = [ctx]
        seen = set()
        while stack:
            item = stack.pop()
            obj_id = id(item)
            if obj_id in seen:
                continue
            seen.add(obj_id)
            if isinstance(item, dict):
                patch_named_dict(item)
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)

        if changed:
            info("IDA rename refresh: %s is now %s" % (target, name))
        return changed

    def _set_busy(self, busy: bool) -> None:
        for widget in (
            self.btn_analyze_func,
            self.btn_analyze_asm,
            self.btn_rebuild_pseudo,
            self.btn_quick_local,
            self.btn_preview_focus,
            self.btn_test_llm,
            self.btn_pseudo_rebuild_capture,
            self.btn_pseudo_rebuild_analyze,
            self.btn_pseudo_rebuild_local,
            self.btn_pseudo_rebuild_copy,
            self.btn_save_settings,
            self.btn_send_action,
            self.btn_save_dump_context,
            self.btn_reload_dump_context,
            self.btn_seed_feedback,
            self.btn_save_feedback,
            self.btn_clear_feedback,
            self.btn_pseudodiff_local,
            self.btn_pseudodiff_ai,
            self.btn_pseudodiff_clear,
            self.btn_save_external_evidence,
            self.btn_reload_external_evidence,
            self.btn_import_external_evidence,
            self.btn_template_external_evidence,
            self.btn_preview_external_evidence,
            self.btn_import_integration,
            self.btn_template_integration,
            self.btn_preview_integration,
            self.btn_push_integration,
            self.btn_structure_scout,
            self.btn_signature_scout,
            self.btn_all_static_scouts,
            self.btn_toolchain_check,
            self.btn_obfuscation_scout,
            self.btn_toolchain_scouts,
        ):
            widget.setEnabled(not busy)
        self.btn_refresh_map.setEnabled(not busy)
        if not busy:
            has_rebuild = bool(self.rebuild_result and self.pseudo_rebuild_edit.toPlainText().strip())
            self.btn_pseudo_rebuild_analyze.setEnabled(has_rebuild)
            self.btn_pseudo_rebuild_local.setEnabled(has_rebuild)
            self.btn_pseudo_rebuild_copy.setEnabled(has_rebuild)
        if busy:
            self.btn_apply_name.setEnabled(False)
            self.btn_apply_comments.setEnabled(False)
            self.btn_trainer_radar.setEnabled(False)
            self.btn_call_returns.setEnabled(False)
            self.btn_hook_modify.setEnabled(False)
        else:
            can_experiment = bool(self.current_analysis and self.current_context and self.current_context.get("has_function"))
            valid_name = validate_function_name(self.current_analysis.get("suggested_function_name")) if self.current_analysis else ""
            self.btn_apply_name.setEnabled(bool(valid_name))
            self.btn_apply_comments.setEnabled(bool(self.current_analysis and (
                self.current_analysis.get("comments")
                or self.current_analysis.get("evidence")
                or self.current_analysis.get("summary")
            )))
            self.btn_call_returns.setEnabled(can_experiment)
            self.btn_hook_modify.setEnabled(can_experiment)
            self.btn_trainer_radar.setEnabled(bool(self.current_analysis and self.current_analysis.get("trainer_radar")))
            self.btn_send_action.setEnabled(bool(can_experiment and self.current_action_kind))

    def _ensure_debug_trace(self) -> DebugTraceDialog:
        if self.debug_dialog is None:
            self.debug_dialog = DebugTraceDialog(self)
            self.debug_dialog.setStyleSheet(PANEL_STYLE)
        return self.debug_dialog

    def _show_debug_trace(self) -> None:
        dialog = self._ensure_debug_trace()
        dialog.set_trace_html(self._analysis_log_html())
        dialog.show()
        try:
            dialog.raise_()
            dialog.activateWindow()
        except Exception:
            pass

    def _ensure_trainer_radar(self) -> TrainerRadarDialog:
        if self.trainer_radar_dialog is None:
            self.trainer_radar_dialog = TrainerRadarDialog(self)
            self.trainer_radar_dialog.setStyleSheet(PANEL_STYLE)
        return self.trainer_radar_dialog

    def _show_trainer_radar(self) -> None:
        if not self.current_analysis:
            self._set_status("Analyze a function first", ok=False)
            return
        dialog = self._ensure_trainer_radar()
        dialog.set_radar_html(self._trainer_radar_popup_html(self.current_analysis))
        dialog.show()
        try:
            dialog.raise_()
            dialog.activateWindow()
        except Exception:
            pass

    def _copy_summary(self) -> None:
        text = self.last_summary_text or self.summary_edit.toPlainText()
        QtWidgets.QApplication.clipboard().setText(text)
        self._set_status("Summary copied", ok=True)

    def _set_combo_text(self, combo: QtWidgets.QComboBox, text: Any) -> None:
        needle = str(text or "").strip().lower()
        if not needle:
            combo.setCurrentIndex(0)
            return
        for idx in range(combo.count()):
            if str(combo.itemText(idx)).strip().lower() == needle:
                combo.setCurrentIndex(idx)
                return

    def _seed_feedback_from_current(self) -> None:
        if not self.current_analysis:
            self._set_status("Analyze a function first", ok=False)
            return
        trainer = self.current_analysis.get("trainer_assessment") or {}
        if not isinstance(trainer, dict):
            trainer = {}
        name = validate_function_name(self.current_analysis.get("suggested_function_name"))
        if name:
            self.feedback_name_edit.setText(name)
        self._set_combo_text(self.feedback_role_combo, trainer.get("category"))
        self._set_combo_text(self.feedback_usefulness_combo, trainer.get("usefulness"))
        self._set_combo_text(self.feedback_strategy_combo, trainer.get("best_hook_strategy"))
        summary = str(self.current_analysis.get("summary") or "").strip()
        if summary and not self.feedback_notes_edit.toPlainText().strip():
            self.feedback_notes_edit.setPlainText("Current AI summary to correct:\n%s\n\nCorrection:\n" % summary)
        self.tabs.setCurrentWidget(self.feedback_tab)
        self._set_status("Feedback seeded from current analysis", ok=True)

    def _clear_feedback(self) -> None:
        self.feedback_name_edit.clear()
        self.feedback_role_combo.setCurrentIndex(0)
        self.feedback_usefulness_combo.setCurrentIndex(0)
        self.feedback_strategy_combo.setCurrentIndex(0)
        self.feedback_notes_edit.clear()
        self.feedback_status_label.clear()

    def _save_feedback(self) -> None:
        if not self.current_context:
            self._set_status("No current function/region context for feedback", ok=False)
            return
        raw_name = self.feedback_name_edit.text().strip()
        corrected_name = validate_function_name(raw_name) if raw_name else ""
        if raw_name and not corrected_name:
            self._set_status("Corrected name must be a valid snake_case IDA name", ok=False)
            return
        notes = sanitize_text(self.feedback_notes_edit.toPlainText(), max_chars=4000).strip()
        feedback = {
            "corrected_name": corrected_name,
            "corrected_role": self.feedback_role_combo.currentText().strip(),
            "usefulness": self.feedback_usefulness_combo.currentText().strip(),
            "strategy": self.feedback_strategy_combo.currentText().strip(),
            "notes": notes,
            "previous_summary": (self.current_analysis or {}).get("summary") if isinstance(self.current_analysis, dict) else "",
            "previous_suggested_name": (self.current_analysis or {}).get("suggested_function_name") if isinstance(self.current_analysis, dict) else "",
        }
        has_feedback = any(str(value or "").strip() for key, value in feedback.items() if key.startswith("corrected") or key in ("usefulness", "strategy", "notes"))
        if not has_feedback:
            self._set_status("Add at least one correction or note", ok=False)
            return
        try:
            path = upsert_feedback(self.current_context, feedback)
            self.feedback_status_label.setText("Saved feedback for %s into %s" % (self.current_context.get("start_ea"), path))
            self._refresh_game_map()
            self._set_status("Feedback saved into Process Map", ok=True)
            info("Feedback saved: %s" % path)
        except Exception as exc:
            self._set_status("Feedback save failed", ok=False)
            info("Feedback save failed: %s" % exc)

    def _pseudodiff_inputs(self) -> tuple:
        return (
            sanitize_text(self.pseudodiff_old_edit.toPlainText(), max_chars=240000),
            sanitize_text(self.pseudodiff_new_edit.toPlainText(), max_chars=240000),
            sanitize_text(self.pseudodiff_goal_edit.text(), max_chars=900, collapse_ws=True),
        )

    def _diff_card(self, title: str, values: Any, color: str, empty: str = "none", limit: int = 8) -> str:
        if not isinstance(values, list):
            values = [] if not values else [values]
        rows = []
        for value in values[:limit]:
            text = str(value or "").strip()
            if not text:
                continue
            rows.append(
                "<div style='margin:4px 0; padding-left:8px; border-left:2px solid %s; line-height:1.35;'>%s</div>"
                % (color, html.escape(text))
            )
        body = "".join(rows) if rows else "<div style='color:#7f8994;'>%s</div>" % html.escape(empty)
        return (
            "<td valign='top' width='50%%' style='padding:5px;'>"
            "<div style='background:#20252a; border:1px solid #333b44; border-radius:4px; padding:8px;'>"
            "<div style='color:%s; font-weight:700; margin-bottom:5px;'>%s</div>%s"
            "</div></td>"
            % (color, html.escape(title), body)
        )

    def _pseudodiff_html(self, local: Dict[str, Any], report_text: str = "") -> str:
        local = local if isinstance(local, dict) else {}
        calls = local.get("calls") if isinstance(local.get("calls"), dict) else {}
        constants = local.get("constants") if isinstance(local.get("constants"), dict) else {}
        offsets = local.get("offsets") if isinstance(local.get("offsets"), dict) else {}
        risk = str(local.get("porting_risk") or "unknown").lower()
        risk_color = {"low": "#9af2b2", "medium": "#ffd58a", "high": "#ff9f9f"}.get(risk, "#98f0df")
        summary = str(local.get("summary") or "-")
        impact = str(local.get("impact") or "-")
        blocks = local.get("changed_blocks") if isinstance(local.get("changed_blocks"), list) else []
        block_lines = []
        for idx, block in enumerate(blocks[:4], 1):
            if not isinstance(block, dict):
                continue
            old = " | ".join(str(line) for line in (block.get("old") or [])[:3])
            new = " | ".join(str(line) for line in (block.get("new") or [])[:3])
            block_lines.append("Block %d: old [%s] -> new [%s]" % (idx, old, new))
        ai_html = ""
        if report_text:
            ai_html = (
                "<div style='margin-top:8px; padding:5px 7px; background:#242a30; "
                "border-left:3px solid #d2b6ff; font-weight:700; color:#d2b6ff;'>AI / Copyable Report</div>"
                "<pre style='white-space:pre-wrap; color:#edf1f5; background:#15191d; border:1px solid #303840; "
                "padding:8px; margin:0;'>%s</pre>"
                % html.escape(str(report_text or ""))
            )
        return (
            "<html><body style='font-family:Segoe UI, Arial; color:#edf1f5; background:#1b1d20;'>"
            "<div style='margin-bottom:8px; padding:7px 9px; background:#242a30; "
            "border-left:3px solid %s; font-weight:700; color:%s;'>Pseudo Diff Lab</div>"
            "<div style='padding:8px; background:#1d2227; border:1px solid #333b44;'>%s%s%s</div>"
            "<div style='line-height:1.35; padding:7px 8px; background:#181c20; border-left:3px solid %s;'>%s<br>%s</div>"
            "<table width='100%%' cellspacing='0' cellpadding='0' style='margin-top:4px;'>"
            "<tr>%s%s</tr><tr>%s%s</tr><tr>%s%s</tr></table>"
            "%s"
            "</body></html>"
            % (
                risk_color,
                risk_color,
                self._chip("Similarity", local.get("similarity", "-"), "#9bd7ff"),
                self._chip("Porting risk", risk, risk_color),
                self._chip("Mode", local.get("mode", "-"), "#98f0df"),
                risk_color,
                html.escape(summary),
                html.escape(impact),
                self._diff_card("Calls added", calls.get("added"), "#9af2b2"),
                self._diff_card("Calls removed", calls.get("removed"), "#ffb3a7"),
                self._diff_card("Offsets added", offsets.get("added"), "#f0a7c6"),
                self._diff_card("Offsets removed", offsets.get("removed"), "#ff9f9f"),
                self._diff_card("Constants added", constants.get("added"), "#ffd58a", limit=10),
                self._diff_card("Changed blocks", block_lines, "#9bd7ff", empty="no changed block preview", limit=6),
                ai_html,
            )
        )

    def _run_pseudodiff_local(self) -> None:
        old_text, new_text, _goal = self._pseudodiff_inputs()
        if not old_text.strip() or not new_text.strip():
            self._set_status("Paste old and new pseudocode first", ok=False)
            return
        local = local_pseudocode_diff(old_text, new_text)
        text = render_local_pseudocode_diff_text(local)
        self.pseudodiff_last_text = text
        self.pseudodiff_result.setHtml(self._pseudodiff_html(local, text))
        self._set_status("Local pseudocode diff ready", ok=True)

    def _run_pseudodiff_ai(self) -> None:
        old_text, new_text, goal = self._pseudodiff_inputs()
        if not old_text.strip() or not new_text.strip():
            self._set_status("Paste old and new pseudocode first", ok=False)
            return
        self._save_settings_from_ui()
        local = local_pseudocode_diff(old_text, new_text)
        local_text = render_local_pseudocode_diff_text(local)
        self.pseudodiff_last_text = local_text
        self.pseudodiff_result.setHtml(self._pseudodiff_html(local, local_text + "\n\nAI is generating..."))
        self._set_busy(True)
        self._set_status("Pseudo Diff AI...", ok=True)
        self.pseudodiff_worker = PseudoDiffWorker(self.cfg, old_text, new_text, goal, self)
        self.pseudodiff_worker.progress.connect(lambda message: self._set_status(str(message), ok=True))
        self.pseudodiff_worker.succeeded.connect(self._on_pseudodiff_ok)
        self.pseudodiff_worker.failed.connect(self._on_pseudodiff_failed)
        self.pseudodiff_worker.finished.connect(lambda: self._set_busy(False))
        self.pseudodiff_worker.start()

    def _on_pseudodiff_ok(self, local: Dict[str, Any], report_text: str) -> None:
        self.pseudodiff_last_text = str(report_text or render_local_pseudocode_diff_text(local))
        self.pseudodiff_result.setHtml(self._pseudodiff_html(local, self.pseudodiff_last_text))
        self._set_status("Pseudo Diff ready", ok=True)

    def _on_pseudodiff_failed(self, message: str) -> None:
        self._set_status("Pseudo Diff error", ok=False)
        self.pseudodiff_result.setPlainText(str(message or "Unknown error"))

    def _copy_pseudodiff_result(self) -> None:
        text = self.pseudodiff_last_text or self.pseudodiff_result.toPlainText()
        if not str(text or "").strip():
            self._set_status("No diff result to copy", ok=False)
            return
        QtWidgets.QApplication.clipboard().setText(str(text))
        self._set_status("Pseudo Diff copied", ok=True)

    def _clear_pseudodiff(self) -> None:
        self.pseudodiff_old_edit.clear()
        self.pseudodiff_new_edit.clear()
        self.pseudodiff_goal_edit.clear()
        self.pseudodiff_result.clear()
        self.pseudodiff_last_text = ""

    def _pipeline_style(self, state: str, active: bool = False) -> str:
        colors = {
            "pending": ("#20252a", "#3a424c", "#7f8994"),
            "run": ("#1d2b36", "#4a6b84", "#9bd7ff"),
            "ok": ("#182820", "#346b4c", "#8df29b"),
            "warn": ("#302a19", "#705d2d", "#ffd58a"),
            "error": ("#301d21", "#6b3944", "#ff9f9f"),
        }
        bg, border, fg = colors.get(state, colors["pending"])
        if active:
            border = "#9bd7ff" if state == "run" else border
        return (
            "padding:4px 7px; border:1px solid %s; border-radius:5px; "
            "background:%s; color:%s; font-weight:700;"
            % (border, bg, fg)
        )

    def _reset_pipeline(self) -> None:
        self.pipeline_state = {}
        for key, label in getattr(self, "pipeline_labels", {}).items():
            self.pipeline_state[key] = "pending"
            label.setStyleSheet(self._pipeline_style("pending"))
        try:
            self.pipeline_timer.stop()
        except Exception:
            pass

    def _set_pipeline_step(self, key: str, state: str) -> None:
        if key not in getattr(self, "pipeline_labels", {}):
            return
        self.pipeline_state[key] = state
        self.pipeline_labels[key].setStyleSheet(self._pipeline_style(state, active=(state == "run")))
        if any(value == "run" for value in self.pipeline_state.values()):
            if not self.pipeline_timer.isActive():
                self.pipeline_timer.start()
        else:
            self.pipeline_timer.stop()

    def _pipeline_tick(self) -> None:
        self.pipeline_pulse = (int(getattr(self, "pipeline_pulse", 0)) + 1) % 2
        for key, state in getattr(self, "pipeline_state", {}).items():
            label = self.pipeline_labels.get(key)
            if label is not None:
                label.setStyleSheet(self._pipeline_style(state, active=(state == "run" and self.pipeline_pulse == 1)))

    def _pipeline_from_log(self, message: str, level: str) -> None:
        low = str(message or "").lower()
        if "run #" in low and "started" in low:
            self._set_pipeline_step("focus", "run")
        if "collecting focused ida context" in low:
            self._set_pipeline_step("focus", "ok")
            self._set_pipeline_step("context", "run")
        elif "ida context ready" in low:
            self._set_pipeline_step("context", "ok")
        elif "external evidence" in low or "process/dump context" in low or "evidence pack" in low:
            self._set_pipeline_step("evidence", "ok" if level != "warn" else "warn")
        elif "provider ready" in low or "worker started" in low:
            self._set_pipeline_step("provider", "ok")
            self._set_pipeline_step("llm", "run")
        elif "sending chat/completions" in low or "waiting for" in low:
            self._set_pipeline_step("llm", "run")
        elif "llm response received" in low:
            self._set_pipeline_step("llm", "ok")
            self._set_pipeline_step("parse", "run")
        elif "json parse failed" in low or "repair" in low:
            self._set_pipeline_step("parse", "warn")
        elif "parsing json" in low:
            self._set_pipeline_step("parse", "run")
        elif "local semantic" in low or "fallback" in low or "enrichment" in low:
            self._set_pipeline_step("enrich", "warn" if level in ("warn", "error") else "ok")
        elif "analysis ready" in low or "quick local pass" in low:
            self._set_pipeline_step("ready", "ok")

    def _reset_analysis_log(self) -> None:
        self.analysis_log_lines = []
        self.analysis_started_at = time.perf_counter()
        self.analysis_log_last_tick = -1
        self.analysis_timeout_last_warn = -1
        self.analysis_log_active = True
        self._reset_pipeline()
        self._show_debug_trace()

    def _append_analysis_log(self, message: str, level: str = "info") -> None:
        text = str(message or "").strip()
        if not text:
            return
        try:
            info("analysis: %s" % text)
        except Exception:
            pass
        if not bool(getattr(self, "analysis_log_active", False)):
            return
        self._pipeline_from_log(text, level)
        self.analysis_log_lines.append({
            "time": time.strftime("%H:%M:%S"),
            "level": level,
            "message": text,
        })
        if len(self.analysis_log_lines) > 90:
            self.analysis_log_lines = self.analysis_log_lines[-90:]
        self._render_analysis_progress()

    def _analysis_log_html(self) -> str:
        colors = {
            "step": "#9bd7ff",
            "info": "#98f0df",
            "wait": "#ffd58a",
            "ok": "#9af2b2",
            "warn": "#ffcf6e",
            "error": "#ff9f9f",
        }
        rows = []
        for item in self.analysis_log_lines:
            color = colors.get(str(item.get("level") or "info"), colors["info"])
            rows.append(
                "<tr>"
                "<td style='width:74px; color:#7f8994; padding:4px 7px; border-bottom:1px solid #252b31;'>%s</td>"
                "<td style='width:72px; color:%s; font-weight:700; padding:4px 7px; border-bottom:1px solid #252b31;'>%s</td>"
                "<td style='color:#edf1f5; padding:4px 7px; border-bottom:1px solid #252b31;'>%s</td>"
                "</tr>"
                % (
                    html.escape(str(item.get("time") or "")),
                    color,
                    html.escape(str(item.get("level") or "info").upper()),
                    html.escape(str(item.get("message") or "")),
                )
            )
        return (
            "<html><body style='font-family:Segoe UI, Arial; background:#1b1d20; color:#edf1f5;'>"
            "<div style='margin-bottom:7px; padding:6px 8px; background:#242a30; "
            "border-left:3px solid #9bd7ff; font-weight:700; color:#9bd7ff;'>Analysis processing trace</div>"
            "<div style='margin-bottom:7px; color:#aab3bd;'>Live debug while Monstey collects context, sends the prompt, waits for the provider, parses JSON, and falls back if needed.</div>"
            "<table width='100%%' cellspacing='0' cellpadding='0' style='border:1px solid #333b44; background:#181c20;'>%s</table>"
            "</body></html>" % "".join(rows)
        )

    def _render_analysis_progress(self) -> None:
        if self.debug_dialog is not None:
            self.debug_dialog.set_trace_html(self._analysis_log_html())

    def _start_analysis_debug_timer(self) -> None:
        self.analysis_started_at = time.perf_counter()
        self.analysis_log_last_tick = -1
        self.analysis_debug_timer.start()

    def _stop_analysis_debug_timer(self) -> None:
        try:
            self.analysis_debug_timer.stop()
        except Exception:
            pass
        self.analysis_log_active = False

    def _analysis_watchdog_seconds(self) -> int:
        return watchdog_seconds(self.cfg, self.current_context or {})

    def _analysis_provider_label(self) -> str:
        policy = agent_policy(self.cfg, self.current_context or {})
        mode = str(policy.get("effective") or policy.get("requested") or "Single")
        if mode == "Council" and getattr(self.cfg, "provider", "local") == "gemini":
            return "Local / OpenAI-compatible (Council forced)"
        return self.cfg.active_provider_label()

    def _analysis_model_label(self) -> str:
        policy = agent_policy(self.cfg, self.current_context or {})
        mode = str(policy.get("effective") or policy.get("requested") or "Single")
        if mode == "Council" and getattr(self.cfg, "provider", "local") == "gemini":
            return getattr(self.cfg, "model", "") or "local model"
        route = model_policy(self.cfg, self.current_context or {})
        if route.get("reason"):
            return "%s (routed from %s)" % (route.get("effective"), route.get("requested"))
        return self.cfg.active_model()

    def _analysis_debug_tick(self) -> None:
        if not bool(getattr(self, "analysis_log_active", False)):
            return
        elapsed = int(time.perf_counter() - float(getattr(self, "analysis_started_at", 0.0) or 0.0))
        timeout_seconds = int(getattr(self.cfg, "analysis_timeout_seconds", 75))
        watchdog_seconds = self._analysis_watchdog_seconds()
        provider = self._analysis_provider_label()
        policy = agent_policy(self.cfg, self.current_context or {})
        agent_mode = str(policy.get("effective") or policy.get("requested") or "Single")
        requested = str(policy.get("requested") or agent_mode)
        mode_label = agent_mode if agent_mode == requested else "%s from %s" % (agent_mode, requested)
        self._set_status("Analyzing with %s [%s]... %ds/%ds" % (provider, mode_label, elapsed, watchdog_seconds), ok=True)
        if elapsed > 0 and elapsed % 5 == 0 and elapsed != self.analysis_log_last_tick:
            self.analysis_log_last_tick = elapsed
            if elapsed >= timeout_seconds:
                if self.analysis_timeout_last_warn < 0 or elapsed - self.analysis_timeout_last_warn >= 15:
                    self.analysis_timeout_last_warn = elapsed
                    self._append_analysis_log(
                        "provider timeout threshold reached at %ds; UI watchdog fallback is scheduled around %ds"
                        % (elapsed, watchdog_seconds),
                        "warn",
                    )
            else:
                self._append_analysis_log(
                    "waiting for %s response: %ds elapsed, timeout at %ds"
                    % (provider, elapsed, timeout_seconds),
                    "wait",
                )

    def _preview_focus(self) -> None:
        snap = navigation_snapshot()
        focus = preferred_focus_ea(snap)
        self.raw_edit.setPlainText(json.dumps({"preferred_focus": focus, "navigation": snap}, indent=2, sort_keys=True))
        self._set_status("Focus preview ready", ok=True)
        self.tabs.setCurrentWidget(self.tabs.widget(0))

    def _capture_asm_reconstruction(self) -> None:
        self._save_settings_from_ui()
        self._set_status("Capturing ASM for pseudo rebuild...", ok=True)
        try:
            QtWidgets.QApplication.processEvents()
        except Exception:
            pass
        try:
            ctx = collect_context(force_asm=True, cfg=self.cfg)
            result = reconstruct_pseudocode_from_context(ctx)
        except Exception as exc:
            self._set_status("Pseudo rebuild capture failed", ok=False)
            self.pseudo_rebuild_status_label.setText("Pseudo rebuild capture failed")
            self.pseudo_rebuild_conf_label.setText("Error")
            self.pseudo_rebuild_conf_label.setStyleSheet("color:#ff9f9f; font-weight:700;")
            self.pseudo_rebuild_warning_label.setText(str(exc))
            self.pseudo_rebuild_asm_edit.setPlainText("")
            self.pseudo_rebuild_edit.setPlainText("")
            self.btn_pseudo_rebuild_analyze.setEnabled(False)
            self.btn_pseudo_rebuild_local.setEnabled(False)
            self.btn_pseudo_rebuild_copy.setEnabled(False)
            info("Pseudo rebuild capture failed: %s" % exc)
            return

        self.rebuild_context = ctx
        self.rebuild_result = result
        self.current_context = ctx
        try:
            self._update_game_label(ctx)
        except Exception:
            pass
        asm_text = render_asm_source(ctx)
        pseudo = str(result.get("pseudo") or "")
        warnings = result.get("warnings") or []
        confidence = float(result.get("confidence") or 0.0)
        source_start = result.get("source_start") or ctx.get("start_ea") or ctx.get("current_ea") or "-"
        source_end = result.get("source_end") or ctx.get("end_ea") or "-"
        translated = int(result.get("translated_instruction_count") or 0)
        total = int(result.get("instruction_count") or 0)

        self.pseudo_rebuild_asm_edit.setPlainText(asm_text)
        self.pseudo_rebuild_edit.setPlainText(pseudo)
        self.pseudo_rebuild_status_label.setText(
            "Source %s - %s | %s | %d/%d instructions translated"
            % (source_start, source_end, ctx.get("region_kind") or ctx.get("mode") or "-", translated, total)
        )
        color = "#9af2b2" if confidence >= 0.48 else "#ffd58a" if confidence >= 0.28 else "#ff9f9f"
        self.pseudo_rebuild_conf_label.setStyleSheet("color:%s; font-weight:700;" % color)
        self.pseudo_rebuild_conf_label.setText("Approx %.2f" % confidence)
        self.pseudo_rebuild_warning_label.setText(" | ".join(str(item) for item in warnings[:4]))
        has_pseudo = bool(pseudo.strip())
        self.btn_pseudo_rebuild_analyze.setEnabled(has_pseudo)
        self.btn_pseudo_rebuild_local.setEnabled(has_pseudo)
        self.btn_pseudo_rebuild_copy.setEnabled(has_pseudo)
        self.tabs.setCurrentWidget(self.pseudo_rebuild_tab)
        self._refresh_context_label(ctx)
        self._set_status("Pseudo rebuild ready" if has_pseudo else "Pseudo rebuild produced no code", ok=has_pseudo)
        try:
            self.toast.show_message("Pseudo rebuild ready" if has_pseudo else "No pseudocode generated", ok=has_pseudo)
        except Exception:
            pass

    def _copy_rebuild_pseudocode(self) -> None:
        text = self.pseudo_rebuild_edit.toPlainText()
        if not text.strip():
            self._set_status("No generated pseudocode to copy", ok=False)
            return
        QtWidgets.QApplication.clipboard().setText(text)
        self._set_status("Generated pseudocode copied", ok=True)
        try:
            self.toast.show_message("Generated pseudocode copied", ok=True)
        except Exception:
            pass

    def _analyze_reconstructed_pseudocode(self, local_only: bool = False) -> None:
        if not self.rebuild_context or not self.rebuild_result:
            self._capture_asm_reconstruction()
        if not self.rebuild_context or not self.rebuild_result:
            return
        pseudo = self.pseudo_rebuild_edit.toPlainText()
        if not pseudo.strip():
            self._set_status("Generate or paste pseudocode first", ok=False)
            return
        reconstruction = dict(self.rebuild_result)
        reconstruction["pseudo"] = pseudo
        reconstruction["lines"] = pseudo.splitlines()
        reconstruction["line_count"] = len(reconstruction["lines"])
        ctx = attach_reconstruction_to_context(self.rebuild_context, reconstruction)
        self._start_analysis(
            force_asm=True,
            local_only=local_only,
            prepared_context=ctx,
            run_label="reconstructed_pseudocode",
        )

    def _test_llm(self) -> None:
        self._save_settings_from_ui()
        self._set_busy(True)
        self._set_status("Testing LLM...", ok=True)
        self.test_worker = TestLLMWorker(self.cfg, self)
        self.test_worker.succeeded.connect(self._on_test_ok)
        self.test_worker.failed.connect(self._on_test_failed)
        self.test_worker.finished.connect(lambda: self._set_busy(False))
        self.test_worker.start()

    def _on_test_ok(self, raw: str) -> None:
        self._set_status("LLM connected", ok=True)
        self.llm_detail_label.setStyleSheet("color:#9af2b2; padding:4px 0;")
        self.llm_detail_label.setText(
            "Connected: %s / %s" % (self.cfg.active_provider_label(), self.cfg.active_model())
        )
        self.raw_edit.setPlainText(raw)

    def _on_test_failed(self, message: str) -> None:
        self._set_status("LLM error", ok=False)
        self.llm_detail_label.setStyleSheet("color:#ff9f9f; padding:4px 0;")
        self.llm_detail_label.setText(str(message)[:1600])
        self.raw_edit.setPlainText(message)
        info(message)

    def _local_analysis_from_context(
        self,
        ctx: Dict[str, Any],
        mode: str,
        summary: str,
        risk: str = "",
        local_only: bool = False,
    ) -> Dict[str, Any]:
        analysis = normalize_analysis({
            "mode": mode,
            "summary": summary,
            "confidence": 0.25 if risk else 0.0,
            "evidence": [],
            "comments": [],
            "risks": [risk] if risk else [],
            "next_questions": [],
        })
        analysis = ensure_function_questions(analysis, ctx)
        analysis = ensure_user_context_alignment(analysis, ctx)
        analysis = enrich_analysis_with_local_cues(analysis, ctx)
        analysis = apply_external_evidence_to_analysis(analysis, ctx)
        analysis = build_trainer_intel(analysis, ctx)
        analysis = ensure_function_questions(analysis, ctx)
        analysis["runtime_timing"] = {
            "llm_seconds": 0.0,
            "json_repair_seconds": 0.0,
            "worker_total_seconds": 0.0,
            "max_analysis_tokens": 0,
            "analysis_depth": getattr(self.cfg, "analysis_depth", ""),
            "local_only": bool(local_only),
        }
        return analysis

    def _start_analysis_safely(self, force_asm: bool, local_only: bool = False) -> None:
        try:
            self._start_analysis(force_asm=force_asm, local_only=local_only)
        except Exception as exc:
            message = traceback.format_exc()
            try:
                self._stop_analysis_debug_timer()
            except Exception:
                pass
            try:
                self._set_busy(False)
            except Exception:
                pass
            try:
                self._set_status("Analysis launch error", ok=False)
            except Exception:
                pass
            try:
                self.summary_edit.setPlainText(message)
                self.raw_edit.setPlainText(message)
            except Exception:
                pass
            info("Analysis launch error: %s" % exc)
            info(message)

    def _start_analysis(
        self,
        force_asm: bool,
        local_only: bool = False,
        prepared_context: Optional[Dict[str, Any]] = None,
        run_label: str = "",
    ) -> None:
        self._save_settings_from_ui()
        self.analysis_run_id += 1
        run_id = self.analysis_run_id
        prepared = isinstance(prepared_context, dict)
        self.current_analysis = None
        self.current_action_kind = None
        self.action_history = ""
        self.last_action_code = ""
        self.action_mode_label.setText("Choose a Call/Hook action after an analysis.")
        self.action_chat_edit.clear()
        self.action_code_edit.clear()
        self.btn_send_action.setEnabled(False)
        self.btn_apply_name.setEnabled(False)
        self.btn_apply_comments.setEnabled(False)
        self.btn_copy_summary.setEnabled(False)
        self.btn_trainer_radar.setEnabled(False)
        self.btn_call_returns.setEnabled(False)
        self.btn_hook_modify.setEnabled(False)
        self._reset_analysis_log()
        self.summary_edit.setHtml(
            "<html><body style='font-family:Segoe UI, Arial; background:#1b1d20; color:#edf1f5;'>"
            "<div style='margin-bottom:8px; padding:7px 9px; background:#242a30; border-left:3px solid #9bd7ff; "
            "font-weight:700; color:#9bd7ff;'>Analysis running</div>"
            "<div style='line-height:1.35;'>The live processing trace is in the dedicated Debug Trace window. "
            "The final summary will appear here when the analysis completes.</div>"
            "</body></html>"
        )
        self.last_summary_text = ""
        self._append_analysis_log(
            "run #%d started: %s, local_only=%s"
            % (run_id, run_label or ("force_asm=%s" % bool(force_asm)), bool(local_only)),
            "step",
        )
        if prepared:
            self.current_context = prepared_context
            self._append_analysis_log("using prepared context: %s" % (prepared_context.get("mode") or run_label or "prepared"), "step")
            self._set_status("Preparing generated pseudocode analysis...", ok=True)
        else:
            self._append_analysis_log("collecting focused IDA context...", "step")
            self._set_status("Collecting IDA context...", ok=True)
            try:
                QtWidgets.QApplication.processEvents()
            except Exception:
                pass
            try:
                self.current_context = collect_context(force_asm=force_asm, cfg=self.cfg)
            except Exception as exc:
                self._set_status("IDA context error", ok=False)
                self._append_analysis_log("IDA context error: %s" % exc, "error")
                self._stop_analysis_debug_timer()
                self.summary_edit.setPlainText(str(exc))
                info(str(exc))
                return

        ctx = self.current_context
        timings = (ctx.get("performance_budget") or {}).get("timings_seconds") or {}
        focus = ctx.get("focus") or {}
        self._append_analysis_log(
            "IDA context ready: mode=%s, region=%s, focus=%s 0x%s, context=%.2fs"
            % (
                ctx.get("mode") or "-",
                ctx.get("region_kind") or "-",
                focus.get("source") or "-",
                str(focus.get("item_head") or focus.get("ea") or "-").replace("0x", ""),
                float(timings.get("total_context") or 0.0),
            ),
            "ok",
        )
        if timings:
            self._append_analysis_log(
                "context timings: decompile=%.2fs, xrefs=%.2fs, xref_expand=%.2fs, strings=%.2fs"
                % (
                    float(timings.get("decompile") or 0.0),
                    float(timings.get("xrefs") or 0.0),
                    float(timings.get("xref_expansion") or 0.0),
                    float(timings.get("strings") or 0.0),
                ),
                "info",
            )
        self._save_dump_context_from_ui(silent=True)
        self._save_external_evidence_from_ui(silent=True)
        ctx["known_game_map"] = prompt_memory(load_game_map(ctx))
        ctx["dump_context"] = self._dump_context_for_prompt(ctx)
        ctx["external_evidence"] = self._external_evidence_for_prompt(ctx)
        self._load_dump_context_into_ui()
        self._refresh_external_evidence_preview()
        self._update_game_label(ctx)
        ext = ctx.get("external_evidence") or {}
        ext_summary = ext.get("summary") or {}
        self._append_analysis_log(
            "process/dump context, external evidence (%s total, %s matched), and local Process Map memory injected"
            % (ext_summary.get("total", 0), ext.get("matched_count", 0)),
            "info",
        )
        self._append_analysis_log("waiting for analyst hint dialog...", "wait")
        analyst_hint = self._ask_analyst_hint(ctx)
        if analyst_hint is None:
            self._set_status("Analysis cancelled", ok=False)
            self._append_analysis_log("analysis cancelled by analyst before LLM call", "warn")
            self._stop_analysis_debug_timer()
            self.raw_edit.setPlainText(json.dumps(ctx, indent=2, sort_keys=True))
            return
        ctx["analyst_hint"] = analyst_hint
        ctx["analyst_context"] = {
            "present": bool(analyst_hint),
            "user_hypothesis": analyst_hint,
            "priority": "primary function hypothesis from the analyst; verify with current IDB evidence",
            "expected_model_behavior": "address this hypothesis explicitly in user_context_alignment",
        }
        if analyst_hint:
            self._append_analysis_log("analyst hint added: %d chars" % len(analyst_hint), "ok")
        else:
            self._append_analysis_log("no analyst hint supplied; AI will analyze solo", "info")
        mode = ctx.get("mode")
        self._refresh_context_label(ctx)
        if mode == "data":
            artifact = ctx.get("data_artifact") or {}
            self._append_analysis_log(
                "data/string artifact detected: %s %s; using deterministic data/XREF analysis instead of function LLM"
                % (artifact.get("kind") or "data", artifact.get("start_ea") or artifact.get("address") or ""),
                "step",
            )
            analysis = self._local_analysis_from_context(ctx, "data", "", local_only=True)
            self._on_analysis_ok(analysis, json.dumps(analysis, indent=2, sort_keys=True))
            timings = (ctx.get("performance_budget") or {}).get("timings_seconds") or {}
            self._set_status("Data artifact analysis ready | context %.2fs | no function LLM" % float(timings.get("total_context") or 0.0), ok=True)
            return
        if local_only:
            self._append_analysis_log("Quick Local Pass: running local semantic enrichment only", "step")
            analysis = self._local_analysis_from_context(ctx, "local_quick", "", local_only=True)
            self._on_analysis_ok(analysis, json.dumps(analysis, indent=2, sort_keys=True))
            timings = (ctx.get("performance_budget") or {}).get("timings_seconds") or {}
            self._set_status("Quick local pass ready | context %.2fs | no LLM" % float(timings.get("total_context") or 0.0), ok=True)
            return

        provider_label = self._analysis_provider_label()
        budget = ctx.get("performance_budget") or {}
        effective_budget = self.cfg.depth_budget() if hasattr(self.cfg, "depth_budget") else {}
        policy = agent_policy(self.cfg, ctx)
        requested_mode = str(policy.get("requested") or getattr(self.cfg, "agent_mode", "Single"))
        effective_mode = str(policy.get("effective") or requested_mode)
        mode_label = effective_mode if effective_mode == requested_mode else "%s from %s" % (effective_mode, requested_mode)
        compact_ctx = compact_analysis_context(ctx)
        compact_chars = len(json.dumps(compact_ctx, sort_keys=True))
        self._append_analysis_log(
            "provider ready: %s / %s | agent_mode=%s"
            % (provider_label, self._analysis_model_label(), mode_label),
            "step",
        )
        if policy.get("reason"):
            self._append_analysis_log(str(policy.get("reason")), "warn")
        route = model_policy(self.cfg, ctx)
        if route.get("reason"):
            self._append_analysis_log(str(route.get("reason")), "warn")
        self._append_analysis_log(
            "budgets: depth=%s, asm=%s, pseudo=%s, xrefs=%s, xref_expand=%s, tokens=%s, timeout=%ss"
            % (
                budget.get("analysis_depth") or getattr(self.cfg, "analysis_depth", "-"),
                budget.get("max_asm_lines", getattr(self.cfg, "max_asm_lines", "-")),
                budget.get("max_pseudocode_chars", getattr(self.cfg, "max_pseudocode_chars", "-")),
                budget.get("max_xref_items", getattr(self.cfg, "max_xref_items", "-")),
                budget.get("max_xref_expansion_items", getattr(self.cfg, "max_xref_expansion_items", "-")),
                effective_budget.get("max_analysis_tokens", getattr(self.cfg, "max_analysis_tokens", "-")),
                getattr(self.cfg, "analysis_timeout_seconds", "-"),
            ),
            "info",
        )
        self._append_analysis_log("compact prompt payload ready: %d chars" % compact_chars, "ok")
        self.raw_edit.setPlainText(json.dumps({
            "prompt_context": compact_ctx,
            "raw_context_note": "The worker keeps the full IDA context internally; this tab shows the compact prompt payload for speed/debug.",
        }, indent=2, sort_keys=True))
        self._set_status("Analyzing with %s..." % provider_label, ok=True)
        self._set_busy(True)
        self._start_analysis_debug_timer()

        self.worker = LLMWorker(self.cfg, ctx, self)
        self.worker.progress.connect(lambda message, rid=run_id: self._append_analysis_log(message, "info") if rid == self.analysis_run_id else None)
        self.worker.succeeded.connect(lambda analysis, raw, rid=run_id: self._on_analysis_ok(analysis, raw) if rid == self.analysis_run_id else info("Ignored stale analysis result"))
        self.worker.failed.connect(lambda message, rid=run_id: self._on_analysis_failed(message) if rid == self.analysis_run_id else info("Ignored stale analysis error"))
        self.worker.finished.connect(lambda rid=run_id: self._set_busy(False) if rid == self.analysis_run_id else None)
        self.worker.start()
        watchdog_ms = self._analysis_watchdog_seconds() * 1000
        QtCore.QTimer.singleShot(watchdog_ms, lambda rid=run_id, captured_ctx=ctx: self._analysis_watchdog(rid, captured_ctx))

    def _analysis_watchdog(self, run_id: int, ctx: Dict[str, Any]) -> None:
        if run_id != self.analysis_run_id:
            return
        worker = self.worker
        if worker is None:
            return
        try:
            running = bool(worker.isRunning())
        except Exception:
            running = False
        if not running:
            return
        self.analysis_run_id += 1
        timeout_seconds = self._analysis_watchdog_seconds()
        reason = "Gemini/local provider did not finish within %d seconds; showing local semantic fallback and ignoring late model output." % timeout_seconds
        self._append_analysis_log(reason, "warn")
        self._set_pipeline_step("llm", "warn")
        self._set_pipeline_step("parse", "warn")
        self._set_pipeline_step("enrich", "run")
        self._stop_analysis_debug_timer()
        analysis = self._local_analysis_from_context(ctx, "local_timeout_fallback", reason, risk=reason, local_only=True)
        raw = json.dumps(analysis, indent=2, sort_keys=True)
        self._on_analysis_ok(analysis, raw)
        self._set_busy(False)
        self._set_status("Analysis watchdog fallback | no LLM result after %ds" % timeout_seconds, ok=False)
        info(reason)

    def _ask_analyst_hint(self, ctx: Optional[Dict[str, Any]] = None) -> Optional[str]:
        ctx = ctx or {}
        subject = "this function" if ctx.get("has_function") else "this selected ASM/red region"
        func_name = str(ctx.get("function_name") or "").strip()
        if func_name and func_name != "None":
            subject = "%s (%s)" % (subject, func_name)
        answer = QtWidgets.QMessageBox.question(
            self,
            PLUGIN_NAME,
            "Do you already have an idea of what %s does?\n\nYes: add your hint before analysis.\nNo: let the AI analyze solo." % subject,
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No | QtWidgets.QMessageBox.Cancel,
            QtWidgets.QMessageBox.No,
        )
        if answer == QtWidgets.QMessageBox.Cancel:
            return None
        if answer == QtWidgets.QMessageBox.Yes:
            text, ok = QtWidgets.QInputDialog.getMultiLineText(
                self,
                PLUGIN_NAME,
                "Priority analyst context for the AI:\n\n"
                "Tell it what you think this function/region does, expected role, useful names, "
                "what to verify, or what would prove you wrong.",
                "",
            )
            if not ok:
                return None
            return str(text).strip()
        return ""

    def _refresh_context_label(self, ctx: Optional[Dict[str, Any]] = None) -> None:
        ctx = ctx or self.current_context or {}
        focus = ctx.get("focus") or {}
        budget = ctx.get("performance_budget") or {}
        timings = budget.get("timings_seconds") or {}
        timing_text = ""
        if timings:
            timing_text = " | context %.2fs" % float(timings.get("total_context") or 0.0)
        self.context_label.setText(
            "%s | %s - %s | %s | %s | %s | focus=%s %s%s"
            % (
                ctx.get("function_name"),
                ctx.get("start_ea"),
                ctx.get("end_ea"),
                ctx.get("mode"),
                ctx.get("region_kind"),
                budget.get("analysis_depth") or "-",
                focus.get("source"),
                focus.get("item_head") or focus.get("ea"),
                timing_text,
            )
        )

    def _update_game_label(self, ctx: Dict[str, Any]) -> None:
        game_ctx = ctx.get("game_context") or {}
        process = (
            game_ctx.get("process_display")
            or game_ctx.get("process_name")
            or game_ctx.get("selected_candidate")
            or ""
        )
        process = sanitize_label(process, 160)
        db = ctx.get("database") or {}
        if not process:
            process = sanitize_label(db.get("root_filename") or "unknown", 160)
        lookup = game_ctx.get("online_lookup") or {}
        suffix = " cached/web" if lookup.get("used") else " local"
        self.game_label.setText("Process: %s (%s)" % (process, suffix.strip()))
        self.game_label.setToolTip(
            "Process: %s\nFull dump/process candidate: %s\nProduct/context: %s"
            % (
                process,
                sanitize_label(game_ctx.get("process_full_name") or db.get("root_filename") or "unknown", 220),
                sanitize_label(game_ctx.get("selected_candidate") or "unknown", 220),
            )
        )

    def _on_analysis_ok(self, analysis: Dict[str, Any], raw: str) -> None:
        self._stop_analysis_debug_timer()
        self._set_pipeline_step("llm", "ok" if str(analysis.get("mode") or "").lower() not in ("local_timeout_fallback", "local_quick", "data") else self.pipeline_state.get("llm", "pending"))
        self._set_pipeline_step("parse", "ok" if str(analysis.get("mode") or "").lower() not in ("local_timeout_fallback", "local_quick", "data") else self.pipeline_state.get("parse", "pending"))
        self._set_pipeline_step("enrich", "ok")
        self._set_pipeline_step("ready", "ok")
        self.current_analysis = analysis
        try:
            path = upsert_analysis(self.current_context or {}, analysis)
            info("Process map updated: %s" % path)
            self._refresh_game_map()
        except Exception as exc:
            info("Process map update failed: %s" % exc)
        self._render_analysis(analysis)
        self.last_summary_text = self.summary_edit.toPlainText()
        self.btn_copy_summary.setEnabled(bool(self.last_summary_text.strip()))
        self.raw_edit.setPlainText(json.dumps(analysis, indent=2, sort_keys=True))
        valid_name = validate_function_name(analysis.get("suggested_function_name"))
        status_bits = []
        if valid_name and self.current_context and self.current_context.get("has_function") and bool(self.cfg.auto_rename_after_analysis):
            try:
                start = int(str(self.current_context["start_ea"]), 16)
                result = apply_function_name(start, analysis, only_if_default=True)
                if result.get("ok"):
                    self.current_context["function_name"] = result.get("new_name") or valid_name
                    self._refresh_context_label(self.current_context)
                    refresh_ida()
                rename_message = result.get("message", "")
                if rename_message:
                    status_bits.append(rename_message)
                info("Auto rename: %s" % rename_message)
            except Exception as exc:
                rename_message = "Auto rename failed: %s" % exc
                status_bits.append(rename_message)
                info(rename_message)
        if bool(self.cfg.auto_comment_after_analysis):
            try:
                results = apply_colored_annotations(analysis, self.current_context or {})
                refresh_ida()
                ok_count = sum(1 for item in results if item.get("ok"))
                status_bits.append("AI comments/colors: %d" % ok_count)
                info("Auto comments/colors: applied %d items" % ok_count)
            except Exception as exc:
                message = "Auto comments/colors failed: %s" % exc
                status_bits.append(message)
                info(message)
        self._set_status("Analysis ready%s" % ((" | " + " | ".join(status_bits)) if status_bits else ""), ok=True)
        if self.current_context:
            timings = (self.current_context.get("performance_budget") or {}).get("timings_seconds") or {}
            if timings:
                runtime = analysis.get("runtime_timing") or {}
                self._set_status(
                    "Analysis ready | %s | context %.2fs | sidecar %.2fs | xref %.2fs | analyst %.2fs | decompile %.2fs | xrefs %.2fs | expand %.2fs%s"
                    % (
                        str(runtime.get("agent_mode") or getattr(self.cfg, "agent_mode", "Single")),
                        float(timings.get("total_context") or 0.0),
                        float(runtime.get("toolchain_seconds") or 0.0),
                        float(runtime.get("xref_agent_seconds") or 0.0),
                        float(runtime.get("llm_seconds") or 0.0),
                        float(timings.get("decompile") or 0.0),
                        float(timings.get("xrefs") or 0.0),
                        float(timings.get("xref_expansion") or 0.0),
                        (" | " + " | ".join(status_bits)) if status_bits else "",
                    ),
                    ok=True,
                )
        self.btn_apply_name.setEnabled(bool(valid_name))
        self.btn_apply_comments.setEnabled(bool(analysis.get("comments") or analysis.get("evidence") or analysis.get("summary")))
        self.btn_trainer_radar.setEnabled(bool(analysis.get("trainer_radar")))
        can_experiment = bool(self.current_context and self.current_context.get("has_function"))
        self.btn_call_returns.setEnabled(can_experiment)
        self.btn_hook_modify.setEnabled(can_experiment)

    def _on_analysis_failed(self, message: str) -> None:
        self._stop_analysis_debug_timer()
        self._set_pipeline_step("llm", "error")
        self._set_pipeline_step("parse", "error")
        self._set_pipeline_step("ready", "error")
        self._set_status("Analysis error", ok=False)
        self.summary_edit.setPlainText(message)
        info(message)

    def _render_analysis(self, analysis: Dict[str, Any]) -> None:
        confidence = float(analysis.get("confidence") or 0.0)
        confidence_color = "#9af2b2" if confidence >= 0.72 else "#ffd58a" if confidence >= 0.45 else "#ff9f9f"
        process = "-"
        if self.current_context:
            game_ctx = self.current_context.get("game_context") or {}
            process = str(game_ctx.get("process_display") or game_ctx.get("process_name") or game_ctx.get("selected_candidate") or "-")
        parts = [
            "<html><body style='font-family:Segoe UI, Arial; color:#edf1f5; background:#1b1d20;'>",
            "<div style='margin-bottom:8px;'>",
            self._chip("Mode", analysis.get("mode") or "-", "#9bd7ff"),
            self._chip("Confidence", "%.2f" % confidence, confidence_color),
            self._chip("Process", process, "#ffd58a"),
            self._chip("Name", analysis.get("suggested_function_name") or "-", "#d2b6ff"),
            "</div>",
            self._multi_agent_html(analysis),
            self._section_html("Summary", [str(analysis.get("summary") or "-")], "#9bd7ff", paragraph=True),
            self._trainer_radar_html(analysis),
            self._user_context_html(analysis),
            self._algorithm_html(analysis),
            self._trainer_assessment_html(analysis),
            self._hook_experiments_html(analysis),
            self._trainer_candidates_html(analysis),
            self._xref_graph_html(analysis),
            self._structure_hypotheses_html(analysis),
            self._bitstream_html(analysis),
            self._section_html("Semantic cues used", analysis.get("semantic_cues_used", [])[:12], "#ffcf6e"),
            self._section_html("Detected local cues", self._context_semantic_lines(), "#ffcf6e"),
            self._local_enrichment_html(analysis),
            self._external_evidence_html(analysis),
            self._section_html("Dataflow", analysis.get("dataflow", [])[:12], "#98f0df"),
            self._section_html("Structure offsets", self._structure_offset_lines(analysis), "#f0a7c6"),
            self._section_html("Behavior", analysis.get("behavior", [])[:10], "#9af2b2"),
            self._section_html("Process relevance", analysis.get("game_relevance", [])[:10], "#ffd58a"),
            self._section_html("Engine hints", analysis.get("engine_hints", [])[:10], "#d2b6ff"),
            self._section_html("Risks", analysis.get("risks", [])[:10], "#ff9f9f"),
            self._section_html("Next questions", analysis.get("next_questions", [])[:10], "#98f0df"),
            "</body></html>",
        ]
        self.summary_edit.setHtml("".join(parts))

        evidence = analysis.get("evidence") or []
        if not isinstance(evidence, list):
            evidence = []
        self.evidence_table.setRowCount(len(evidence))
        for row, item in enumerate(evidence):
            if not isinstance(item, dict):
                item = {"kind": "note", "address": "", "text": str(item)}
            kind = str(item.get("kind") or "note").lower()
            bg, fg = KIND_COLORS.get(kind, KIND_COLORS["note"])
            values = [
                str(item.get("kind") or ""),
                str(item.get("address") or ""),
                str(item.get("text") or item.get("value") or item.get("reason") or ""),
            ]
            for col, value in enumerate(values):
                table_item = QtWidgets.QTableWidgetItem(value)
                table_item.setBackground(QtGui.QBrush(QtGui.QColor(bg)))
                table_item.setForeground(QtGui.QBrush(QtGui.QColor(fg if col != 2 else "#edf1f5")))
                address = self._extract_address(value) if col == 1 else self._extract_address(values[1])
                if address is not None:
                    table_item.setData(QtCore.Qt.UserRole, address)
                if col == 1 and address is not None:
                    font = table_item.font()
                    font.setUnderline(True)
                    table_item.setFont(font)
                    table_item.setToolTip("Jump to 0x%X" % address)
                self.evidence_table.setItem(row, col, table_item)
        self.evidence_table.resizeColumnsToContents()

    def _open_action_lab(self, action_kind: str) -> None:
        if not self.current_context or not self.current_analysis:
            self._set_status("Analyze a function first", ok=False)
            return
        self.current_action_kind = action_kind
        label = "Lets call it and see the returns" if action_kind == "call" else "Lets hook it and modify something"
        self.action_mode_label.setText(label)
        radar = self.current_analysis.get("trainer_radar") if isinstance(self.current_analysis, dict) else {}
        if not isinstance(radar, dict):
            radar = {}
        log_first = radar.get("log_first") or []
        if not isinstance(log_first, list):
            log_first = [log_first]
        log_text = ", ".join([str(item) for item in log_first[:5] if str(item).strip()])
        next_move = str(radar.get("next_move") or "").strip()
        strategy = str(radar.get("strategy_label") or radar.get("strategy") or "").strip()
        if action_kind == "call":
            goal = (
                "I want to call this function with __fastcall and validate the Trainer Radar decision. "
                "Use the radar strategy '%s'. Log first: %s. Next move: %s. "
                "Suggest a safe local test harness and what arguments need to be valid."
                % (strategy or "observe/log", log_text or "arguments, caller, return value, output fields", next_move or "observe first")
            )
        else:
            goal = (
                "I want to hook this function using the Trainer Radar as the source of truth. "
                "Use the radar strategy '%s'. Log first: %s. Next move: %s. "
                "Propose a MinHook __fastcall scaffold, where to observe, and only place a mutation gate if the radar supports it."
                % (strategy or "observe/log", log_text or "arguments, caller, return value, output fields", next_move or "observe first")
            )
        self.action_goal_edit.setPlainText(goal)
        self.btn_send_action.setEnabled(True)
        self.tabs.setCurrentWidget(self.action_tab)

    def _send_action_chat(self) -> None:
        if not self.current_context or not self.current_analysis or not self.current_action_kind:
            self._set_status("No action context", ok=False)
            return
        self._save_settings_from_ui()
        user_goal = sanitize_text(self.action_goal_edit.toPlainText(), max_chars=5000).strip()
        if not user_goal:
            self._set_status("Describe what you want to call/hook first", ok=False)
            return
        transcript = sanitize_text(self.action_history, max_chars=12000).strip()
        goal = user_goal if not transcript else transcript + "\n\nUser follow-up:\n" + user_goal
        self.action_history = (transcript + "\n\nUser:\n" + user_goal).strip()
        self._append_action_message("You", user_goal, "#9bd7ff")
        self._append_action_message("AI", "Generating...", "#ffd58a")
        self._set_busy(True)
        self._set_status("Action chat...", ok=True)
        self.action_worker = ActionWorker(self.cfg, self.current_context, self.current_analysis, self.current_action_kind, goal, self)
        self.action_worker.progress.connect(lambda message: self._append_action_message("Debug", message, "#98f0df"))
        self.action_worker.succeeded.connect(self._on_action_ok)
        self.action_worker.failed.connect(self._on_action_failed)
        self.action_worker.finished.connect(lambda: self._set_busy(False))
        self.action_worker.start()

    def _on_action_ok(self, raw: str) -> None:
        self.action_history = (self.action_history + "\n\nAssistant:\n" + raw).strip()
        self._append_action_message("AI", raw, "#9af2b2")
        code = self._extract_code_block(raw)
        if code:
            self.last_action_code = code
            self.action_code_edit.setPlainText(code)
            self._set_status("Action answer ready - code extracted", ok=True)
            return
        self._set_status("Action answer ready", ok=True)

    def _on_action_failed(self, message: str) -> None:
        self._append_action_message("Error", message, "#ff8c8c")
        self._set_status("Action error", ok=False)
        info(message)

    def _clear_action_chat(self) -> None:
        self.action_history = ""
        self.last_action_code = ""
        self.action_chat_edit.clear()
        self.action_code_edit.clear()

    def _chip(self, label: str, value: Any, color: str) -> str:
        return (
            "<span style='display:inline-block; margin:2px 6px 2px 0; padding:3px 7px; "
            "border:1px solid #3b424a; border-radius:4px; background:#252a30;'>"
            "<span style='color:%s; font-weight:700;'>%s</span> "
            "<span style='color:#edf1f5;'>%s</span></span>"
            % (color, html.escape(str(label)), html.escape(str(value)))
        )

    def _section_html(self, title: str, items: Any, color: str, paragraph: bool = False) -> str:
        if not isinstance(items, list):
            items = [str(items)] if items else []
        title_html = (
            "<div style='margin-top:8px; padding:4px 6px; background:#242a30; "
            "border-left:3px solid %s; font-weight:700; color:%s;'>%s</div>"
            % (color, color, html.escape(title))
        )
        if not items:
            body = "<div style='padding:6px 8px; color:#7f8994;'>-</div>"
            return title_html + body
        if paragraph:
            body = "<div style='padding:7px 8px; line-height:1.35;'>%s</div>" % html.escape(str(items[0]))
            return title_html + body
        rows = []
        for item in items:
            rows.append(
                "<li style='margin:3px 0; line-height:1.35;'>%s</li>"
                % html.escape(str(item))
            )
        return title_html + "<ul style='margin:5px 0 8px 18px; padding:0;'>%s</ul>" % "".join(rows)

    def _multi_agent_html(self, analysis: Dict[str, Any]) -> str:
        data = analysis.get("multi_agent") or {}
        pack = analysis.get("evidence_pack") or {}
        board = analysis.get("claim_board") or {}
        if not isinstance(data, dict) or not data:
            return ""
        mode = str(data.get("mode") or "Single")
        if mode == "Single" and not pack and not board:
            return ""
        agents = data.get("agents") or []
        if not isinstance(agents, list):
            agents = []
        claims = board.get("claims") if isinstance(board, dict) else []
        if not isinstance(claims, list):
            claims = []

        status_colors = {
            "ok": "#9af2b2",
            "fallback": "#ffd58a",
            "error": "#ff9f9f",
            "supported": "#9af2b2",
            "weak": "#ffd58a",
            "contradicted": "#ff9f9f",
            "open": "#98f0df",
        }

        agent_rows = []
        for agent in agents[:6]:
            if not isinstance(agent, dict):
                continue
            status = str(agent.get("status") or "ok")
            color = status_colors.get(status, "#98f0df")
            agent_rows.append(
                "<div style='margin:4px 0; padding-left:8px; border-left:2px solid %s;'>"
                "<span style='color:%s; font-weight:700;'>%s</span> "
                "<span style='color:#7f8994;'>%s</span><br>"
                "<span>%s</span></div>"
                % (
                    color,
                    color,
                    html.escape(str(agent.get("name") or "agent")),
                    html.escape(status),
                    html.escape(str(agent.get("summary") or "")),
                )
            )

        claim_rows = []
        for claim in claims[:8]:
            if not isinstance(claim, dict):
                continue
            status = str(claim.get("status") or "open")
            color = status_colors.get(status, "#98f0df")
            evidence_ids = claim.get("evidence_ids") or []
            if not isinstance(evidence_ids, list):
                evidence_ids = []
            claim_rows.append(
                "<div style='margin:4px 0; padding:5px 7px; background:#1b2025; border:1px solid #303840;'>"
                "<span style='color:%s; font-weight:700;'>%s</span> "
                "<span style='color:#9bd7ff;'>%s</span> "
                "<span style='color:#7f8994;'>%s</span><br>"
                "<span>%s</span></div>"
                % (
                    color,
                    html.escape(status),
                    html.escape(str(claim.get("id") or "")),
                    html.escape(",".join([str(x) for x in evidence_ids[:6]])),
                    html.escape(str(claim.get("statement") or "")),
                )
            )

        fact_count = len(pack.get("facts") or []) if isinstance(pack, dict) else 0
        claim_count = len(claims)
        decision = analysis.get("council_decision") or {}
        decision_html = ""
        if isinstance(decision, dict) and decision:
            decision_html = (
                "<div style='margin-top:6px; color:#cfd7df;'>%s%s%s<br>"
                "<span style='color:#7f8994;'>%s</span></div>"
                % (
                    self._chip("Final", decision.get("final_source", "-"), "#9af2b2"),
                    self._chip("Analyst score", decision.get("analyst_score", "-"), "#9bd7ff"),
                    self._chip("Synth score", decision.get("synthesis_score", "-"), "#ffd58a"),
                    html.escape(str(decision.get("reason") or "")),
                )
            )
        title = (
            "<div style='margin-top:8px; padding:5px 7px; background:#242a30; "
            "border-left:3px solid #d2b6ff; font-weight:700; color:#d2b6ff;'>Agent council</div>"
        )
        header = (
            "<div style='padding:8px; background:#1d2227; border:1px solid #333b44;'>"
            "%s%s%s%s%s</div>"
            % (
                self._chip("Mode", mode, "#d2b6ff"),
                self._chip("Pack", pack.get("id") if isinstance(pack, dict) else "-", "#9bd7ff"),
                self._chip("Facts", fact_count, "#98f0df"),
                self._chip("Claims", claim_count, "#ffd58a"),
                decision_html,
            )
        )
        body = (
            "<table width='100%%' cellspacing='0' cellpadding='0'><tr>"
            "<td valign='top' width='50%%' style='padding:5px;'>"
            "<div style='color:#9bd7ff; font-weight:700; margin-bottom:4px;'>Agents</div>%s</td>"
            "<td valign='top' width='50%%' style='padding:5px;'>"
            "<div style='color:#ffd58a; font-weight:700; margin-bottom:4px;'>Claim board</div>%s</td>"
            "</tr></table>"
            % (
                "".join(agent_rows) if agent_rows else "<div style='color:#7f8994;'>No agent log.</div>",
                "".join(claim_rows) if claim_rows else "<div style='color:#7f8994;'>No shared claims.</div>",
            )
        )
        return title + header + body

    def _user_context_html(self, analysis: Dict[str, Any]) -> str:
        if not self.current_context:
            return ""
        analyst_context = self.current_context.get("analyst_context") or {}
        if not analyst_context.get("present"):
            return ""
        alignment = analysis.get("user_context_alignment") or {}
        items = []
        hint = str(analyst_context.get("user_hypothesis") or "").strip()
        if hint:
            items.append("Your hint: %s" % hint)
        notes = str(alignment.get("notes") or "").strip()
        if notes:
            items.append("AI check: %s" % notes)
        supports = alignment.get("supports_user_hint") or []
        contradicts = alignment.get("contradicts_user_hint") or []
        for item in supports[:5]:
            items.append("Supports: %s" % item)
        for item in contradicts[:5]:
            items.append("Contradicts: %s" % item)
        if not items:
            items.append("AI did not return an explicit context check.")
        return self._section_html("Your context check", items, "#ffcf6e")

    def _algorithm_html(self, analysis: Dict[str, Any]) -> str:
        algorithm = analysis.get("algorithm") or {}
        if not isinstance(algorithm, dict):
            return ""
        kind = str(algorithm.get("kind") or "").strip()
        description = str(algorithm.get("description") or "").strip()
        if not kind and not description:
            return ""
        text = "%s: %s" % (kind or "unknown", description or "-")
        return self._section_html("Algorithm", [text], "#9bd7ff", paragraph=True)

    def _trainer_assessment_html(self, analysis: Dict[str, Any]) -> str:
        data = analysis.get("trainer_assessment") or {}
        if not isinstance(data, dict):
            return ""

        def values_for(key: str, limit: int = 4) -> list:
            values = data.get(key) or []
            if not isinstance(values, list):
                values = [values]
            out = []
            for value in values[:limit]:
                text = str(value or "").strip()
                if text:
                    out.append(text)
            return out

        usefulness = str(data.get("usefulness") or "unknown").strip().lower()
        category = str(data.get("category") or "unknown").strip()
        strategy = str(data.get("best_hook_strategy") or "unknown").strip()
        surface = str(data.get("modification_surface") or "none").strip()
        reason = str(data.get("usefulness_reason") or "").strip()
        has_content = any([
            usefulness and usefulness != "unknown",
            category and category != "unknown",
            strategy and strategy != "unknown",
            surface and surface != "none",
            reason,
            values_for("what_happens_if_hooked", 1),
            values_for("values_to_log_first", 1),
            values_for("candidate_trainer_features", 1),
            values_for("recommended_experiments", 1),
            values_for("not_useful_for", 1),
            values_for("stability_notes", 1),
        ])
        if not has_content:
            return ""

        colors = {
            "high": ("#9af2b2", "#20382a", "Strong hook candidate"),
            "medium": ("#ffd58a", "#3a3323", "Useful after validation"),
            "low": ("#ffcf6e", "#362f20", "Mostly mapping / telemetry"),
            "none": ("#ff9f9f", "#382526", "Not a good hook point"),
            "unknown": ("#98f0df", "#233533", "Needs more evidence"),
        }
        accent, chip_bg, verdict = colors.get(usefulness, colors["unknown"])

        def chip(label: str, value: Any, color: str = "#edf1f5", bg: str = "#252a30") -> str:
            return (
                "<span style='display:inline-block; margin:2px 7px 4px 0; padding:4px 8px; "
                "border:1px solid #424a53; border-radius:4px; background:%s;'>"
                "<span style='color:#9bd7ff; font-weight:700;'>%s</span> "
                "<span style='color:%s; font-weight:700;'>%s</span></span>"
                % (bg, html.escape(str(label)), color, html.escape(str(value or "-")))
            )

        def mini_panel(title: str, items: list, color: str, empty_text: str = "") -> str:
            if not items and not empty_text:
                return ""
            if not items:
                body = "<div style='color:#7f8994; padding-top:4px;'>%s</div>" % html.escape(empty_text)
            else:
                rows = []
                for item in items[:4]:
                    rows.append(
                        "<div style='margin:5px 0; padding-left:8px; border-left:2px solid %s; "
                        "line-height:1.35;'>%s</div>"
                        % (color, html.escape(str(item)))
                    )
                body = "".join(rows)
            return (
                "<td valign='top' width='50%%' style='padding:5px;'>"
                "<div style='background:#20252a; border:1px solid #333b44; border-radius:4px; padding:8px;'>"
                "<div style='color:%s; font-weight:700; margin-bottom:5px;'>%s</div>"
                "%s"
                "</div></td>"
                % (color, html.escape(title), body)
            )

        panels = [
            mini_panel("Hook impact", values_for("what_happens_if_hooked"), "#ffd58a", "No hook effect returned."),
            mini_panel("Log first", values_for("values_to_log_first"), "#98f0df", "Log args, caller, return and touched fields."),
            mini_panel("Trainer ideas", values_for("candidate_trainer_features"), "#9af2b2", "No feature idea is justified yet."),
            mini_panel("Validation experiments", values_for("recommended_experiments"), "#9bd7ff", "Observe-only hook first."),
            mini_panel("Not useful for", values_for("not_useful_for"), "#ffb3a7", ""),
            mini_panel("Stability notes", values_for("stability_notes"), "#f0a7c6", ""),
        ]
        panel_rows = []
        current = []
        for panel in [item for item in panels if item]:
            current.append(panel)
            if len(current) == 2:
                panel_rows.append("<tr>%s</tr>" % "".join(current))
                current = []
        if current:
            current.append("<td width='50%'></td>")
            panel_rows.append("<tr>%s</tr>" % "".join(current))

        title = (
            "<div style='margin-top:8px; padding:5px 7px; background:#242a30; "
            "border-left:3px solid %s; font-weight:700; color:%s;'>Trainer lab</div>"
            % (accent, accent)
        )
        header = (
            "<div style='padding:8px; background:#1d2227; border:1px solid #333b44;'>"
            "%s%s%s%s%s"
            "</div>"
            % (
                chip("Verdict", verdict, accent, chip_bg),
                chip("Usefulness", usefulness, accent, chip_bg),
                chip("Category", category, "#d2b6ff"),
                chip("Strategy", strategy, "#9bd7ff"),
                chip("Surface", surface, "#98f0df"),
            )
        )
        if reason:
            header += (
                "<div style='padding:8px; background:#181c20; border-left:3px solid %s; "
                "line-height:1.35;'><span style='color:%s; font-weight:700;'>Why: </span>%s</div>"
                % (accent, accent, html.escape(reason))
            )
        table = "<table width='100%%' cellspacing='0' cellpadding='0' style='margin-top:4px;'>%s</table>" % "".join(panel_rows)
        return title + header + table

    def _score_color(self, score: Any) -> str:
        try:
            value = int(score)
        except Exception:
            value = 0
        if value >= 75:
            return "#9af2b2"
        if value >= 55:
            return "#ffd58a"
        if value >= 35:
            return "#ffcf6e"
        return "#ff9f9f"

    def _trainer_radar_html(self, analysis: Dict[str, Any]) -> str:
        radar = analysis.get("trainer_radar") or {}
        if not isinstance(radar, dict) or not radar:
            return ""
        score = int(radar.get("score") or 0)
        score = max(0, min(100, score))
        accent = self._score_color(score)
        tags = radar.get("tags") or []
        if not isinstance(tags, list):
            tags = [tags]
        tag_html = "".join(self._chip("Tag", item, "#98f0df") for item in tags[:5])
        bar = (
            "<div style='height:8px; background:#11161a; border:1px solid #303840; margin:7px 0;'>"
            "<div style='height:8px; width:%d%%; background:%s;'></div></div>"
            % (score, accent)
        )

        def rows(title: str, values: Any, color: str, empty: str) -> str:
            items = values if isinstance(values, list) else ([] if not values else [values])
            if not items:
                body = "<div style='color:#7f8994;'>%s</div>" % html.escape(empty)
            else:
                body = "".join(
                    "<div style='margin:4px 0; padding-left:8px; border-left:2px solid %s;'>%s</div>"
                    % (color, html.escape(str(item)))
                    for item in items[:4]
                )
            return (
                "<td valign='top' width='50%%' style='padding:5px;'>"
                "<div style='background:#20252a; border:1px solid #333b44; border-radius:4px; padding:8px;'>"
                "<div style='color:%s; font-weight:700; margin-bottom:5px;'>%s</div>%s</div></td>"
                % (color, html.escape(title), body)
            )

        title = (
            "<div style='margin-top:8px; padding:6px 8px; background:#242a30; "
            "border-left:3px solid %s; font-weight:700; color:%s;'>Trainer Target Radar</div>"
            % (accent, accent)
        )
        header = (
            "<div style='padding:8px; background:#1d2227; border:1px solid #333b44;'>"
            "%s%s%s%s%s%s"
            "%s"
            "<div style='line-height:1.35; margin-top:5px;'>%s</div>"
            "<div style='line-height:1.35; margin-top:5px; color:#cfd7df;'><span style='color:%s; font-weight:700;'>Next: </span>%s</div>"
            "</div>"
            % (
                self._chip("Score", score, accent),
                self._chip("Verdict", radar.get("verdict") or "-", accent),
                self._chip("Usefulness", radar.get("usefulness") or "-", accent),
                self._chip("Role", radar.get("category") or "-", "#d2b6ff"),
                self._chip("Strategy", radar.get("strategy_label") or radar.get("strategy") or "-", "#9bd7ff"),
                self._chip("Surface", radar.get("modification_surface") or "-", "#98f0df"),
                tag_html,
                html.escape(str(radar.get("reason") or "")),
                accent,
                html.escape(str(radar.get("next_move") or "-")),
            )
        )
        table = (
            "<table width='100%%' cellspacing='0' cellpadding='0' style='margin-top:4px;'>"
            "<tr>%s%s</tr><tr>%s%s</tr></table>"
            % (
                rows("Hook effect", radar.get("hook_effect"), "#ffd58a", "Hook effect not known yet."),
                rows("Log first", radar.get("log_first"), "#98f0df", "Log args, caller, return and output fields."),
                rows("Good for", radar.get("good_for"), "#9af2b2", "No supported trainer outcome yet."),
                rows("Experiments", radar.get("experiments"), "#9bd7ff", "Observe-only hook first."),
            )
        )
        return title + header + bar + table

    def _trainer_candidates_html(self, analysis: Dict[str, Any]) -> str:
        rows = analysis.get("trainer_candidates") or []
        if not isinstance(rows, list) or not rows:
            return ""
        cards = []
        for item in rows[:6]:
            if not isinstance(item, dict):
                continue
            score = int(item.get("score") or 0)
            color = self._score_color(score)
            evidence = item.get("evidence") or []
            if not isinstance(evidence, list):
                evidence = [evidence]
            evidence_html = "".join(
                "<div style='margin:3px 0; padding-left:7px; border-left:2px solid %s;'>%s</div>"
                % (color, html.escape(str(ev)))
                for ev in evidence[:3]
            )
            cards.append(
                "<td valign='top' width='50%%' style='padding:5px;'>"
                "<div style='background:#20252a; border:1px solid #333b44; border-radius:4px; padding:8px;'>"
                "<div>%s%s%s</div>"
                "<div style='font-weight:700; color:#edf1f5; margin-top:4px;'>%s</div>"
                "<div style='color:#7f8994;'>%s</div>"
                "<div style='margin-top:5px; color:#cfd7df;'>%s</div>"
                "%s"
                "</div></td>"
                % (
                    self._chip("Score", score, color),
                    self._chip("Relation", item.get("relation") or "-", "#9bd7ff"),
                    self._chip("Role", item.get("role") or "-", "#d2b6ff"),
                    html.escape(str(item.get("function") or "unknown")),
                    html.escape(str(item.get("address") or "")),
                    html.escape(str(item.get("next_action") or "")),
                    evidence_html,
                )
            )
        if not cards:
            return ""
        row_html = []
        current = []
        for card in cards:
            current.append(card)
            if len(current) == 2:
                row_html.append("<tr>%s</tr>" % "".join(current))
                current = []
        if current:
            current.append("<td width='50%'></td>")
            row_html.append("<tr>%s</tr>" % "".join(current))
        return (
            "<div style='margin-top:8px; padding:5px 7px; background:#242a30; "
            "border-left:3px solid #9af2b2; font-weight:700; color:#9af2b2;'>Trainer Candidates</div>"
            "<table width='100%%' cellspacing='0' cellpadding='0'>%s</table>"
            % "".join(row_html)
        )

    def _hook_experiments_html(self, analysis: Dict[str, Any]) -> str:
        experiments = analysis.get("hook_experiments") or []
        if not isinstance(experiments, list) or not experiments:
            return ""
        cards = []
        for item in experiments[:4]:
            if not isinstance(item, dict):
                continue
            steps = item.get("steps") or []
            if not isinstance(steps, list):
                steps = [steps]
            logs = item.get("log") or []
            if not isinstance(logs, list):
                logs = [logs]
            step_html = "".join("<li style='margin:3px 0;'>%s</li>" % html.escape(str(step)) for step in steps[:4])
            log_html = "".join(self._chip("Log", value, "#98f0df") for value in logs[:5])
            cards.append(
                "<div style='margin:5px 0; background:#20252a; border:1px solid #333b44; border-radius:4px; padding:8px;'>"
                "<div style='color:#9bd7ff; font-weight:700;'>%s</div>"
                "<div style='line-height:1.35; margin:4px 0;'>%s</div>"
                "<ul style='margin:5px 0 5px 18px; padding:0;'>%s</ul>"
                "<div>%s</div>"
                "<div style='margin-top:5px; color:#ffd58a;'><span style='font-weight:700;'>Gate: </span>%s</div>"
                "</div>"
                % (
                    html.escape(str(item.get("title") or "Experiment")),
                    html.escape(str(item.get("intent") or "")),
                    step_html,
                    log_html,
                    html.escape(str(item.get("mutation_gate") or "Observe first.")),
                )
            )
        return (
            "<div style='margin-top:8px; padding:5px 7px; background:#242a30; "
            "border-left:3px solid #9bd7ff; font-weight:700; color:#9bd7ff;'>Hook Experiments</div>"
            "%s" % "".join(cards)
        )

    def _xref_graph_html(self, analysis: Dict[str, Any]) -> str:
        graph = analysis.get("xref_graph") or {}
        if not isinstance(graph, dict) or not graph:
            return ""
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        next_targets = graph.get("next_targets") or []
        if not isinstance(nodes, list):
            nodes = []
        if not isinstance(edges, list):
            edges = []
        callers = [node for node in nodes if isinstance(node, dict) and node.get("role") == "caller"][:4]
        callees = [node for node in nodes if isinstance(node, dict) and node.get("role") == "callee"][:4]
        center = graph.get("center") or {}
        if not isinstance(center, dict):
            center = {}

        def node_card(node: Dict[str, Any], color: str) -> str:
            label = str(node.get("label") or "unknown")
            address = str(node.get("address") or "")
            label_html = self._jump_link(address or label, label, color)
            address_html = self._jump_link(address or label, address, "#9aa7b2") if address else ""
            return (
                "<div style='margin:4px 0; padding:6px; background:#20252a; border:1px solid #333b44; border-left:3px solid %s;'>"
                "<div style='font-weight:700;'>%s</div><div style='color:#7f8994;'>%s</div>%s</div>"
                % (
                    color,
                    label_html,
                    address_html,
                    self._chip("Score", node.get("score") or 0, color),
                )
            )

        caller_html = "".join(node_card(node, "#9bd7ff") for node in callers) or "<div style='color:#7f8994;'>No caller expanded.</div>"
        callee_html = "".join(node_card(node, "#d2b6ff") for node in callees) or "<div style='color:#7f8994;'>No callee expanded.</div>"
        center_html = node_card({
            "label": center.get("name") or "current",
            "address": center.get("address") or "",
            "score": (nodes[0].get("score") if nodes and isinstance(nodes[0], dict) else 0),
        }, "#9af2b2")
        target_lines = []
        if isinstance(next_targets, list):
            for target in next_targets[:4]:
                if isinstance(target, dict):
                    target_lines.append(
                        "<div style='margin:4px 0; padding-left:8px; border-left:2px solid %s;'>%s %s - %s</div>"
                        % (
                            self._score_color(target.get("score") or 0),
                            self._jump_link(
                                str(target.get("address") or target.get("function") or ""),
                                str(target.get("function") or "unknown"),
                                "#edf1f5",
                            ),
                            self._jump_link(
                                str(target.get("address") or target.get("function") or ""),
                                str(target.get("address") or ""),
                                "#9aa7b2",
                            ),
                            html.escape(str(target.get("reason") or "")),
                        )
                    )
        return (
            "<div style='margin-top:8px; padding:5px 7px; background:#242a30; "
            "border-left:3px solid #d2b6ff; font-weight:700; color:#d2b6ff;'>XREF Evidence Map</div>"
            "<table width='100%%' cellspacing='0' cellpadding='0'><tr>"
            "<td valign='top' width='33%%' style='padding:5px;'><div style='color:#9bd7ff; font-weight:700;'>Callers</div>%s</td>"
            "<td valign='top' width='34%%' style='padding:5px;'><div style='color:#9af2b2; font-weight:700;'>Current</div>%s"
            "<div style='color:#7f8994; margin-top:6px;'>edges=%d</div></td>"
            "<td valign='top' width='33%%' style='padding:5px;'><div style='color:#d2b6ff; font-weight:700;'>Callees</div>%s</td>"
            "</tr></table>"
            "<div style='background:#1d2227; border:1px solid #333b44; padding:7px; margin-top:4px;'>"
            "<div style='color:#ffd58a; font-weight:700; margin-bottom:4px;'>Next XREF targets</div>%s</div>"
            % (
                caller_html,
                center_html,
                len(edges),
                callee_html,
                "".join(target_lines) if target_lines else "<div style='color:#7f8994;'>No ranked XREF target yet.</div>",
            )
        )

    def _structure_hypotheses_html(self, analysis: Dict[str, Any]) -> str:
        hypotheses = analysis.get("structure_hypotheses") or []
        if not isinstance(hypotheses, list) or not hypotheses:
            return ""
        cards = []
        for item in hypotheses[:3]:
            if not isinstance(item, dict):
                continue
            fields = item.get("fields") or []
            field_count = len(fields) if isinstance(fields, list) else 0
            preview = html.escape(str(item.get("cpp_preview") or ""))
            cards.append(
                "<div style='margin:5px 0; background:#20252a; border:1px solid #333b44; border-radius:4px; padding:8px;'>"
                "%s%s%s"
                "<pre style='white-space:pre-wrap; color:#edf1f5; background:#15191d; border:1px solid #303840; padding:7px; margin:6px 0 0 0;'>%s</pre>"
                "</div>"
                % (
                    self._chip("Base", item.get("base") or "-", "#f0a7c6"),
                    self._chip("Struct", item.get("name") or "-", "#9bd7ff"),
                    self._chip("Fields", field_count, "#98f0df"),
                    preview,
                )
            )
        return (
            "<div style='margin-top:8px; padding:5px 7px; background:#242a30; "
            "border-left:3px solid #f0a7c6; font-weight:700; color:#f0a7c6;'>Structure Hypotheses</div>"
            "%s" % "".join(cards)
        )

    def _trainer_radar_popup_html(self, analysis: Dict[str, Any]) -> str:
        return (
            "<html><body style='font-family:Segoe UI, Arial; color:#edf1f5; background:#1b1d20;'>"
            "<div style='margin-bottom:8px; padding:7px 9px; background:#242a30; "
            "border-left:3px solid #9af2b2; font-weight:700; color:#9af2b2;'>Trainer / Modding Decision Workspace</div>"
            "%s%s%s%s%s"
            "</body></html>"
            % (
                self._trainer_radar_html(analysis),
                self._hook_experiments_html(analysis),
                self._trainer_candidates_html(analysis),
                self._xref_graph_html(analysis),
                self._structure_hypotheses_html(analysis),
            )
        )

    def _bitstream_html(self, analysis: Dict[str, Any]) -> str:
        data = analysis.get("bitstream_deserialization") or {}
        if not isinstance(data, dict):
            return ""
        lines = []
        likelihood = str(data.get("likelihood") or "").strip()
        if likelihood and likelihood != "none":
            lines.append("likelihood=%s" % likelihood)
        for label, key in (
            ("reader", "reader_calls"),
            ("layout", "output_layout"),
            ("dirty", "dirty_masks"),
            ("sanity", "sanity_checks"),
            ("bitwise", "bitwise_checks"),
            ("string", "string_anchors"),
        ):
            values = data.get(key) or []
            if not isinstance(values, list):
                values = [values]
            for value in values[:5]:
                lines.append("%s: %s" % (label, value))
        if not lines:
            return ""
        return self._section_html("Bitstream / structured parse", lines, "#ffcf6e")

    def _local_enrichment_html(self, analysis: Dict[str, Any]) -> str:
        data = analysis.get("local_enrichment") or {}
        if not isinstance(data, dict) or not data.get("applied"):
            return ""
        lines = []
        policy = str(data.get("policy") or "").strip()
        if policy:
            lines.append(policy)
        notes = data.get("notes") or []
        if not isinstance(notes, list):
            notes = [notes]
        for note in notes[:8]:
            lines.append(str(note))
        return self._section_html("Local enrichment", lines, "#9af2b2")

    def _external_evidence_html(self, analysis: Dict[str, Any]) -> str:
        summary = analysis.get("external_evidence_summary") or {}
        if not isinstance(summary, dict):
            summary = {}
        payload = {}
        if self.current_context:
            payload = self.current_context.get("external_evidence") or {}
        if not isinstance(payload, dict):
            payload = {}
        if not summary and not payload.get("present"):
            return ""

        stats = summary.get("summary") or payload.get("summary") or {}
        if not isinstance(stats, dict):
            stats = {}
        by_kind = stats.get("by_kind") or {}
        if not isinstance(by_kind, dict):
            by_kind = {}
        total = stats.get("total", 0)
        static_count = stats.get("static_count", 0)
        matched = summary.get("matched_count")
        if matched in (None, ""):
            matched = payload.get("matched_count", 0)

        chips = (
            self._chip("Loaded", total, "#98f0df")
            + self._chip("Static", static_count, "#9af2b2")
            + self._chip("Matched focus", matched, "#ffd58a")
        )
        kinds_html = "".join(
            self._chip(str(kind), count, "#d2b6ff")
            for kind, count in sorted(by_kind.items())[:8]
        )

        notes = summary.get("analysis_text") or payload.get("analysis_text") or []
        if not isinstance(notes, list):
            notes = [notes]
        note_html = "".join(
            "<div style='margin:3px 0; padding-left:8px; border-left:2px solid #9bd7ff;'>%s</div>"
            % html.escape(str(note))
            for note in notes[:8]
            if str(note).strip()
        )

        cards = []
        items = payload.get("items") or []
        if not isinstance(items, list):
            items = []
        kind_colors = {
            "diff": "#ffd58a",
            "capability": "#9bd7ff",
            "signature": "#98f0df",
            "crypto_signature": "#f0a7c6",
            "deobf": "#d2b6ff",
            "structure": "#b8d6ff",
            "xref": "#d2b6ff",
            "string": "#ffd58a",
            "note": "#d7dde5",
        }
        for item in items[:8]:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "note")
            color = kind_colors.get(kind, "#d7dde5")
            cards.append(
                "<div style='margin:4px 0; padding:6px 7px; background:#20252a; border:1px solid #333b44; border-left:3px solid %s;'>"
                "<div>%s%s%s</div>"
                "<div style='line-height:1.35; margin-top:3px;'>%s</div>"
                "</div>"
                % (
                    color,
                    self._chip("Source", item.get("source") or "external", color),
                    self._chip("Kind", kind, color),
                    self._chip("EA", item.get("address") or "-", "#9bd7ff"),
                    html.escape(str(item.get("text") or "")),
                )
            )

        return (
            "<div style='margin-top:8px; padding:5px 7px; background:#242a30; "
            "border-left:3px solid #d2b6ff; font-weight:700; color:#d2b6ff;'>External Evidence Sources</div>"
            "<div style='padding:8px; background:#1d2227; border:1px solid #333b44;'>%s%s%s</div>%s"
            % (
                chips,
                kinds_html,
                note_html or "<div style='color:#7f8994; margin-top:4px;'>No static evidence note generated yet.</div>",
                "".join(cards),
            )
        )

    def _structure_offset_lines(self, analysis: Dict[str, Any]) -> list:
        rows = analysis.get("structure_offsets") or []
        if not isinstance(rows, list):
            return []
        out = []
        for item in rows[:16]:
            if not isinstance(item, dict):
                out.append(str(item))
                continue
            bits = []
            for key in ("base", "offset", "type", "meaning", "confidence"):
                value = item.get(key)
                if value not in (None, ""):
                    bits.append("%s=%s" % (key, value))
            evidence = str(item.get("evidence") or "").strip()
            if evidence:
                bits.append("evidence=%s" % evidence)
            if bits:
                out.append(", ".join(bits))
        return out

    def _context_semantic_lines(self) -> list:
        if not self.current_context:
            return []
        cues = self.current_context.get("semantic_cues") or {}
        if not isinstance(cues, dict):
            return []
        lines = []
        likelihood = cues.get("bitstream_or_structured_reader_likelihood")
        if likelihood:
            lines.append("bitstream_or_structured_reader_likelihood=%s" % likelihood)
        for item in (cues.get("likely_reader_calls") or [])[:6]:
            if isinstance(item, dict):
                lines.append("reader %s(%s, widths=%s)" % (item.get("call"), item.get("stream_arg"), item.get("widths")))
        for item in (cues.get("structure_reads") or [])[:8]:
            if isinstance(item, dict):
                lines.append("read %s+%s :: %s" % (item.get("base"), item.get("offset"), item.get("line")))
        for item in (cues.get("output_layout_writes") or [])[:8]:
            if isinstance(item, dict):
                lines.append("write %s[%s] :: %s" % (item.get("base"), item.get("offset_or_index"), item.get("line")))
        for item in (cues.get("numeric_ops") or [])[:6]:
            if isinstance(item, dict):
                lines.append("numeric :: %s" % item.get("line"))
        for item in (cues.get("mode_checks") or [])[:6]:
            if isinstance(item, dict):
                lines.append("mode %s %s %s" % (item.get("selector"), item.get("operator"), item.get("value")))
        for item in (cues.get("dirty_masks") or [])[:6]:
            if isinstance(item, dict):
                lines.append("dirty mask %s |= %s" % (item.get("target"), item.get("mask")))
        for item in (cues.get("bitwise_or_checksum_ops") or [])[:6]:
            if isinstance(item, dict):
                lines.append("bitwise/checksum :: %s" % item.get("line"))
        for item in (cues.get("magic_constants") or [])[:6]:
            if isinstance(item, dict):
                lines.append("magic constant %s (%s)" % (item.get("constant"), item.get("decimal")))
        for item in (cues.get("string_anchors") or [])[:8]:
            if isinstance(item, dict):
                marker = "priority string" if item.get("priority") else "string"
                lines.append("%s %s :: %s" % (marker, item.get("address"), item.get("value")))
        return lines

    def _append_action_message(self, role: str, text: str, color: str) -> None:
        escaped = html.escape(str(text or "")).replace("\n", "<br>")
        self.action_chat_edit.append(
            "<div style='margin:8px 0; padding:7px; background:#20252a; border-left:3px solid %s;'>"
            "<div style='color:%s; font-weight:700; margin-bottom:4px;'>%s</div>"
            "<div style='color:#edf1f5; line-height:1.35;'>%s</div>"
            "</div>"
            % (color, color, html.escape(role), escaped)
        )

    def _extract_code_block(self, text: str) -> str:
        matches = re.findall(r"```(?:cpp|c\+\+|cc|cxx|c|hpp|h)?\s*\n(.*?)```", str(text or ""), flags=re.IGNORECASE | re.DOTALL)
        if not matches:
            return ""
        return matches[-1].strip()

    def _copy_action_code(self) -> None:
        code = self.action_code_edit.toPlainText().strip()
        if not code:
            self._set_status("No code to copy", ok=False)
            return
        QtWidgets.QApplication.clipboard().setText(code)
        self._set_status("Code copied", ok=True)

    def _save_action_code(self) -> None:
        code = self.action_code_edit.toPlainText().strip()
        if not code:
            self._set_status("No code to save", ok=False)
            return
        root = os.path.join(config_dir(), "generated_code")
        os.makedirs(root, exist_ok=True)
        name = "monstey_action"
        if self.current_analysis and self.current_analysis.get("suggested_function_name"):
            name = str(self.current_analysis.get("suggested_function_name"))
        elif self.current_context and self.current_context.get("function_name"):
            name = str(self.current_context.get("function_name"))
        name = re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_") or "monstey_action"
        suffix = self.current_action_kind or "action"
        ext = ".hpp" if suffix == "hook" else ".cpp"
        path = os.path.join(root, "%s_%s%s" % (name[:64], suffix, ext))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(code + "\n")
        self._set_status("Saved code: %s" % path, ok=True)
        info("Saved generated code: %s" % path)

    def _extract_address(self, text: Any) -> Optional[int]:
        value = str(text or "")
        match = re.search(r"0x[0-9A-Fa-f]+", value)
        if not match:
            match = re.search(r"\b(?:sub|loc|off|byte|word|dword|qword|unk|stru|asc)_([0-9A-Fa-f]{6,16})\b", value)
        if not match:
            return None
        try:
            return int(match.group(1) if match.lastindex else match.group(0), 16)
        except Exception:
            return None

    def _jump_link(self, address_source: Any, label: Any, color: str) -> str:
        text = str(label or "").strip()
        if not text:
            return ""
        ea = self._extract_address(address_source)
        if ea is None:
            return html.escape(text)
        return (
            "<a href='monstey://jump?ea=0x%X' "
            "style='color:%s; text-decoration:underline; font-weight:700;' "
            "title='Jump to 0x%X in IDA'>%s</a>"
            % (ea, color, ea, html.escape(text))
        )

    def _jump_to_address(self, ea: int, source: str = "report") -> bool:
        try:
            ida_kernwin.jumpto(int(ea))
            if bool(getattr(self, "focus_highlight_enabled", True)):
                try:
                    set_focus_marker(int(ea))
                    self._last_focus_marker_ea = int(ea)
                except Exception:
                    pass
            self._set_status("Jumped to %s 0x%X" % (source, int(ea)), ok=True)
            return True
        except Exception as exc:
            self._set_status("Jump failed", ok=False)
            info("Jump failed: %s" % exc)
            return False

    def _on_summary_anchor_clicked(self, url: QtCore.QUrl) -> None:
        raw = url.toString()
        if not raw.startswith("monstey://jump"):
            return
        ea = self._extract_address(raw)
        if ea is None:
            self._set_status("Report link has no valid IDA address", ok=False)
            return
        self._jump_to_address(ea, "report")

    def _jump_to_evidence_row(self, row: int) -> None:
        for col in (1, 2, 0):
            item = self.evidence_table.item(row, col)
            if not item:
                continue
            address = item.data(QtCore.Qt.UserRole)
            if address is None:
                address = self._extract_address(item.text())
            if address is None:
                continue
            self._jump_to_address(int(address), "evidence")
            return

    def _on_evidence_cell_clicked(self, row: int, col: int) -> None:
        if col == 1:
            self._jump_to_evidence_row(row)

    def _on_evidence_cell_double_clicked(self, row: int, col: int) -> None:
        self._jump_to_evidence_row(row)

    def _apply_name(self) -> None:
        if not self.current_context or not self.current_analysis:
            return
        name = validate_function_name(self.current_analysis.get("suggested_function_name"))
        if not name:
            return
        answer = QtWidgets.QMessageBox.question(
            self,
            PLUGIN_NAME,
            "Apply function name '%s' at %s?" % (name, self.current_context.get("start_ea")),
        )
        if answer != QtWidgets.QMessageBox.Yes:
            return
        start = int(str(self.current_context["start_ea"]), 16)
        result = apply_function_name(start, self.current_analysis)
        if result.get("ok"):
            self.current_context["function_name"] = result.get("new_name") or name
            self._refresh_context_label(self.current_context)
        refresh_ida()
        self._set_status(result["message"], ok=bool(result["ok"]))
        info(result["message"])

    def _apply_comments(self) -> None:
        if not self.current_analysis:
            return
        answer = QtWidgets.QMessageBox.question(self, PLUGIN_NAME, "Apply AI comments and colors to the IDB?")
        if answer != QtWidgets.QMessageBox.Yes:
            return
        results = apply_colored_annotations(self.current_analysis, self.current_context or {})
        refresh_ida()
        ok_count = sum(1 for item in results if item.get("ok"))
        self._set_status("Applied %d AI annotations/colors" % ok_count, ok=True)
        for item in results:
            info(item.get("message", "comment"))

    def shutdown(self) -> None:
        try:
            self.focus_indicator_timer.stop()
        except Exception:
            pass
        try:
            if self.idb_hooks is not None:
                self.idb_hooks.unhook()
                self.idb_hooks = None
        except Exception:
            pass
        clear_focus_lock()
        clear_focus_marker()


try:
    PluginFormBase = ida_kernwin.PluginForm
except AttributeError:
    PluginFormBase = idaapi.PluginForm


class LocalGameAIForm(PluginFormBase):
    instance = None

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.widget = MainWidget(self.parent)
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.widget)
        self.parent.setLayout(layout)

    def OnClose(self, form):
        try:
            widget = getattr(self, "widget", None)
            if widget is not None:
                widget.shutdown()
        except Exception:
            pass
        LocalGameAIForm.instance = None


def show_panel() -> LocalGameAIForm:
    if LocalGameAIForm.instance is None:
        LocalGameAIForm.instance = LocalGameAIForm()
    persist = getattr(PluginFormBase, "FORM_PERSIST", 0)
    LocalGameAIForm.instance.Show(PLUGIN_NAME, options=persist)
    return LocalGameAIForm.instance


def analyze_focus(force_asm: bool = True) -> LocalGameAIForm:
    form = show_panel()
    widget = getattr(form, "widget", None)
    if widget is not None:
        widget._start_analysis(force_asm=force_asm)
    return form


def reconstruct_focus_pseudocode() -> LocalGameAIForm:
    form = show_panel()
    widget = getattr(form, "widget", None)
    if widget is not None:
        widget._capture_asm_reconstruction()
    return form
