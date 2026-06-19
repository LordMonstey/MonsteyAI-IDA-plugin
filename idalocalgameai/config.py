"""Local configuration for the plugin."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import Any, Dict


DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"
DEFAULT_MODEL = "qwen3-coder:30b"
DEFAULT_TIMEOUT_SECONDS = 600
DEFAULT_PROVIDER = "local"
DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"
DEFAULT_GEMINI_MODEL = "gemini-2.5-pro"

MODEL_PRESETS = [
    {
        "label": "Deep reverse - qwen3-coder:30b",
        "model": "qwen3-coder:30b",
        "timeout_seconds": 600,
    },
    {
        "label": "Balanced - qwen2.5-coder:14b",
        "model": "qwen2.5-coder:14b",
        "timeout_seconds": 300,
    },
    {
        "label": "Fast - qwen2.5-coder:7b",
        "model": "qwen2.5-coder:7b",
        "timeout_seconds": 180,
    },
]

GEMINI_MODEL_PRESETS = [
    {
        "label": "Deep hosted - Gemini 2.5 Pro",
        "model": "gemini-2.5-pro",
        "timeout_seconds": 600,
    },
    {
        "label": "Balanced hosted - Gemini 2.5 Flash",
        "model": "gemini-2.5-flash",
        "timeout_seconds": 300,
    },
    {
        "label": "Fast hosted - Gemini 3.5 Flash",
        "model": "gemini-3.5-flash",
        "timeout_seconds": 240,
    },
]


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


@dataclass
class PluginConfig:
    provider: str = DEFAULT_PROVIDER
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    api_key: str = "ollama"
    gemini_base_url: str = DEFAULT_GEMINI_BASE_URL
    gemini_model: str = DEFAULT_GEMINI_MODEL
    gemini_api_key: str = ""
    temperature: float = 0.1
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    analysis_timeout_seconds: int = 45
    engine_profile: str = "Auto"
    max_asm_lines: int = 140
    max_pseudocode_chars: int = 6500
    max_decompile_instructions: int = 320
    max_decompile_bytes: int = 18000
    max_xref_items: int = 20
    max_xref_expansion_items: int = 0
    analysis_depth: str = "Fast"
    agent_mode: str = "Single"
    max_analysis_tokens: int = 1300
    auto_rename_after_analysis: bool = True
    auto_comment_after_analysis: bool = True
    auto_toolchain_scouts: bool = True
    show_verbal_summary_popup: bool = True
    verbal_summary_language: str = "English"
    enable_game_research: bool = True
    enable_global_string_scan: bool = False
    game_research_ttl_days: int = 14

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginConfig":
        cfg = cls()
        defaults = cls()
        for key in asdict(cfg).keys():
            if key in data:
                setattr(cfg, key, data[key])
        cfg.temperature = as_float(cfg.temperature, defaults.temperature)
        cfg.provider = str(cfg.provider or DEFAULT_PROVIDER).strip().lower()
        if cfg.provider not in ("local", "gemini"):
            cfg.provider = DEFAULT_PROVIDER
        cfg.timeout_seconds = as_int(cfg.timeout_seconds, defaults.timeout_seconds)
        cfg.analysis_timeout_seconds = as_int(cfg.analysis_timeout_seconds, defaults.analysis_timeout_seconds)
        cfg.max_asm_lines = as_int(cfg.max_asm_lines, defaults.max_asm_lines)
        cfg.max_pseudocode_chars = as_int(cfg.max_pseudocode_chars, defaults.max_pseudocode_chars)
        cfg.max_decompile_instructions = as_int(cfg.max_decompile_instructions, defaults.max_decompile_instructions)
        cfg.max_decompile_bytes = as_int(cfg.max_decompile_bytes, defaults.max_decompile_bytes)
        cfg.max_xref_items = as_int(cfg.max_xref_items, defaults.max_xref_items)
        cfg.max_xref_expansion_items = as_int(cfg.max_xref_expansion_items, defaults.max_xref_expansion_items)
        cfg.analysis_depth = str(cfg.analysis_depth or "Fast").strip().title()
        if cfg.analysis_depth not in ("Fast", "Balanced", "Deep"):
            cfg.analysis_depth = "Fast"
        cfg.agent_mode = str(cfg.agent_mode or "Single").strip().title()
        if cfg.agent_mode not in ("Single", "Duo", "Council"):
            cfg.agent_mode = "Single"
        cfg.max_analysis_tokens = as_int(cfg.max_analysis_tokens, defaults.max_analysis_tokens)
        cfg.auto_rename_after_analysis = as_bool(cfg.auto_rename_after_analysis)
        cfg.auto_comment_after_analysis = as_bool(cfg.auto_comment_after_analysis)
        cfg.auto_toolchain_scouts = as_bool(cfg.auto_toolchain_scouts)
        cfg.show_verbal_summary_popup = as_bool(cfg.show_verbal_summary_popup)
        cfg.verbal_summary_language = str(cfg.verbal_summary_language or "English").strip().title()
        if cfg.verbal_summary_language not in ("English", "French"):
            cfg.verbal_summary_language = "English"
        cfg.enable_game_research = as_bool(cfg.enable_game_research)
        cfg.enable_global_string_scan = as_bool(cfg.enable_global_string_scan)
        cfg.game_research_ttl_days = as_int(cfg.game_research_ttl_days, defaults.game_research_ttl_days)
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def active_provider_label(self) -> str:
        return "Gemini hosted" if self.provider == "gemini" else "Local / OpenAI-compatible"

    def active_base_url(self) -> str:
        if self.provider == "gemini":
            return self.gemini_base_url or DEFAULT_GEMINI_BASE_URL
        return self.base_url or DEFAULT_BASE_URL

    def active_model(self) -> str:
        if self.provider == "gemini":
            return self.gemini_model or DEFAULT_GEMINI_MODEL
        return self.model or DEFAULT_MODEL

    def active_api_key(self) -> str:
        if self.provider == "gemini":
            return self.gemini_api_key or ""
        return self.api_key or "ollama"

    def depth_budget(self) -> Dict[str, int]:
        if self.analysis_depth == "Deep":
            return {
                "max_asm_lines": max(self.max_asm_lines, 360),
                "max_pseudocode_chars": max(self.max_pseudocode_chars, 18000),
                "max_decompile_instructions": max(self.max_decompile_instructions, 900),
                "max_decompile_bytes": max(self.max_decompile_bytes, 49152),
                "max_xref_items": max(self.max_xref_items, 64),
                "max_xref_expansion_items": max(self.max_xref_expansion_items, 6),
                "max_analysis_tokens": max(self.max_analysis_tokens, 2200),
            }
        if self.analysis_depth == "Balanced":
            return {
                "max_asm_lines": min(max(self.max_asm_lines, 180), 240),
                "max_pseudocode_chars": min(max(self.max_pseudocode_chars, 8000), 12000),
                "max_decompile_instructions": min(max(self.max_decompile_instructions, 420), 650),
                "max_decompile_bytes": min(max(self.max_decompile_bytes, 20480), 32768),
                "max_xref_items": min(max(self.max_xref_items, 28), 40),
                "max_xref_expansion_items": min(max(self.max_xref_expansion_items, 1), 3),
                "max_analysis_tokens": min(max(self.max_analysis_tokens, 1500), 1900),
            }
        return {
            "max_xref_expansion_items": min(max(self.max_xref_expansion_items, 3), 4)
            if self.agent_mode == "Council"
            else min(max(self.max_xref_expansion_items, 2), 3)
            if self.agent_mode == "Duo"
            else 0,
            "max_asm_lines": min(self.max_asm_lines, 140),
            "max_pseudocode_chars": min(self.max_pseudocode_chars, 6500),
            "max_decompile_instructions": min(self.max_decompile_instructions, 320),
            "max_decompile_bytes": min(self.max_decompile_bytes, 18000),
            "max_xref_items": min(self.max_xref_items, 20),
            "max_analysis_tokens": min(max(self.max_analysis_tokens, 1600), 1800)
            if self.agent_mode == "Council"
            else min(max(self.max_analysis_tokens, 1400), 1600)
            if self.agent_mode == "Duo"
            else min(self.max_analysis_tokens, 1300),
        }


def config_dir() -> str:
    root = os.path.join(os.path.expanduser("~"), ".monstey-ai-plugin")
    if not os.path.isdir(root):
        os.makedirs(root, exist_ok=True)
    return root


def config_path() -> str:
    return os.path.join(config_dir(), "config.json")


def load_config() -> PluginConfig:
    path = config_path()
    if not os.path.isfile(path):
        cfg = PluginConfig()
        save_config(cfg)
        return cfg
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return PluginConfig.from_dict(json.load(fh))
    except Exception:
        return PluginConfig()


def save_config(cfg: PluginConfig) -> None:
    with open(config_path(), "w", encoding="utf-8") as fh:
        json.dump(cfg.to_dict(), fh, indent=2, sort_keys=True)
