"""Optional external analysis sidecar launcher.

Heavy reverse-engineering libraries should not be imported inside IDAPython.
This module launches a separate Python process and exchanges bounded JSON.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, Dict, List


def toolchain_dir() -> str:
    root = os.path.join(os.path.expanduser("~"), ".monstey-ai-plugin", "toolchain")
    os.makedirs(root, exist_ok=True)
    return root


def toolchain_state_path() -> str:
    return os.path.join(toolchain_dir(), "toolchain_state.json")


def sidecar_script_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "toolchain_sidecar.py")


def _read_json(path: str) -> Dict[str, Any]:
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _candidate_python_paths() -> List[str]:
    candidates: List[str] = []
    env_python = os.environ.get("MONSTEY_TOOLCHAIN_PYTHON") or os.environ.get("MONSTEY_SIDECAR_PYTHON")
    if env_python:
        candidates.append(env_python)
    state = _read_json(toolchain_state_path())
    state_python = state.get("python") or state.get("python_path")
    if state_python:
        candidates.append(str(state_python))
    default_venv = os.path.join(toolchain_dir(), ".venv", "Scripts", "python.exe")
    candidates.append(default_venv)
    candidates.extend(["python", "py"])
    return candidates


def resolve_sidecar_python() -> str:
    for candidate in _candidate_python_paths():
        if not candidate:
            continue
        if os.path.isabs(candidate) and os.path.isfile(candidate):
            return candidate
        if not os.path.isabs(candidate):
            return candidate
    return sys.executable or "python"


def run_toolchain(command: str, payload: Dict[str, Any] = None, timeout: int = 45) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    script = sidecar_script_path()
    if not os.path.isfile(script):
        raise RuntimeError("Toolchain sidecar script not found: %s" % script)
    python = resolve_sidecar_python()
    request = dict(payload)
    request["command"] = command
    raw_input = json.dumps(request, ensure_ascii=True)
    proc = subprocess.run(
        [python, script, command],
        input=raw_input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=max(5, int(timeout)),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        raise RuntimeError("Toolchain sidecar failed (%s): %s" % (proc.returncode, stderr or stdout or "no output"))
    try:
        data = json.loads(stdout)
    except Exception as exc:
        raise RuntimeError("Toolchain sidecar returned invalid JSON: %s | %s" % (exc, stdout[:1000]))
    if not isinstance(data, dict):
        raise RuntimeError("Toolchain sidecar returned a non-object response")
    if stderr:
        warnings = data.setdefault("warnings", [])
        if isinstance(warnings, list):
            warnings.append(stderr[:1200])
    return data


def toolchain_status(timeout: int = 15) -> Dict[str, Any]:
    return run_toolchain("check", {}, timeout=timeout)


def toolchain_scout_context(context: Dict[str, Any], scout: str = "all", timeout: int = 45) -> Dict[str, Any]:
    return run_toolchain("scout_context", {"context": context or {}, "scout": scout}, timeout=timeout)
