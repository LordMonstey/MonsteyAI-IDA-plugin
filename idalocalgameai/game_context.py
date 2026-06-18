"""Game identity and lightweight background lookup."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional

from .config import config_dir


GENERIC_NAME_PARTS = {
    "bin",
    "binaries",
    "capture",
    "client",
    "debug",
    "dump",
    "dumped",
    "game",
    "gameassembly",
    "ida",
    "main",
    "server",
    "shipping",
    "steam",
    "ue4",
    "ue5",
    "unityplayer",
    "win64",
    "win32",
    "windows",
    "x64",
    "x86",
}

INTERESTING_STRING_TOKENS = [
    "project",
    "product",
    "gamename",
    "game name",
    "steam_appid",
    "appmanifest",
    "unreal",
    "unity",
    "il2cpp",
    "uobject",
    "ufunction",
    "process_event",
    "processevent",
    "/game/",
    "content/",
    "assets/",
]

_STRING_SCAN_CACHE: Dict[str, List[str]] = {}
_LOOKUP_CACHE: Dict[str, Dict[str, Any]] = {}


def safe_key(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    text = text.strip("._-")
    return text[:96] or "unknown"


def research_dir() -> str:
    root = os.path.join(config_dir(), "game_research")
    os.makedirs(root, exist_ok=True)
    return root


def cache_path(candidate: str) -> str:
    return os.path.join(research_dir(), "%s.json" % safe_key(candidate))


def strip_timestamp_suffix(value: str) -> str:
    tokens = [token for token in re.split(r"\s+", value.strip()) if token]
    if len(tokens) < 4:
        return value.strip()
    for idx, token in enumerate(tokens):
        if not re.fullmatch(r"(?:19|20)\d{2}", token):
            continue
        suffix = tokens[idx:]
        prefix = tokens[:idx]
        if len(suffix) >= 3 and prefix and all(re.fullmatch(r"\d{1,4}", item) for item in suffix):
            return " ".join(prefix).strip()
    return value.strip()


def clean_candidate(text: Any) -> str:
    value = str(text or "")
    value = os.path.splitext(os.path.basename(value))[0] or value
    value = re.sub(r"[_\-.]+", " ", value)
    value = re.sub(
        r"\b(win64|win32|x64|x86|shipping|debug|release|dump|dumped|fulldump|minidump|memorydump|client|server)\b",
        " ",
        value,
        flags=re.IGNORECASE,
    )
    value = strip_timestamp_suffix(value)
    value = re.sub(r"\s+", " ", value).strip(" -_.")
    return value


def truncate_display(value: str, max_chars: int = 34) -> str:
    value = str(value or "").strip()
    if len(value) <= max_chars:
        return value
    keep = max(8, max_chars - 3)
    return value[:keep].rstrip() + "..."


def is_good_candidate(text: str) -> bool:
    if not text or len(text) < 3:
        return False
    low = text.lower()
    parts = {part for part in re.split(r"\s+", low) if part}
    if low in GENERIC_NAME_PARTS:
        return False
    if parts and parts.issubset(GENERIC_NAME_PARTS):
        return False
    if re.fullmatch(r"[0-9a-f]{6,}", low):
        return False
    return True


def path_candidates(database: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    paths = [database.get("root_filename"), database.get("input_file")]
    input_file = database.get("input_file") or ""
    if input_file:
        parent = os.path.basename(os.path.dirname(input_file))
        grandparent = os.path.basename(os.path.dirname(os.path.dirname(input_file)))
        paths.extend([parent, grandparent])
        if parent.lower().endswith("_data"):
            paths.append(parent[:-5])
    for value in paths:
        candidate = clean_candidate(value)
        if is_good_candidate(candidate) and candidate not in out:
            out.append(candidate)
    return out[:6]


def extract_candidates_from_strings(strings: Iterable[str]) -> List[str]:
    out: List[str] = []
    patterns = [
        r"(?:ProjectName|GameName|ProductName|ProductVersion|AppName)\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9 _.'-]{2,80})",
        r"(?:/Game/|Content/)([A-Za-z0-9_][A-Za-z0-9_ -]{2,60})",
        r"steamapps[/\\]common[/\\]([^/\\]{3,80})",
    ]
    for text in strings:
        for pattern in patterns:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                candidate = clean_candidate(match.group(1))
                if is_good_candidate(candidate) and candidate not in out:
                    out.append(candidate)
                    if len(out) >= 8:
                        return out
    return out


def collect_interesting_strings(cache_key: str = "default", max_seen: int = 3500, max_items: int = 90) -> List[str]:
    cache_key = "%s:%d:%d" % (safe_key(cache_key), int(max_seen), int(max_items))
    if cache_key in _STRING_SCAN_CACHE:
        return list(_STRING_SCAN_CACHE[cache_key])
    try:
        import idautils
    except Exception:
        return []
    out: List[str] = []
    seen = set()
    try:
        for idx, item in enumerate(idautils.Strings()):
            if idx >= max_seen:
                break
            text = str(item)
            if len(text) < 4 or len(text) > 260:
                continue
            low = text.lower()
            if not any(token in low for token in INTERESTING_STRING_TOKENS):
                continue
            if text in seen:
                continue
            seen.add(text)
            out.append(text)
            if len(out) >= max_items:
                break
    except Exception:
        _STRING_SCAN_CACHE[cache_key] = out
        return out
    _STRING_SCAN_CACHE[cache_key] = out
    return out


def read_cached(candidate: str, ttl_days: int) -> Optional[Dict[str, Any]]:
    path = cache_path(candidate)
    if not os.path.isfile(path):
        return None
    try:
        age_seconds = time.time() - os.path.getmtime(path)
        if age_seconds > max(1, ttl_days) * 86400:
            return None
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data["cache_hit"] = True
            return data
    except Exception:
        return None
    return None


def write_cached(candidate: str, data: Dict[str, Any]) -> None:
    try:
        with open(cache_path(candidate), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
    except Exception:
        pass


def related_topics(data: Dict[str, Any], limit: int = 3) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    stack = list(data.get("RelatedTopics") or [])
    while stack and len(out) < limit:
        item = stack.pop(0)
        if not isinstance(item, dict):
            continue
        if "Topics" in item:
            stack.extend(item.get("Topics") or [])
            continue
        text = str(item.get("Text") or "").strip()
        url = str(item.get("FirstURL") or "").strip()
        if text:
            out.append({"text": text[:360], "url": url})
    return out


def duckduckgo_lookup(candidate: str, ttl_days: int = 14) -> Dict[str, Any]:
    memory_key = "%s:%d" % (safe_key(candidate), int(ttl_days))
    if memory_key in _LOOKUP_CACHE:
        return dict(_LOOKUP_CACHE[memory_key])
    cached = read_cached(candidate, ttl_days)
    if cached:
        _LOOKUP_CACHE[memory_key] = dict(cached)
        return cached

    query = "%s video game" % candidate
    params = urllib.parse.urlencode(
        {
            "q": query,
            "format": "json",
            "no_html": "1",
            "no_redirect": "1",
            "skip_disambig": "1",
        }
    )
    url = "https://api.duckduckgo.com/?%s" % params
    result: Dict[str, Any] = {
        "cache_hit": False,
        "query": query,
        "source": "DuckDuckGo Instant Answer",
        "heading": "",
        "abstract": "",
        "url": "",
        "related": [],
        "error": "",
    }
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Monstey-AI-plugin/0.1"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        result["heading"] = str(data.get("Heading") or "")[:160]
        result["abstract"] = str(data.get("AbstractText") or "")[:900]
        result["url"] = str(data.get("AbstractURL") or "")
        result["related"] = related_topics(data)
    except Exception as exc:
        result["error"] = str(exc)[:260]
    write_cached(candidate, result)
    _LOOKUP_CACHE[memory_key] = dict(result)
    return result


def collect_game_context(database: Dict[str, Any], cfg: Any, function_strings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    function_string_values = [str(item.get("value") or item.get("string") or "") for item in (function_strings or []) if isinstance(item, dict)]
    scan_enabled = bool(getattr(cfg, "enable_global_string_scan", False))
    cache_key = database.get("root_filename") or database.get("input_file") or "default"
    local_strings = collect_interesting_strings(cache_key) if scan_enabled else []
    path_items = path_candidates(database)
    candidates = []
    for candidate in path_items + extract_candidates_from_strings(function_string_values + local_strings):
        if candidate not in candidates:
            candidates.append(candidate)
    selected = candidates[0] if candidates else ""
    process_name = selected.strip()
    process_display = truncate_display(process_name or selected or "unknown")

    online = {
        "enabled": bool(getattr(cfg, "enable_game_research", True)),
        "used": False,
    }
    if selected and online["enabled"]:
        online = duckduckgo_lookup(selected, int(getattr(cfg, "game_research_ttl_days", 14)))
        online["enabled"] = True
        online["used"] = True

    return {
        "identity_candidates": candidates[:10],
        "selected_candidate": selected,
        "process_name": process_name,
        "process_display": process_display,
        "process_full_name": selected,
        "database": database,
        "local_clues": {
            "path_candidates": path_items,
            "interesting_strings": local_strings[:35],
            "function_strings": function_string_values[:20],
            "global_string_scan": "enabled_cached" if scan_enabled and local_strings else "enabled_empty" if scan_enabled else "disabled_for_speed",
        },
        "online_lookup": online,
        "notes": [
            "Online lookup is lightweight background context, not proof.",
            "Prefer strings, xrefs, imports, and current binary evidence over web context.",
            "Use process_name/process_display for UI identity; selected_candidate may be a cleaned product title.",
            "Global IDB string scanning is disabled by default to avoid IDA 'Generating a list of strings' delays.",
        ],
    }
