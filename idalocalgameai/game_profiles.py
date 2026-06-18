"""Game-engine profile hints used in prompts and triage."""

from __future__ import annotations

from typing import Dict, List


PROFILES: Dict[str, Dict[str, List[str]]] = {
    "Auto": {
        "focus": [
            "detect likely engine family",
            "classify gameplay systems",
            "identify update loops, managers, dispatchers, object/entity handling",
        ],
        "hints": [],
    },
    "Unreal": {
        "focus": ["UObject/UClass/UFunction", "ProcessEvent", "Tick/BeginPlay", "GWorld/GNames/GUObjectArray", "FName/FString/TArray"],
        "hints": ["reflection strings", "Blueprint names", "actor/component hierarchy", "virtual calls through UObject classes"],
    },
    "Unity IL2CPP": {
        "focus": ["GameAssembly.dll", "global-metadata.dat", "metadata/code registration", "MonoBehaviour methods", "Update/FixedUpdate/LateUpdate"],
        "hints": ["il2cpp exports", "class/method tables", "scene and asset strings"],
    },
    "Source": {
        "focus": ["interfaces", "vtables", "entity list", "convars", "networked vars", "input/render callbacks"],
        "hints": ["CreateInterface", "client/server modules", "prediction and networking paths"],
    },
    "Custom": {
        "focus": ["main loop", "resource managers", "scripting VM", "ECS/object model", "serialization", "packet handlers"],
        "hints": ["init order", "manager singletons", "asset/config/save systems"],
    },
}


def profile_names() -> List[str]:
    return list(PROFILES.keys())


def prompt_for_profile(name: str) -> str:
    profile = PROFILES.get(name) or PROFILES["Auto"]
    focus = "\n".join("- " + item for item in profile.get("focus", []))
    hints = "\n".join("- " + item for item in profile.get("hints", []))
    return "Engine profile: %s\nFocus:\n%s\nHints:\n%s" % (name, focus, hints or "- none")

