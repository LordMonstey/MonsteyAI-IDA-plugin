# Changelog

## v0.3.13 - Pleasant workflow pass

### Highlights

- Added a compact animated analysis pipeline in the Function tab.
- Added non-intrusive status toasts for completed actions, errors, copies, jumps, and applies.
- Added a persistent `Review Queue` tab for Monstey review marks.
- `Mark Review` now writes into IDA and persists the mark in the per-dump Process Map.
- Review Queue supports refresh, jump, copy, remove, and clear.
- Process Map now counts review marks.

## v0.3.12 - LordMonstey Made + IDA symbiote pass

### Highlights

- Public name aligned to `MonsteyAI-IDA-plugin`.
- Added the `LordMonstey Made That` opening animation inside the IDA panel.
- Added permanent `LordMonstey Made` branding in the panel header.
- Added `Mark Review`, a direct IDA interaction that comments and colors the current AI focus as a review point.
- Added a public IDA screenshot to the README.
- Added `docs/SYMBIOTE_ROADMAP.md` with the next high-impact IDA interaction ideas.

## v0.3.11 - Plug-and-play public release

First GitHub-ready release of Monstey-AI-plugin.

### Highlights

- Plug-and-play Windows setup through `setup.cmd` / `setup.ps1`.
- Local-first LLM workflow for Ollama, LM Studio, vLLM, or any OpenAI-compatible endpoint.
- Optional Gemini hosted provider through Google's OpenAI-compatible API.
- IDA focus tracking, focus lock, red-region ASM fallback, and right-click analysis action.
- Evidence Pack and context-only Council scouts for XREF/caller/callee/string evidence.
- Trainer Radar for hook usefulness, expected hook effect, log-first fields, and validation experiments.
- Action Lab with MinHook/call scaffold prompting.
- Pseudo Diff for comparing old/new Hex-Rays pseudocode across game versions.
- Static evidence imports for diffing, capa/YARA-style findings, signatures, structures, and analyst notes.
- Debug Trace popup and environment diagnostic script for support.
- GitHub-ready issue templates, CI, security policy, contribution guide, and release packaging.

### Validation

- PowerShell setup dry-run.
- PowerShell script parse checks.
- Python compile check for the plugin package.
- Release zip packaging with cache/binary exclusions.
