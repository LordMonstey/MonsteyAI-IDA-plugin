# Changelog

## v0.3.15 - Optional analysis toolchain sidecar

### Highlights

- Added a separate Python sidecar for optional heavy reverse-engineering libraries so IDAPython stays stable.
- Added sidecar library detection for Capstone, LIEF, yara-python, Unicorn, Miasm, angr, and manually installed Triton.
- Added `Toolchain Check`, `Obfuscation Scout`, and `Run Toolchain Scouts` buttons in the `Integrations` tab.
- Obfuscation Scout emits static evidence for high branch density, dispatcher/flattening shape, indirect branches, opaque predicates, bitwise mixes, and magic constants.
- Capstone, LIEF, and YARA enrich Evidence Sources automatically when installed.
- Added `scripts/setup_toolchain.ps1` plus `setup.ps1 -InstallToolchain -ToolchainTier Core|Advanced|Full`; Core installs Capstone, LIEF, yara-python, Unicorn, and Miasm.
- Added optional sidecar requirements files for core and advanced toolchains.

## v0.3.14 - ASM pseudo rebuild workflow

### Highlights

- Added a `Pseudo Rebuild` tab that captures selected/focused ASM or red code and generates approximate pseudo-C.
- Added right-click `MonsteyAI-Rebuild Pseudocode` in IDA views.
- Generated pseudo-C stays editable before analysis and remains paired with the original ASM evidence.
- `Analyze Generated Pseudo` sends the synthetic pseudocode through the normal Monstey analysis pipeline.
- Prompts now tell the model that reconstructed pseudocode is approximate and must be verified against ASM addresses.
- Data/string selections are warned as data-like instead of being silently treated as executable code.

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
