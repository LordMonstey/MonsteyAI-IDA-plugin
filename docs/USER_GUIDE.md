# User Guide

## First run

1. Start your local LLM server if you use the local provider.
2. Open IDA.
3. Open `MonsteyAI-IDA-plugin`.
4. Go to `Settings`.
5. Confirm `Provider`, `Base URL`, `Model preset`, and `Engine profile`.
6. Press `Test LLM`.

The panel opens with a short `LordMonstey Made That` signature animation. It is cosmetic and non-blocking.

## Model presets

The plugin supports two provider modes:

- `Local / Ollama`: local OpenAI-compatible endpoint such as Ollama, LM Studio, or vLLM.
- `Gemini hosted`: Google's Gemini OpenAI-compatible API.

The local machine is prepared with three Ollama models:

- `Deep reverse - qwen3-coder:30b`: best default for hard reverse engineering and red ASM regions.
- `Balanced - qwen2.5-coder:14b`: good middle ground when Deep is too slow.
- `Fast - qwen2.5-coder:7b`: quick first pass for simple functions.

Default endpoint:

```text
http://127.0.0.1:11434/v1
```

If the first Deep request takes time, that usually means Ollama is loading the model into memory.

## Analysis Speed

`Settings > Analysis speed` controls how much context the plugin collects before calling the model:

- `Fast`: shortest pass, skips XREF expansion, tight ASM/pseudocode budget, lower answer token budget.
- `Balanced`: limited XREF expansion and larger context.
- `Deep`: richer but slower pass for hard functions.

During analysis, a dedicated `Debug Trace` popup shows the live processing trace: context capture, focus/mode, context timings, provider/model, budget, compact prompt size, LLM request/response, JSON parse or repair, local enrichment, heartbeat, timeout, and watchdog fallback. The Function tab keeps the final summary readable instead of being replaced by debug logs. Use `Debug Trace` to reopen the popup, `Copy Debug Trace` to copy the processing log, and `Copy Summary` to copy the final rendered analysis summary.

Use `Quick Local Pass` when you want an immediate no-LLM pass. It still collects focused IDA context and semantic cues, then fills the summary/trainer assessment locally. This is useful for quick hook usefulness checks or when the hosted/local model is slow.

## Analysis Profile

`Settings > Analysis profile` changes what Monstey optimizes for:

- `Trainer / Modding`: game dump analysis, hook usefulness, values to log, modification surfaces, structure hypotheses, and trainer experiments.
- `Driver IOCTL`: defensive Windows driver auditing. Monstey looks for IOCTL dispatch, `IoControlCode` checks, IRP/request buffers, transfer method hints, validation gaps, device strings, and memory copy/map/process primitives.

In `Driver IOCTL` mode, the report shows a dedicated `Driver IOCTL Risk Radar`. It is evidence-first: it should say what is proven, what is only a lead, and what must be verified before calling something a vulnerability.

If `Driver IOCTL` is accidentally left enabled while analyzing a game dump, Monstey applies a profile guard. Without driver/IOCTL evidence or a driver-like target, the current analysis is treated as `Trainer / Modding` and the debug trace records the downgrade.

## AI Focus Lock

The `AI focus` row shows which address Preview/Analyze will use.

- Hover/click normally to let the focus follow IDA.
- Hold `A` for 1.5 seconds to lock the AI focus on the current address.
- Press `A` again to unlock.
- When locked, the focus row shows `LOCKED` and that address wins over mouse/cursor movement.
- `Jump` moves IDA to the current AI focus.
- `Mark Review` writes a Monstey review comment and color marker directly into the IDB at the current AI focus.

## Review Queue

Every `Mark Review` action is saved in the local per-dump Process Map and appears in the `Review Queue` tab.

- `Jump`: move IDA to the selected mark.
- `Copy Queue`: copy a compact report for notes or issue reports.
- `Remove`: remove one selected mark from the queue.
- `Clear`: clear all marks for the current dump.

The IDA comment/color stays in the IDB until you edit or recolor it manually.

## Pleasant UI Feedback

The Function tab includes a compact animated pipeline:

```text
Focus -> Context -> Evidence -> Provider -> LLM -> Parse -> Enrich -> Ready
```

It updates from the live debug trace so you can tell whether Monstey is collecting context, waiting for the provider, parsing JSON, or falling back locally. Completed actions also show a small toast in the lower-right corner of the panel.

## Agent Mode

`Settings > Agent mode` controls how many analyst roles cooperate on the same shared context:

- `Single`: one analyst pass. Best default when you want speed or when testing provider stability.
- `Duo`: local scout builds an `Evidence Pack` and `Claim Board`; the LLM analyst must use those shared facts.
- `Council`: Context Council. Local scout plus XREF/caller/callee/string scouts prepare external context before the LLM analyst. The solo analyst remains the final source of truth.

Council excludes Gemini automatically. If `Provider` is set to `Gemini hosted`, Council forces the local OpenAI-compatible provider so hosted credits/quota are not consumed. Use `Single` or `Duo` if you explicitly want the selected hosted provider.

The `Evidence Pack` contains source facts like `F001`, `F002`, strings, xrefs, offsets, dirty masks, reader calls, and semantic cues. The `Claim Board` contains shared hypotheses like `C001`, `C002`. Context scouts can add or update claims using those fact IDs before the analyst prompt is built. The Function tab renders an `Agent council` section so you can see which scouts contributed and which claims were available to the analyst.

The XREF context scout focuses on joining evidence across callers, callees, data refs, strings, and `xref_expansion`. It adds context links before the analyst decides what the function is useful for. There is no post-analysis critic or synthesizer pass in current Council mode.

Trainer/modding remains a first-class requirement in Council. The final answer must still fill `Trainer lab`: expected hook effect, usefulness, strategy, modification surface, values to log, candidate trainer ideas, validation experiments, non-use cases, and stability notes.

Practical use:

- use `Single` while browsing quickly;
- use `Duo` for normal serious analysis;
- use `Council` when XREF context matters, but you still want the normal solo analyst quality.

Hosted Gemini presets:

- `Deep hosted - Gemini 2.5 Pro`: best hosted default for hard reverse engineering.
- `Balanced hosted - Gemini 2.5 Flash`: cheaper/faster hosted pass.
- `Fast hosted - Gemini 3.5 Flash`: quick hosted first pass.

Gemini endpoint:

```text
https://generativelanguage.googleapis.com/v1beta/openai
```

For Gemini, paste a Gemini API key from Google AI Studio into `Settings > API key`, then press `Test LLM`. A Gemini/Gemini Pro web subscription is not always the same thing as API access; the plugin needs a valid API key.
If `gemini-2.5-pro` fails with HTTP 429 and a `limit: 0` quota message, the API key/project currently has no Pro API quota. Use `gemini-2.5-flash` for now, or enable billing/quota for the Gemini API project.

## Understanding confidence

Confidence is model-provided and should be treated as a review signal, not a fact.

Prefer suggestions that include:

- concrete strings;
- named imports;
- obvious call targets;
- repeated xref patterns;
- recognizable engine patterns;
- consistent callers/callees.

Be careful with suggestions based only on:

- generic arithmetic;
- short functions;
- missing symbols;
- obfuscated control flow;
- assembly fallback without strings or xrefs.

## Red region analysis

Use `Analyze Red/ASM Region` when:

- Hex-Rays refuses to decompile;
- pseudocode looks wrong;
- the function is marked or rendered in a warning/error color;
- you selected raw assembly;
- you are studying thunks, stubs, hand-written assembly, dispatcher code, jump tables, VM handlers, or obfuscated blocks.

The plugin does not need pseudocode for this mode. It extracts assembly and surrounding evidence.

## Pseudo Rebuild

Use `Pseudo Rebuild` when Hex-Rays cannot produce useful pseudocode but the focused/selected bytes are still executable code.

Workflow:

1. Select the suspicious ASM/red region in IDA, or hover/click the target instruction.
2. Right-click and choose `MonsteyAI-Rebuild Pseudocode`, or press `Rebuild ASM -> Pseudo` in the panel.
3. Review the captured ASM evidence on the left.
4. Review or edit the generated pseudo-C on the right.
5. Press `Analyze Generated Pseudo` to send the reconstructed pseudocode plus original ASM evidence through the normal AI pipeline.

The generated pseudo-C is not Hex-Rays output. It is an approximate reading aid built from assembly mnemonics, registers, memory operands, labels, branches, calls, and returns. Monstey tells the model that this pseudocode is synthetic, so the analysis should still cite and verify against original ASM addresses.

If the selection is mostly `.rdata`, strings, or `db/dw/dd/dq` directives, the rebuild tab warns that the focus looks like data rather than executable code. In that case, inspect the referencing functions or define the bytes as code in IDA before rebuilding.

## Focus-aware analysis

The plugin tracks:

- recent mouse hover/click in IDA views;
- pseudocode cursor position;
- current disassembly cursor;
- highlighted identifier;
- active widget and recent navigation history.

Priority order:

```text
mouse hover -> last click -> pseudocode cursor -> view cursor -> screen EA
```

Use `Preview Focus` before an analysis to confirm that the plugin is looking at the same instruction, pseudocode line, or identifier as you.

Before the LLM request starts, the plugin asks whether you already have a hypothesis for the function or selected ASM/red region. Choose `Yes` to add context such as "looks like inventory stack update" or "probably a player controller helper"; choose `No` to let the AI analyze solo. Your hint is injected as priority analyst context and the model must return a `Your context check` section explaining what evidence supports or contradicts it. The analysis also includes `Algorithm`, `Dataflow`, and `Structure offsets` sections so the model has to explain the mechanics before giving the gameplay label.

## Trainer Assessment

Every function analysis includes a `Trainer assessment` section for local game-modding lab work.

It answers:

- whether the function is useful for a trainer;
- what should happen if you hook it;
- whether to observe, mutate output, mutate arguments, or trace caller/callee first;
- which arguments, output fields, offsets, selectors, and return values to log first;
- candidate trainer ideas supported by current evidence;
- experiments to validate usefulness;
- what the function is probably not useful for directly.

For example, an identity/bitstream parser may be useful for structure mapping and player labeling, but not as a direct health/damage/ammo modification point. A numeric accumulator that writes output slots is usually a stronger candidate, but the plugin still asks you to log before mutating.

## Dump Context

Use the `Dump Context` tab for information that should be available to every analysis of the current dump/process.

Examples:

- process/product name;
- engine/runtime if you know it;
- reverse objective;
- known globals, managers, class names, offsets, signatures;
- local naming conventions.

This context is saved per dump under:

```text
%USERPROFILE%\.monstey-ai-plugin\dump_contexts
```

It is injected into the LLM prompt as analyst-provided background. The model is still required to cite local IDB evidence for function-specific claims.

## Right-click analysis

You can analyze directly from IDA:

1. Select one or more instructions, or place the mouse/cursor on the interesting line.
2. Right-click in the disassembly, pseudocode, hex, or custom view.
3. Choose `MonsteyAI-Analyse`.

If a selection exists, the selected instructions are preferred. Otherwise the plugin uses the current focus.

`MonsteyAI-Analyse` can run without opening the main panel. It uses a hidden controller and shows the `Simple Summary` popup when the result is ready.

Use `MonsteyAI-Analyze + Rename` when you want the same headless analysis plus a valid suggested name applied to the focused function. It only renames default IDA names such as `sub_...`, so existing analyst names are preserved.

## Clickable Evidence

Evidence rows are color-coded by kind: strings, assembly, xrefs, calls, imports, constants, and notes.

Click an address in the `Address` column, or double-click a row, to jump directly to that location in IDA.

The analysis report is interactive as well: in `XREF Evidence Map`, click a caller, callee, current function, or ranked next XREF target to jump to that function/address in IDA. Monstey also moves the focus marker there when focus highlighting is enabled.

## Evidence-Specific Trainer Guidance

Trainer Radar avoids generic hook advice. If the model gives vague text, Monstey filters it and rebuilds `Hook effect`, `Good for`, and experiments from local cues such as output writes, offsets, reader calls, mode selectors, dirty masks, bitwise operations, callers, strings, and analyst hints.

When there is not enough evidence, the Radar should say what is missing and where to inspect next instead of pretending the current function is useful.

## Simple Verbal Summary Popup

After each successful analysis, Monstey opens a small `Simple Summary` popup. It explains the function in plain words: what it appears to do, why it matters, what to check next, and how confident the analysis is.

The default language is English. Use the language selector inside the popup, or `Settings > Popup language`, to switch to French. Disable it with `Settings > Verbal popup`.

The popup also scans raw local clues such as Hex-Rays lines, strings, XREF strings, assembly text, and semantic cues. For example, a function containing `DrawIndexed` is summarized as a graphics draw request instead of a vague unknown helper.

## IDA Comments And Colors

`Apply Comments + Colors` writes the analysis back into IDA:

- summary comment at the function start;
- bounded `AI:` comments on suggested comment/evidence addresses;
- item colors for calls, xrefs, strings, assembly, constants, imports, and notes.

Existing non-AI comments are preserved. Existing `AI:` lines are refreshed so repeated analysis does not endlessly duplicate old AI text.

When Hex-Rays is available, Monstey also tries to write the same bounded comments as pseudocode user comments so they can appear directly in the pseudocode view after refresh.

Enable `Settings > Auto comments/colors` to apply the same comments and colors automatically after each analysis.

The header shows an `Auto:` badge so you can see whether automatic rename and comments are active without opening settings.

## Auto Rename

After a successful function analysis, the plugin automatically applies `suggested_function_name` in IDA when the name passes local validation. You can disable this in `Settings > Auto rename`.

Automatic rename is conservative: it only renames IDA-generated names such as `sub_7FF...`, `j_sub_...`, `nullsub_...`, or `loc_...`. If a function already has a human/analyst name, use `Apply Name` manually to overwrite it.

## Process label

The panel header shows:

```text
Process: cleaned-process (local)
Process: cleaned-process (cached/web)
```

Use this as a quick sanity check. The label uses a shortened process identity, not the full dump filename. If the detected process/dump name looks wrong, adjust the filename/working context or disable process lookup in settings before trusting process-specific conclusions.

`Settings > Global strings` is disabled by default for speed. Enabling it lets the plugin scan global IDB strings for extra process/engine hints, but on large dumps it can trigger IDA's slow `Generating a list of strings` pass. Leave it off unless the dump filename/path gives bad process context.

## Call and Hook Action Lab

When the current analysis is for a function in `Trainer / Modding` profile, `Next questions` includes:

```text
Lets call it and see the returns
Lets hook it and modify something
```

The Function tab also exposes matching buttons. Press one to open `Action Lab`, then tell the AI what you want to observe or modify. You can continue the chat after the first answer, and the plugin keeps the current analysis/context attached.

In `Driver IOCTL` profile, `Next questions` instead prioritizes mapping the IOCTL code/buffer layout and auditing length/probe/access validation before any copy/map/process-memory primitive.

While generating, Action Lab prints debug progress in the chat so you can see prompt construction, provider/model, request send, response time, or failure.

Expected output style:

- `Lets call it and see the returns`: `__fastcall` call scaffold, return logging, out-param logging, and argument validity notes.
- `Lets hook it and modify something`: MinHook-style C++ scaffold using project-style globals and a safe direct call to the original function.

Action Lab has two panes:

- `Chat`: reasoning, assumptions, logging plan, and follow-up discussion.
- `Code Workspace`: the extracted C++ code block in a monospace no-wrap editor, with `Copy Code` and `Save .hpp`.

The assistant avoids anti-cheat bypass, stealth, spoofing, evasion, persistence, or weaponized behavior. Keep the first hook pass observation-heavy: log arguments, return values, important dereferences, and only then modify the smallest behavior you can prove from evidence.

## XREF Expansion

The context sent to the model includes a limited `xref_expansion` block:

- callers around the callsite;
- callees around their entry/callsite;
- local strings;
- nearby assembly;
- incoming/outgoing call counts.

This helps the model understand whether a function looks like a dispatcher, manager, callback, update loop, wrapper, or leaf helper.

## Semantic Cues

The plugin extracts local semantic cues before calling the LLM. These appear in the analysis as `Detected local cues`.

The current cue set focuses on:

- repeated bit/field reader calls such as `read(a1, 64)`, `read(a1, 6)`, `read(a1, 9)`;
- output structure writes and explicit offsets;
- dirty masks like `*out_mask |= X`;
- XOR/ROL/ROR/shift loops and magic constants;
- sentinel/bounds checks;
- hardcoded strings, especially player/network/identity strings.

Use this section to sanity-check the model. If `Detected local cues` says high bitstream/structured-reader likelihood and the summary says "simple copy", the model is probably wrong.

## Process Context

The plugin tries to identify the reversed process from the dump/input filename, parent folders, and IDB strings. If enabled, it also performs a minimal cached online lookup for background context.

Dump timestamps are trimmed before display and lookup. A name such as:

```text
destiny2 2026 06 09 21 54 14
```

is reduced to a useful process identity before the model sees it.

Cache path:

```text
%USERPROFILE%\.monstey-ai-plugin\game_research
```

Disable it in `Settings > Process lookup` when you want zero online lookup.

## Performance Budget

Large or flattened functions can make Hex-Rays painfully slow. The plugin now uses a performance budget:

- `Max decompile instructions`;
- `Max decompile bytes`;
- `Max ASM lines`;
- `Max XREF items`;
- `Max XREF expansions`.

If the function exceeds the decompile budget, pseudocode is skipped and the model receives bounded ASM/focus context instead. For control-flow flattening, select the exact block or dispatcher slice first and use `Analyze Focus ASM/Red`.

## JSON Repair

If the model returns malformed JSON, the plugin automatically runs a local JSON repair pass and retries parsing. If that also fails, the raw parse error is shown.

## Process Map memory

After each successful analysis, the plugin saves a compact local map for the current game/IDB.

Path:

```text
%USERPROFILE%\.monstey-ai-plugin\game_maps
```

The `Process Map` tab shows what the plugin has learned so far: analyzed functions, likely engine hints, important strings, confidence, and risks. New analyses receive a compact version of this memory so the local model can connect related functions instead of treating every function as isolated.

## Evidence Sources

For dump/static analysis, paste external tool facts into `Evidence Sources`.

Path:

```text
%USERPROFILE%\.monstey-ai-plugin\external_evidence
```

Accepted inputs:

- simple lines: `diff 0x140123456 changed constant from 100 to 85`;
- JSON arrays or objects with `items`, `evidence`, `matches`, or `results`;
- static kinds: `diff`, `capability`, `signature`, `crypto_signature`, `deobf`, `structure`, `xref`, `string`, `note`.

Use this for Diaphora/BinDiff-style notes, capa/YARA/FindCrypt-style matches, D-810 simplification notes, HexRaysPyTools structure hints, local signatures, and manual static analyst notes. Evidence is previewed, injected into prompts, added to the Evidence Pack, and rendered as a dedicated colored analysis section.

## Integrations

The `Integrations` tab is a static import hub. Pick a source preset, paste or import exported text/JSON/CSV, preview the normalized rows, then push them into `Evidence Sources`.

Presets:

- `Diaphora / BinDiff`: old/new matches, moved functions, changed constants/calls/offsets;
- `capa / YARA`: capability and custom static rule matches;
- `FindCrypt`: hash/checksum/string-id constants;
- `D-810`: deobfuscation and simplified-control-flow notes;
- `Structures / VTables`: field offsets, object names, vtable hints;
- `Signature Packs`: old dump function names and local signatures;
- `Analyst Notes`: manual static notes anchored to addresses.

Local buttons:

- `Structure Scout`: extracts field reads, output writes, and vtable-looking lines from the current bounded context;
- `Signature Scout`: emits a deterministic local function fingerprint plus callee/string shape;
- `Run Static Scouts`: appends both scouts into the current dump evidence file.

Optional toolchain sidecar:

- `Toolchain Check`: starts a separate Python process and reports which optional libraries are available: Capstone, LIEF, yara-python, Unicorn, Miasm, angr, and manually installed Triton;
- `Obfuscation Scout`: inspects the current bounded ASM for high branch density, dispatcher/flattening shape, indirect branches, opaque predicates, bitwise mixes, and magic constants;
- `Run Toolchain Scouts`: runs Obfuscation Scout plus Capstone operand/control-flow evidence, LIEF file metadata, and custom YARA matches when those libraries are installed.

Install the sidecar from the project root:

```powershell
.\setup.cmd -InstallToolchain -ToolchainTier Core
```

`Core` installs Capstone, LIEF, yara-python, Unicorn, and Miasm into `%USERPROFILE%\.monstey-ai-plugin\toolchain\.venv`. `Advanced` / `Full` also try heavier libraries such as angr. The plugin never imports these libraries inside IDA; it talks to the sidecar through bounded JSON.

For custom YARA rules, place `.yar` or `.yara` files in:

```text
%USERPROFILE%\.monstey-ai-plugin\yara
```

Automatic sidecar scouts:

When `Settings > Reverse Context > Sidecar scouts` is enabled, normal LLM analysis can call the sidecar before the Evidence Pack and prompt are built. Monstey auto-runs the sidecar when the focused context shows signs such as:

- ASM fallback or reconstructed pseudocode;
- Hex-Rays pseudocode skipped by budget/failure;
- high branch density or flattening hint;
- indirect jump/call through memory;
- bitwise-heavy code with XOR/AND/OR/shift/rotate patterns.

Fast/Balanced suspicious contexts usually run the bounded `obfuscation` scout. Deep analysis may run `all` when file metadata/rules are useful. The Debug Trace shows the trigger, selected scout, timeout, row count, and elapsed time. If no trigger is found, Debug Trace says the sidecar was skipped.

## Sanitization

Text imported from external static tools is sanitized before it reaches prompts:

- file imports are capped to 4 MiB with a visible truncation note;
- control characters and ANSI terminal escapes are removed;
- Evidence Source kinds are whitelisted, unknown kinds become `note`;
- imported lines starting with `system:`, `assistant:`, or `developer:` are quoted before prompt injection;
- long fields are truncated before storage, preview, or model context.

## Applying changes

The MVP can apply:

- function names;
- comments.

It does not automatically apply:

- types;
- structures;
- variable renames;
- mass rename jobs.

Those are intentionally kept for later sprints after more validation.
