# IDA Symbiote Roadmap

MonsteyAI-IDA-plugin should feel less like a chatbot next to IDA and more like an analyst layer living inside the IDB.

## Implemented

- Live AI focus follows mouse/cursor/selection.
- Focus lock with long-press `A`.
- Jump to current AI focus.
- Temporary highlight for the current AI focus.
- Apply AI suggested names, comments, and colors.
- Right-click `MonsteyAI-Analyse` in IDA views.
- `Mark Review` writes a Monstey review comment and color marker at the current AI focus.
- Persistent `Review Queue` stores review marks per dump/process with jump, copy, remove, and clear actions.
- Animated analysis pipeline shows where Monstey is during a pass.
- Status toasts confirm completed actions without covering the analysis.
- IDA rename events refresh Monstey context labels and global/data names.

## High-Impact Next Moves

### 1. Review Trail Upgrade

Extend the current Review Queue:

- add status presets: `candidate`, `needs-xref`, `hook-later`, `not-useful`, `confirmed`;
- allow inline status editing;
- export a richer markdown review report.

### 2. XREF Walk Mode

Turn the current function into an explorable trail:

- current function in the center;
- callers, callees, data refs, string refs around it;
- one-click promote a neighbor into the next analysis focus;
- preserve why the neighbor was selected.

### 3. Type/Struct Drafting

Use observed offsets to create draft IDA structures:

- build pseudo-struct previews from `[reg+offset]`, output writes, vtable hints, and member access;
- let the user apply a draft struct only after review;
- keep uncertainty in field names, never silently overwrite trusted types.

### 4. Function Role Layers

Color functions by role:

- parser/deserializer;
- stat/damage/modifier;
- identity/player/account;
- input/action;
- renderer/UI;
- allocator/container;
- validation/checksum/hash.

The color should come from evidence strength, not just the LLM guess.

### 5. Smart Comments

Upgrade comments from static text to navigational breadcrumbs:

- comments include evidence IDs like `F001`, `C002`;
- clicking an evidence row jumps to the IDA address;
- the Process Map links a comment back to the analysis that created it.

### 6. Patch/Experiment Planner

For static analysis labs, generate safe experiment plans:

- observe-only hook;
- call-count/caller logger;
- argument/return recorder;
- output-slot compare;
- mutation-gated experiment.

The plugin should keep generated C++ in Action Lab, while IDA stores only reviewed names/comments/colors.

### 7. Diff-Aware Porting

Connect Pseudo Diff and Signature Scout:

- compare old/new pseudocode;
- detect changed calls, constants, offsets, and output fields;
- suggest likely renamed functions in the new dump;
- keep trainer/hook porting notes.

## Design Rules

- IDA remains the source of truth.
- Every automatic write must be reviewable or reversible.
- LLM output should be anchored to addresses, evidence IDs, and local facts.
- The UI should make uncertainty visible instead of hiding it.
- Local-first remains the default for private reversing labs.
