# Research & Design Decisions

---
**Purpose**: Capture the discovery findings and architectural investigation behind the `harnessx-self-improving-rulesets` spec. This is the background-notes companion to `design.md` — it records *what was read*, *what was found in the source*, and *why* the three resolved decisions came out the way they did. `design.md` carries the committed architecture; this file carries the evidence and the rejected alternatives.
---

## Summary
- **Feature**: `harnessx-self-improving-rulesets`
- **Discovery Scope**: Complex Integration (adopt an external agent-runtime library + re-architect the in-house rule/policy/scoring planes)
- **Key Findings**:
  - HarnessX and OpenUltraSAST (OUS) already both have a thing called a "harness" with "processors" and "events", but they are **incompatible at every load-bearing point**: HarnessX is async-generator / message-window-contract / transcript-state; OUS is sync / declared-`reads`/`writes`-contract / dict-state. There is no drop-in.
  - HarnessX's real, reusable value for OUS is concentrated in three places: the **LLM hunter agent loop** (control/tools/observability processors), the **llm-judge verifier** (`build_judge_prompt`/`parse_judge_response`/`_call_judge`), and the **meta-harness self-improvement engine** (journal / novelty / evidence / replay / attribution). Everything else (lab web UI, browser tools, sandboxes, office skills) is unused weight.
  - OUS today fuses **detector + severity authority + volume control** into one regex layer (`PATTERN_RULES` in `findings.py`); its self-improvement loop only demotes *ranking* (floored at `0.1`, keyed on `tags[0]`), never the rules; and its benchmark already names the ruleset as the thing to fix (`next_improvement_candidate="rules_or_language_hunter"`) but writes it to an inert JSON. The signals exist; the loop back onto the rules does not.
  - The `verycode` policy data (`CWE_Score.tsv`, 167 CWEs, severity 0-5 + static/dynamic scope) is **complete and authoritative**, but the `verycode-score` scoring *algorithm was never implemented* (`// scorer code here` placeholder). The score formula in the design is a labeled, defensible reconstruction.
  - OUS today has **zero runtime dependencies** (`dependencies = []`); HarnessX's `dependencies` list is ~30 heavyweight packages (Playwright, Docker SDK, FastAPI/uvicorn, multi-LLM SDKs, office-doc suite) with **no lean extra** to pip-install a subset — a direct hard dependency would invert the project's supply-chain posture for a security tool.

## Research Log

### HarnessX core composition & runtime model
- **Context**: We need to know whether OUS's `harness.HarnessRuntime` can be replaced by, or interoperate with, HarnessX's `Harness`, and how an external project builds and runs a HarnessX harness.
- **Sources Consulted**: `/tmp/HarnessX/harnessx/core/{harness,builder,processor,events,runloop,state,contract_check,config_schema,config_store,model_config,trajectory}.py` (read in full); `/home/mc/Source/OpenUltraSAST/src/openultrasast/harness.py`.
- **Findings**:
  - Public composition is three objects + one method: `HarnessBuilder.build() -> HarnessConfig`; `ModelConfig.agentic(HarnessConfig) -> Harness`; `await Harness.run(task) -> HarnessResult`. **`HarnessConfig` carries NO model info** — model is always supplied separately via `ModelConfig` (key→provider map, `main` required, non-`main` keys auto-get sub-harnesses).
  - `HarnessBuilder` is an immutable fluent factory: `add(proc)`, `slot(**kw)`, `add_tool`, `plugin(source)`, `__or__`/`merge` (collects conflicts → `HarnessConflictError`), `build()` (topo-sorts processors per hook by `_order` then Kahn within a bucket by `_after`). Declarative alt: `build_from_config(dict)` from a flat `processors:` list of `_target_` dicts.
  - The run loop (`run_loop`) is a fixed async agent loop: `task_start` → `while True:` (step: `step_start` → `before_model` → call provider → `after_model` → per-tool `before_tool`/exec/`after_tool` → `step_end`) → `task_end`. `get_procs(key)` runs `"*"` (MultiHook) processors on every hook, then hook-specific lists.
  - State is **two message tracks** (`raw_messages` append-only, `messages` effective context) + typed `slots: dict[str, StateSlot]` (the nearest analogue to OUS's flat `state` dict, but typed and `_target_`-serializable). `StatefulTrajectory` is a first-class product (`s_t = (z_t, Δz_t, a_t, o_t, e_t, r_t)`), built inline during `run_loop`, with `backfill_rewards` and `to_training_records`/`to_rl_records`.
  - Hook-name alignment vs OUS: 5/8 match exactly (`task_start`, `before_model`, `after_model`, `before_tool`, `after_tool`, `task_end`); the gap is `stage_start`/`stage_end` ↔ `step_start`/`step_end`. Semantically an OUS "stage" is a coarse pipeline phase wrapping a callback (`run_stage(name, callback)`), whereas a HarnessX "step" is one model-call iteration — not the same concept.
- **Implications**: A whole-pipeline swap is high risk. The cheapest correct adoption confines HarnessX's async loop to the one OUS stage that *is* an agent loop (the hunter pool) and keeps the sync driver for deterministic stages. This directly motivates Decision D1 (phased seam, not big-bang).

### The two incompatible processor contracts
- **Context**: OUS's defining feature is a declared `reads`/`writes` per-key state contract. We must know if HarnessX preserves it.
- **Sources Consulted**: `/tmp/HarnessX/harnessx/core/{processor,contract_check}.py`; `/home/mc/Source/OpenUltraSAST/src/openultrasast/harness.py:49-118`.
- **Findings**:
  - HarnessX `Processor` is `async def process(event) -> AsyncIterator[Event]` — an async generator that yields transformed events. The recommended base is `MultiHookProcessor` with `on_*` hook methods, an `@on(EventClass)` decorator, and class-attr ordering hints (`_order`, `_after`, `_singleton_group`, `_hook`). There is **no `spec`, no `handles`, no `reads`/`writes`.**
  - HarnessX's contract governs **message-window mutation**, not state keys: enforced in `ProcessorChain.process` via `_validate_messages_contract` (system stays at index 0 on `step_start`; `before_model` net length ∈ {0,+1}; appended message must be role `user`; no out-of-window edits) and per-chain `check_post_hook_invariants`. Mode is the env var `HARNESSX_CONTRACT_MODE ∈ {warn(default), strict}` — not a constructor arg.
  - OUS `Processor` is **synchronous**, `def handle(event, state: dict) -> dict | None`, with `spec: ProcessorSpec(name, version, handles, reads, writes)`; `_run_processor` enforces *state-key* discipline (reads must pre-exist; writes must be declared; return must be a dict). `ContractMode` is a `"strict"|"warn"` constructor arg.
- **Implications**: The two contracts do not map onto each other. OUS's per-key allow-list (its provenance/audit discipline) has **no home in HarnessX**. To keep that discipline we must reimplement it as a `SlotContractMixin` on our HarnessX processors (`reads_slots`/`writes_slots` class attrs validated in a base `on_*` wrapper), gated by our own `OUS_SLOT_CONTRACT` env. This is Decision D7.

### HarnessX built-in processors — reuse map
- **Context**: Which HarnessX processors can OUS register directly, which are reusable as patterns/helpers, and which are irrelevant?
- **Sources Consulted**: `/tmp/HarnessX/harnessx/processors/` (control, tools, multi_model, observability, evaluation, memory, context); `/home/mc/Source/OpenUltraSAST/src/openultrasast/cli.py` (`_run_scan`).
- **Findings**:
  - **Register-direct only inside the hunter loop** (the one real agent loop): `LoopDetectionProcessor`, `CostGuardProcessor`/`TokenBudgetProcessor`, `ToolFailureGuard`, `SelfVerifyProcessor`, `ToolFilterProcessor`/`ToolWhitelistProcessor`, `ModelRouterProcessor`, `EpisodeMetricsProcessor`/`OTelProcessor`/`CheckpointProcessor`.
  - **Reuse as helper functions** for `verify`: the `llm_judge` code (`build_judge_prompt`, `parse_judge_response` with the verdict whitelist, the two-attempt repair loop `_call_judge`) plus the strict-JSON verdict schema (`verdict/confidence/cause/missing_capability`/`lesson`/`missing`). The judge is explicitly told "ground truth is intentionally withheld" — matching OUS's no-oracle scanning.
  - **Reuse as pattern** for `calibrate`/`record_calibration`: `MemoryRetrievalProcessor` + `MemoryPolicy` (retrieve/add, should_retrieve/should_store) is the clean interface to refactor the FP ledger toward; `MemoryExtractionProcessor` mirrors distilling verifier outcomes into durable learnings. Storage stays a custom JSON ledger.
  - **Keep custom** for every SAST-domain stage: `static_mapping`, `preprocess`, `entry_point_mapping`, `quick_findings`, `report`, `sarif`, `manifest`, and the benchmark recall/FP scoring (HarnessX `EvalResult.score` is a single float — too coarse for the recall/FP gate).
- **Implications**: Adoption is bimodal — register HarnessX classes directly only in the hunter sub-harness; everywhere else port logic as helpers or patterns. This is the backbone of the §3 flow-migration table in `design.md`.

### HarnessX self-improvement (meta_harness) and the rule-adaptation seam
- **Context**: Can an external signal (a verifier rejection or a benchmark miss) drive a *detection-rule* change through HarnessX's self-improvement loop, and how does it compare to OUS's current calibration?
- **Sources Consulted**: `/tmp/HarnessX/harnessx/meta_harness/{agent,journal,replay,validate_workflow}.py`, `processors/contract_autocheck.py`, `workers/trajectory_digester.py`, `rl/{builder,config,task}.py`; `/home/mc/Source/OpenUltraSAST/src/openultrasast/{calibration,benchmark,findings,rank,cli}.py`.
- **Findings**:
  - HarnessX self-improves a *harness* round by round. The unit of change is a `HarnessConfig` (the meta-agent literally rewrites the inner agent's config/processors/templates as files); the unit of memory is a markdown **journal** with per-`## Round N` YAML frontmatter; the unit of safety is a multi-phase **validation gate**.
  - The journal classifies every change by a **lever** from `_VALID_LEVERS = {configuration, control, action, instruction}` and tracks `predicted_affected` task_ids plus a `gating_attribution` (`flipped/still_F/regressed/still_T/absent`). `build_context` renders a per-lever **time-decayed Beta posterior** scoreboard (`_DECAY=0.9`) and an explicit "Reverted hypotheses — do not re-propose" list.
  - `EvolveValidator.run` enforces validity (canonicalize → contract → diff → replay smoke gate), policy (novelty + evidence, only when the diff is non-empty), advisory. `check_novelty` hard-blocks re-proposing a reverted hypothesis or reverted `(levers, predicted_affected)` signature unless a `retry_rationale` is present. `_evidence` requires a `candidates.md` `## Candidate C-N` cross-referenced by the journal. `run_synthetic_task_smoke_gate` proves the evolved config boots end-to-end. `ContractAutoCheckProcessor` gives in-session `[AUTO-CHECK]` feedback on every authored `processors/*.py`/`tools/*.py` edit.
  - **The concrete seam to drive a rule change**: add a lever value to `journal._VALID_LEVERS`; carry the external signal in via a `rule_signals.json` read-context artifact + `_render_task_brief` deliverable; add a validity-phase check (`EvolveValidator._rules`) that raises `StrictValidationError(kind="rule_change")`; add changeset buckets (`compute_changeset` + `journal._CHANGESET_KEYS_ORDER`); extend `contract_autocheck` to classify rule files. The novelty/evidence/replay/attribution machinery then applies for free.
  - **OUS by comparison**: detection rules in `findings.py` are static and never modified. Calibration (`calibration.py`) only does `calibrated = max(0.1, calibrated - 0.5)` on a *file's* ranking priority (keyed on `tags[0]`, not `rule_id`) plus a prompt-constraint string — it never disables/tightens/adds a rule, has no novelty gate, no attribution. Benchmark misses produce a `BenchmarkCalibrationRecord` whose `next_improvement_candidate` is hard-coded to `"rules_or_language_hunter"` and written to an **inert** `calibration_records.json` that nothing consumes. The recall side is a fully open loop.
- **Implications**: OUS has exactly the *signals* HarnessX needs (verifier rejections = precision side; benchmark misses = recall side) but no loop closing back onto the rules. The meta_harness is the engine that closes it. This motivates Decision D3 (which levers, and their hard bounds) and the §5/§6 design.

### The verycode policy & scoring model
- **Context**: The design needs a central CWE→severity authority and a project score. What does `verycode` actually provide?
- **Sources Consulted**: `/tmp/verycode-policies/{README.md,CWE_Score.tsv}`; `gh repo view norandom/verycode-score` (incl. `action.yaml`, `main.go`); `gh repo view norandom/verycode-lib`; `/home/mc/Source/OpenUltraSAST/src/openultrasast/findings.py`.
- **Findings**:
  - `CWE_Score.tsv` is the real artifact: 167 data rows, one per CWE, columns `Flaw Category | CWE ID | CWE Name | Flaw Severity (0-5) | Static (X/empty) | Dynamic (X/empty)`. Severity distribution: 12×5, 15×4, 97×3, 31×2, 0×1, 12×0. Scope: 154 Static, 45 Dynamic, 13 Dynamic-only, none neither. (Header column 4 is literally `"Flaw Severity "` with a trailing space.)
  - **The scoring algorithm does not exist.** `norandom/verycode-score` is the unmodified `the-gophers/go-action` "Tweeter" template with `// scorer code here` and a `--policy policies/standard.json` flag; `norandom/verycode-lib` is a one-line stub README. The data shape + the "GitHub Advanced Security findings, weighted by CWE severity" descriptions imply a Veracode-style 0-100 pipeline; the design reconstructs the formula and labels it as such.
  - **Real coverage gap**: CWE-120 (Classic Buffer Overflow) is **absent from the TSV**, but 3 high-value C/C++ rules use it (`c-unsafe-copy`, `c-unsafe-memory-copy`, `c-unsafe-scanf`). Unmapped → those rules would contribute 0 to the score. CWE-121 (Stack Buffer Overflow) is present at severity 5 and is the precise classic-overflow CWE.
  - **Severity mismatch**: OUS rule strings disagree with policy (rules label CWE-78/95/134 "high"; policy rates them 5/critical; rules label CWE-94/502 "high"; policy rates them 3/medium). The policy is the authoritative source.
  - The OUS reachability vocabulary is exactly `reachable | inferred-file-surface | unknown` (verified in `findings.py`), which maps cleanly onto a `REACH_MULT = {reachable:1.0, inferred-file-surface:0.6, unknown:0.4}` exploitability multiplier — and that multiplier is the natural FP-calibration knob (lower effective reachability instead of deleting a rule).
- **Implications**: Severity must flow from PolicyStore (`CWE_Score.tsv`), not from the rule. Day-one fixes: remap the 3 CWE-120 rules to CWE-121 (Decision D5); discard rule string-severities (Decision D4). The score is a stdlib-only reconstruction (Decision D8 ships it advisory-first until `K`/`MIN_SCORE` are calibrated).

### Installability & dependency weight
- **Context**: How does an external project depend on HarnessX, and what does it cost a zero-dependency security tool?
- **Sources Consulted**: `/tmp/HarnessX/pyproject.toml`, `harnessx/__init__.py`, `core/builder.py`, `plugins/{base,loader,discovery,convert}.py`, `examples/{coding,research,assistant}/harness.py`, `extensions/plugins/workflow/plugin.py`, `.gitmodules`; `/home/mc/Source/OpenUltraSAST/pyproject.toml`.
- **Findings**:
  - HarnessX is **library-first** and **effectively not on PyPI** (`name="harnessx"`, `version="0.1.0"`, Beta; consumed from Git). `requires-python = ">=3.11"` — exact match with OUS, no floor conflict. Depend via a SHA-pinned Git URL (the version string won't move).
  - Custom stages map cleanly onto HarnessX's plugin model: each SAST stage is a `MultiHookProcessor`; group stages + tools + skills into a `HarnessPlugin` mounted via `builder.plugin(...)`; load in-process (instance/class) rather than via directory/`plugin.json`.
  - **Dependency-weight is the headline risk.** HarnessX's `dependencies` (always-installed, not extras) is ~30 heavyweight packages: `anthropic`/`openai`/`litellm`/`tiktoken`, `fastapi`/`uvicorn`/`websockets`, `playwright` (ships browser binaries), `docker`/`e2b`, `hydra-core`/`omegaconf`/`structlog`/`loguru`, `opentelemetry-*`, `mcp`, `python-pptx`/`python-docx`/`openpyxl`/`reportlab`/`pdfplumber`. **There is no lean extra** — `pip install harnessx` pulls everything. OUS currently has `dependencies = []`.
  - **Mitigating fact**: HarnessX uses **pervasive lazy imports** (heavy modules imported inside functions). So the heavy deps are *installed* but only *imported on demand* — which makes both an optional-extra opt-in and a vendored subset genuinely viable.
  - **Submodule caveat**: `.gitmodules` declares a nested `recipe/verl_harnessX/verl` → a large verl RL fork OUS does not need; never `--recursive` init.
- **Implications**: A hard dependency is off the table (it inverts the zero-dep stance and pins to an unmovable Beta). Options narrow to (B) optional extra and (C) vendored lean subset. The lazy-import architecture is what makes B keep heavy code cold by default and makes C a surgical packaging switch. This is Decision D2.

### Current OUS rule-system problem analysis
- **Context**: Establish, in code terms, why the user's complaint ("rules are too influential and not centrally managed") is true.
- **Sources Consulted**: `/home/mc/Source/OpenUltraSAST/src/openultrasast/{findings,rank,calibration,benchmark,verification,harness,config,cli}.py`.
- **Findings** (six code-level defects):
  1. **Pattern matches dominate output.** In quick mode, every non-comment regex match becomes a finding (`quick_scan_findings`); the only gate is language. Ranking only sorts; verification rejects only on `reachability_status == "unknown"`. A noisy regex sets output volume and FP rate directly — the rule *is* the result.
  2. **Severity is rule-local.** `PatternRule.severity` is a string literal copied straight onto the finding (`_finding_from_match`). Two rules for the same CWE can disagree; nothing reconciles them.
  3. **No central store.** The ruleset is a Python tuple compiled into the package; `config.py` has no rule/policy section. You cannot enable/disable/tune a rule without editing source and cutting a release.
  4. **Calibration demotes ranking, not rules.** `calibrate_ranking` only subtracts `learning.demotion` (default 0.5) from a *file's* `priority`, floored at `MIN_CALIBRATED_PRIORITY = 0.1`, keyed on `tags[0]`. A chronically wrong rule fires at full severity forever; learning targets the wrong object.
  5. **No CWE-policy linkage.** `cwe` is free-text used only for rationale text and loose benchmark matching. No table maps CWE → governed severity/enablement/evidence floor.
  6. **No project-score weighting.** Severity and emission are global constants; the ranking signal (`composite_priority`) only re-sorts. A low-severity crypto finding in a fuzzable network parser is never promoted; a high-severity finding in dead code is never demoted.
- **Implications**: The regex layer is simultaneously **detector, severity authority, and volume knob**, while ranking/verification/calibration/benchmark can only act *around* the rules, never *on* them. The fix is to split those three roles into three owners (rules detect / policy decides severity & scope / score is the optimization target) with a one-directional authority model (governance drives execution; execution emits signals; the loop edits governance under a gate). This is the organizing principle of `design.md`.

## Architecture Pattern Evaluation

These are the three "architect angles" that were considered for the overall shape. Each is internally coherent; the synthesis in `design.md` borrows from all three and resolves their three disagreements (D1/D2/D3).

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| **Incremental seam** | Keep the OUS sync driver; run HarnessX only inside the `hunter_pool` callback via `asyncio.run`. Rules→data + policy + score added around the existing pipeline. Dependency = optional extra (B) with vendored (C) as escape hatch. Loop edits a `"rule"` lever (status/threshold). | Smallest blast radius; confines the async surface to one stage; keeps the recall/FP gate green per-merge; preserves zero-dep default. | Two harness contracts coexist for a while; `HarnessRuntime` lingers; deterministic stages don't gain HarnessX trajectories yet. | Chosen as the base trajectory (Phases 0-4). |
| **Native rewrite** | Delete `HarnessRuntime` entirely; the *whole* scan becomes a single-step HarnessX harness with `skip_model=True` + slot dataflow; vendored lean subset (C) as the committed default. Loop edits a `"rule"` lever; patterns stay human-PR'd. | Cleanest end-state; one runtime, one contract; full trajectory/journal coverage of every stage; smallest auditable dep graph. | Touches every stage at once — too much blast radius to keep the gate green per-merge; vendoring is permanent fork-maintenance burden. | Demoted to optional Phase 5+; its end-state (single-step harness, retire `HarnessRuntime`) is the long-term target. |
| **Policy-first** | The whole scan runs as processors on a fixed loop; central CWE policy is the centerpiece; loop edits `"rule"` + `"policy"` levers (policy = evidence floors/scope, *not* the 0-5 CWE severity). Dependency = optional extra (B) default, vendored (C) fallback. | Strongest governance story; two levers give the loop the right surface to "stop rules being too influential" without inventing detectors or rewriting severity. | Same whole-pipeline-at-once risk as native if taken literally; needs careful bounds so the loop can't corrupt the ruleset. | Contributed the two-lever model (D3) and the bounded-authority safety rules. |

## Design Decisions

The three architect angles agreed on the destination (rules→governed data; severity from a central CWE policy; a gated project score; HarnessX hosting the hunter loop and a rule-adapting self-improvement loop). They disagreed on three load-bearing choices. Each is resolved below with the recall/FP gate as the deciding tie-breaker. (D4-D9 are smaller decisions that follow.)

### Decision D1: Scope of the HarnessX migration
- **Context**: How much of the scan moves onto HarnessX, and how fast?
- **Alternatives Considered**:
  1. Incremental seam — sync driver stays; HarnessX only in the hunter callback.
  2. Native rewrite — delete `HarnessRuntime`; whole scan becomes a single-step harness immediately.
  3. Policy-first whole-loop — whole scan as processors on a fixed loop.
- **Selected Approach**: **Phased.** Adopt HarnessX directly *at the hunter loop* first (Phase 3); migrate deterministic stages onto a single-step harness only later and optionally (Phase 5+), retiring `HarnessRuntime` only after the seam is proven and the gate has held.
- **Rationale**: The sync→async + contract mismatch is the single highest-risk item in the whole effort. The native rewrite touches every stage at once — too much blast radius to keep ≥90% recall / <10% FP green per-merge. The incremental seam ships the *actual* HarnessX value (agent loop, journal, `StatefulTrajectory`) at exactly the one stage that is already an agent loop.
- **Trade-offs**: Two harness contracts coexist through Phases 3-4 and `HarnessRuntime` lingers; in exchange every phase is independently shippable, test-gated, and reversible.
- **Follow-up**: Golden-output diff gate at each phase; confine `asyncio.run` to the hunter callback; `SlotContractMixin` to preserve key-level discipline.

### Decision D2: Dependency strategy
- **Context**: A zero-dependency security tool considering a ~30-package agent runtime with no lean extra.
- **Alternatives Considered**:
  1. (A) Hard dependency in main deps.
  2. (B) Optional extra `openultrasast[harnessx]`, SHA-pinned, lazy-imported.
  3. (C) Vendored lean subset under `src/openultrasast/_vendor/harnessx/`.
- **Selected Approach**: **(B) is the shipping default; (C) is a pre-committed, triggered fallback** gated by an explicit `pip install --dry-run` audit before Phase 3. Core `dependencies = []` stays; all HarnessX imports are lazy behind a `_has_harnessx()` check.
- **Rationale**: HarnessX's pervasive lazy imports mean the heavy deps are *installed* but only *imported on demand*, so a clean opt-in extra already keeps heavy code paths cold in the default install — with the least maintenance burden, while tracking upstream. (A) permanently inverts the project's stance and pins to an unmovable Beta `0.1.0`. (C) adds permanent fork-maintenance and should only be paid for when the *installed* graph (not the *imported* graph) is itself unacceptable.
- **Trade-offs**: With B, enabling the extra still inherits the full HarnessX dep set (no lean upstream extra exists); every HarnessX import must be guarded.
- **Follow-up**: Run the dry-run audit and record the realized transitive graph. **Decision rule**: if it pulls Playwright browser binaries / Docker SDK / a FastAPI web stack as *mandatory* transitive deps and maintainers judge that unacceptable, switch to (C) — vendor `harnessx/{core,plugins,processors,bundles,meta_harness,workspace,tools/base}` + the `llm_judge`/`journal`/`validate_workflow`/`agent`/`contract_autocheck` modules, delete `lab/`/browser/sandbox/office subtrees, re-pin a minimal set. The lazy-import design makes the deletion surgical. Never use the recursive submodule path (`recipe/verl_harnessX/verl`).

### Decision D3: What the self-improvement loop is allowed to edit
- **Context**: The user's core complaint is that rules are "too influential." The loop must be able to *govern* rules without becoming a new way for them to run wild.
- **Alternatives Considered**:
  1. Single `"rule"` lever (status/threshold).
  2. `"rule"` lever; patterns stay human-PR'd (native angle).
  3. `"rule"` + `"policy"` levers, where policy = evidence floors/scope, *not* CWE severity (policy-first angle).
- **Selected Approach**: **Two bounded levers.** `"rule"` = `status` (enabled/shadow/disabled) + evidence-floor + threshold, **never pattern text**. `"policy"` = evidence floor + scope + score constants `K`/`MIN_SCORE`, **never the authoritative 0-5 CWE severity**. Patterns and CWE severities are human-PR-only.
- **Rationale**: This is the precise answer to "stop rules being too influential" — the loop may *suppress / stage / raise-the-bar*, never *invent detectors* or *rewrite the severity authority*. Bounds + mandatory `shadow` staging + auto-revert keep loop authority safe; the meta_harness novelty/evidence/replay/attribution gates apply for free.
- **Trade-offs**: The loop cannot fix a bad pattern itself (it can only `shadow` it and nominate a human PR), and cannot re-weight a CWE — both are deliberate guardrails.
- **Follow-up**: Implement `EvolveValidator._rules`/`._policy` raising `StrictValidationError(kind="rule_change")`; enforce the four "may NOT" bounds (no pattern edits, no 0-5 severity edits, no `enabled→disabled` without `shadow`, no reverted re-proposal without `retry_rationale`).

### Decision D4: Severity authority
- **Context**: Two rules for the same CWE can disagree on severity today.
- **Selected Approach**: PolicyStore (`CWE_Score.tsv`) is authoritative; `resolve_severity(policy, rule.cwe, target, ranking)` replaces the literal `rule.severity` read; `PatternRule.severity` is removed. Policy always wins; rule string-severities are discarded.
- **Rationale**: One CWE = one governed severity, reconciled centrally; ends rule disagreement.
- **Trade-offs**: Loses the per-rule severity hint (acceptable — it was an authoring accident, not a governed decision).

### Decision D5: The CWE-120 coverage gap
- **Context**: 3 C/C++ buffer rules use CWE-120, which is absent from `CWE_Score.tsv`.
- **Selected Approach**: Remap `c-unsafe-copy`/`c-unsafe-memory-copy`/`c-unsafe-scanf` to **CWE-121** (Stack Buffer Overflow, severity 5) in the ruleset TOML.
- **Rationale**: CWE-121 is the precise classic-overflow CWE and is already at severity 5; this avoids forking the upstream policy file. Otherwise those high-value rules contribute 0 to the score.
- **Follow-up**: Add a hard CI invariant — every `enabled` rule's `cwe` must resolve in PolicyStore (fail loud at startup); log `unmapped_cwe` in the score artifact; PR genuine gaps upstream to verycode-policies.

### Decision D6: Response to a confirmed false positive
- **Context**: How does the system react to an FP without hurting recall?
- **Selected Approach**: Lower the finding's effective **reachability multiplier** and/or `shadow` the rule — **never delete it**.
- **Rationale**: The score stops over-penalizing while the rule keeps firing (tracked, just not scored/reported), preserving ≥90% recall and pushing FP <10%. This is exactly the recall/FP balance the project gates on.

### Decision D7: Where OUS's `reads`/`writes` contract lives
- **Context**: HarnessX has no per-key state contract; OUS's defining discipline must survive.
- **Selected Approach**: Reimplement as a `SlotContractMixin` on our `MultiHookProcessor`s (`reads_slots`/`writes_slots` class attrs validated in a base `on_*` wrapper), gated by `OUS_SLOT_CONTRACT=strict|warn`.
- **Rationale**: The two contracts are incompatible; the mixin preserves provenance/audit discipline inside HarnessX's runtime without trying to bend the message-window contract.

### Decision D8: Project-score gate rollout
- **Context**: The verycode score formula is a reconstruction (no upstream implementation).
- **Selected Approach**: Ship the score gate **advisory-first** (computed and reported, not blocking); promote to blocking only after `K`/`MIN_SCORE` are calibrated against the benchmark corpus. Score computation is stdlib-only and always on (zero-dep), so CI gating runs in the default install with no HarnessX present.
- **Rationale**: The formula needs corpus calibration before it can safely block a merge; keeping it zero-dep keeps the CI gate independent of the optional harness.

### Decision D9: RL adoption
- **Context**: HarnessX has an `rl/` subsystem (weight-level improvement) alongside the config-level meta_harness.
- **Selected Approach**: Optional, Phase 5+.
- **Rationale**: Config-level adaptation via the meta_harness is sufficient to close the rule/policy loop; weight-level RL over hunter trajectories is purely additive and not on the critical path.

## Risks & Mitigations
- **Sync↔async + contract incompatibility (High)** — confine the async surface to the hunter stage via `asyncio.run` in its callback (Phase 3); `SlotContractMixin` for key-level discipline; deterministic stages run `skip_model`; golden-output diff gate at each phase.
- **Dependency posture inversion (High)** — governance/scoring planes stay zero-dep; HarnessX strictly behind the extra + lazy imports + pinned SHA; CI zero-dep guard test; `pip --dry-run` audit before Phase 3; vendored-subset fallback pre-specified.
- **Benchmark-gate regression from rule auto-tuning (High)** — the recall/FP gate is the per-round acceptance test (aggregate + per-rule, hard constraint); `shadow` before `disabled`; novelty + attribution block thrash and reverted re-proposals; auto-revert byte-for-byte.
- **Score gaming the gate (High)** — keep the gate as a *hard constraint*, never part of the reward; track unpredicted regressions; add a score-regression check to acceptance.
- **Meta-agent corrupts the ruleset, re-introducing "too influential" (Medium)** — bounded levers (D3): no pattern rewrites, no severity edits, mandatory `shadow` staging, no `enabled→disabled` jump; recall gate auto-reverts; every change journaled and novelty-checked.
- **Policy completeness / CWE drift (Medium)** — day-one CWE-120→CWE-121 remap; hard CI invariant that every enabled rule's CWE resolves; `unmapped_cwe` logged; treat verycode-policies as authoritative-upstream and PR gaps there.
- **Frozen Beta upstream (Medium)** — pin SHA; document in `VENDOR.md`; keep the meta_harness patch minimal/isolated; rule lever degrades gracefully (absent patch = no rule lever, loop still does ranking demotion); vendored subset removes upstream-instability exposure for depended modules.
- **Slot serialization loss on resume (Medium)** — all scan slots use plain dicts/dataclasses with `_target_` registration; per-slot-type round-trip serialization test (non-serializable content restores as `None` on `wake()`).
- **Two-store coordination drift (Low-Med)** — a single `resolve_severity` owns the rule-status + policy-gate combination; the changeset records both lever edits per round; the benchmark regression suite catches interaction regressions.

## References
- HarnessX core — `/tmp/HarnessX/harnessx/core/{harness,builder,processor,events,runloop,state,contract_check,model_config,trajectory}.py` — composition/run-loop/contract/state model.
- HarnessX processors — `/tmp/HarnessX/harnessx/processors/{evaluation/llm_judge.py, evaluation/strategies/evaluators/prm.py, observability/{otel_proc,episode_metrics,checkpoint}.py, memory/memory_retrieval.py, control/loop_detection.py}` — reuse map (verify/calibrate/observability).
- HarnessX meta_harness — `/tmp/HarnessX/harnessx/meta_harness/{agent,journal,replay,validate_workflow}.py`, `processors/contract_autocheck.py`, `workers/trajectory_digester.py`; `rl/{builder,config,task}.py` — self-improvement engine + rule-adaptation seam.
- HarnessX packaging — `/tmp/HarnessX/pyproject.toml`, `harnessx/__init__.py`, `plugins/{base,loader,discovery,convert}.py`, `examples/{coding,research,assistant}/harness.py`, `extensions/plugins/workflow/plugin.py`, `.gitmodules` — installability + dependency weight.
- verycode policy — `/tmp/verycode-policies/{CWE_Score.tsv,README.md}`; `gh repo view norandom/verycode-score` (`action.yaml`, `main.go` placeholder); `gh repo view norandom/verycode-lib` (stub) — policy data (complete) vs scoring algorithm (never implemented).
- OUS current system — `/home/mc/Source/OpenUltraSAST/src/openultrasast/{findings,rank,calibration,benchmark,verification,harness,config,cli}.py` — `PATTERN_RULES`, ranking-only calibration (`MIN_CALIBRATED_PRIORITY=0.1`), inert `next_improvement_candidate`, sync `HarnessRuntime`, no rule/policy config section.
- Companion design — `.kiro/specs/harnessx-self-improving-rulesets/design.md` (committed architecture); detection gate per `MEMORY.md`: ≥90% recall / <10% FP on the benchmark corpus.
