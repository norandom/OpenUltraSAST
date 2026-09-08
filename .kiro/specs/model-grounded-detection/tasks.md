# Implementation Plan: model-grounded-detection

## Guidance for the implementing agent

Read this before starting. It exists so you never have to reverse-engineer a decision this spec already made.

- **The failure mode to avoid.** The prior work logged eighteen defects, three of them the same shape: a fix
  applied to one instance while the *class* of the bug stayed. When you fix a retry, a key, an error path —
  ask "where else is this shape?" and fix all of them in the one change. That single discipline prevents most
  of the escalations that happened here.
- **The gate baseline is sacred and is your safety net.** `benchmarks/measurements/2026-09-06-gate-baseline.txt`
  holds the byte-exact output of `python -m openultrasast.{gate,map_gate,pair_gate}`. Run all three before and
  after any change and diff against it. If a gate moves, you changed something that was never supposed to
  change — stop and find it. The whole `learning/` package is **absent from the gate path** (the gates import
  only `pairs`, `benchmark`, `findings`, `mapping`, `preprocess`, `rank`, `complexity.map`), so its deletion
  *cannot* move a gate; a moved gate means you touched a retained path by mistake.
- **RED first, always.** Write the failing test, watch it fail for the right reason, then implement. One
  commit per task with selective `git add`. Push when a group's independent review passes.
- **Zero-dependency core.** `pyproject.toml` `dependencies = []` never changes. Joern, the LLM endpoint and the
  execution tier are capability-detected, never imported at module load. Copy the exact pattern in
  `semantic/extra.py::has_semantic_extra` and `sandbox/probe.py::resolve_sandbox_probe` — probe, don't import.
- **Redaction on every prompt and persisted artifact** (`redaction.redact_secrets`). Non-negotiable.
- **Two phases can end the design cheaply.** Phase 1 (subtraction) is reversible via git and gate-protected.
  Phase 2 (the Joern spike) is a go/no-go: if Joern cannot produce a deterministic verdict on the injection
  family at acceptable cost, the design stops there, exactly as the candidate ceiling could have stopped the
  prior spec. Do not build groups 3–6 until phase 2 is green.

### The coupling map (for the subtraction, group 1)

These are every touchpoint of the code being removed. Handle all of them in group 1; do not discover them by
running into import errors.

- **`learning/` package** — imported by: `cli.py` (the `learning` subcommand group + `_run_family_detectors`
  + `_learning*` helpers + `from .learning.families import FamilyTaxonomy` + `from .learning.proposer import
  Proposer`), `pairs.py` (the hunter-scoring path — `_evaluate_hunter_pair`, `_family_metrics`, `_hunter_outcome`,
  `build_pair_signals`, function-local imports of `learning.{families,scoring,classify,rounds}` at lines
  ~519, 1151, 1166, 1184), `semantic/seed.py` and `semantic/loo.py` (the teacher-rule import from
  `learning.split`), and `learning/endpoint.py` (retained — re-homed, not deleted).
- **Mechanism/evolve loop** — `improve/evolve.py`, `improve/validator.py`, `semantic/mechanisms.py`,
  `semantic/variants.py`, `semantic/variant_search.py`, `semantic/prove_budget.py`, `semantic/loo.py`,
  `semantic/seed.py`, and `semantic/__init__.py` (re-exports). `cli.py` has the `--mechanism-candidates`
  surface and `_mechanisms_export`.
- **`config.py`** — `LearningConfig`, `_load_learning`, and the `learning` field on `ResolvedConfig`.
- **`reports.py`** — the `learning=` keyword on the report writers and `_append_learning`; the SARIF
  `family`/`detector`/`verifier` properties (keep `family`, drop `detector`/`verifier`).
- **`pairs.py` is gate-load-bearing** via `pair_gate` (the overlay/inventory path,
  `_evaluate_overlay_pair`/`_evaluate_inventory_pair`). The *hunter-scoring* path is the learning coupling and
  is **not** on the gate path. Remove the hunter path and its learning imports; keep the overlay/inventory
  path untouched; confirm `pair_gate` byte-identical.

### What is retained and re-homed (do not delete)

`learning/families.py` → `model/taxonomy.py`; `learning/candidates.py` → `model/candidates.py`;
`learning/endpoint.py` → `model/endpoint.py`. `semantic/obligations/` stays (its facts feed the dominance
queries in group 4). The gates, `redaction.py`, `pairs.py` overlay/inventory path — unchanged.

---

## Group 1 — Subtract and audit (gate-protected, no Joern yet)

- [x] 1.1 Port the security vocabularies out before deleting their modules
  - Create `src/openultrasast/model/specs.py` and move into it, as data, the knowledge the deleted modules
    carry: `_GUARD_PATTERNS` and the guard-kind vocabulary from `semantic/variants.py`; the sink token tables
    (from `benchmarks/pairs/catalog_gen.py::_SINK_TOKENS` and `semantic/facts.py` SinkFacts) as the seed
    `TaintSpec` source/sink/sanitizer lists per family; a reference to the obligation facts
    (`semantic/obligations/facts.py`) for the `DominanceSpec` operations/dischargers. This is data movement,
    not logic — the CPG queries that consume it come in groups 2 and 4.
  - Observable: `model/specs.py` imports nothing from `learning/`, `improve/`, `semantic/variants`,
    `semantic/mechanisms`; a test asserts every family in the taxonomy has a `TaintSpec` or a `DominanceSpec`
    seed, and that the guard vocabulary is preserved verbatim. `model/specs.py` is read-only data — no LLM and no future optimiser writes it, and a test asserts the module exposes no writer (Req 7.4, the verifier boundary).
  - _Requirements: 1.2, 7.1, 7.2, 7.3, 7.4_

- [x] 1.2 Re-home the three retained modules
  - Move `learning/families.py` → `model/taxonomy.py`, `learning/candidates.py` → `model/candidates.py`,
    `learning/endpoint.py` → `model/endpoint.py`. Update their imports and every importer. `candidates.py`
    keeps its behaviour exactly (it is the suspicion-band feeder, Req 8.4) — its tests move with it and stay
    green.
  - Observable: the moved modules import no other `learning/` module; `test_candidate_enumeration.py` passes
    unchanged against the new path; the taxonomy loads and every family resolves.
  - _Requirements: 4.4, 7.1_
  - _Depends: 1.1_

- [x] 1.3 Detach the retained paths from the removed code
  - `pairs.py`: remove the hunter-scoring path (`_evaluate_hunter_pair`, `_hunter_outcome`, `_family_metrics`,
    `PairEvalResult.per_family`, `build_pair_signals` split arg, the `k_runs`/`hunter` plumbing) and its
    `learning.*` imports; keep `_evaluate_overlay_pair`/`_evaluate_inventory_pair` and the `context_files`
    machinery. `cli.py`: remove the `learning` subcommand group, `_run_family_detectors`, the `_learning*`
    helpers, the `--mechanism-candidates` surface and `_mechanisms_export`; keep `scan`, `benchmark`,
    `improve` (rule-status only), `pairs` (overlay), `mcp`/`index` for now (audited in 1.6). `config.py`:
    remove `LearningConfig`/`_load_learning`. `reports.py`: drop the `learning=` kwarg, `_append_learning`,
    and the SARIF `detector`/`verifier` properties (keep `family`). `semantic/{seed,loo}.py`: remove the
    teacher-rule import from `learning.split`.
  - Observable: `python -m compileall src` clean; the three gates byte-identical to the baseline; the full
    suite still collects (failures expected only in tests that pin removed behaviour, addressed in 1.5).
  - _Requirements: 1.3, 1.4, 11.2_
  - _Depends: 1.2_

- [x] 1.4 Remove the noise architecture and the mechanism/evolve loop
  - Delete `learning/{rounds,acceptance,proposer,journal,canaries,verifiers,difficulty,scoring,classify,
    detectors,split,publish,slices,predicates,judgments}.py` (everything under `learning/` except the three
    modules re-homed in 1.2, which are already gone from the directory), then remove the now-empty `learning/`
    package. Delete `improve/evolve.py`, `improve/validator.py` (mechanism parts — keep rule-status validation
    if `improve` is retained by the 1.6 audit), `semantic/{mechanisms,variants,variant_search,prove_budget,
    loo,seed}.py`, and their re-exports in `semantic/__init__.py`.
  - Guardrail: run this **after** 1.1–1.3, so every vocabulary is ported and every importer detached. If a
    delete breaks an import, the fix is in the importer (a 1.3 miss), never a re-addition of the module.
  - Observable: an import-graph check (a test that walks `ast` over every `src/**/*.py` and asserts no import
    names a removed module) passes; `compileall` clean; three gates byte-identical; the extra-free matrix and
    the full matrix both collect.
  - _Requirements: 1.1, 1.2, 1.2b, 1.3, 1.4_
  - _Depends: 1.3_

- [x] 1.5 Reduce the test suite to surviving behaviour
  - For every deleted module, delete the test files that existed only to pin it (`test_learning_*`,
    `test_mechanism_*`, `test_obligation_*` only where it tested the lever not the checker, `test_pair_*`
    hunter-scoring cases, etc.) in this same change. For every surviving test, confirm it maps to a surviving
    requirement of this spec or a still-shipping feature; delete any that map to nothing, and delete outright
    any test that asserts a shape "does nothing", greps `--help`, or passes with its capability absent.
  - Observable: the suite is smaller than 832 tests; a one-line-per-cluster note records the before/after
    count and the requirement each removed cluster served; the pinned floor (gate-baseline, redaction,
    per-slice honesty, `test_candidate_enumeration`) is green.
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_
  - _Depends: 1.4_

- [x] 1.6 The module audit manifest
  - Add `model/audit.py` that classifies every `src/**/*.py` as `load_bearing` (reachable from a gate, the
    scan CLI, or a surviving requirement), `standalone_capability` (its own CLI/users — e.g. `mcp.py`,
    `skills.py`), or `orphaned` (no importer, no entry, no requirement). Remove the orphans. Give
    `fusion.py`, `mcp.py`, `skills.py`, `harness_ext.py`, `hunter_harness.py` an explicit keep-or-remove line
    each with its reason. Commit `benchmarks/measurements/2026-09-08-module-audit.json`.
  - Observable: the manifest classifies every module; a test asserts no module classified `orphaned` remains
    in the tree; the five named subsystems each have a recorded decision.
  - _Requirements: 1.5, 3.1, 3.2, 3.3, 3.4_
  - _Depends: 1.5_

## Group 2 — The Joern spike on one family (go/no-go)

- [ ] 2.1 The CpgBackend seam, out of process
  - `src/openultrasast/cpg/capability.py::has_cpg()` — Joern on PATH (probe `joern-parse --help`), the
    `has_semantic_extra` pattern exactly. `cpg/backend.py`: `CpgResult` (a built `cpg.bin` path + a `run(query,
    params)->JSON` callable); `JoernBackend` (subprocess: `joern-parse <root>` then `joern --script
    cpg/queries/<name>.sc`, parsing stdout JSON, every step timeout-bounded, fail-closed to `None`);
    `NullBackend` (`available()` False, `build()` None); `resolve_cpg_backend()`. **Never import a JVM
    binding; the subprocess is the only Joern touch-point in the codebase.**
  - Observable: with Joern absent, `resolve_cpg_backend()` is the `NullBackend` and `build()` returns None; a
    scripted fake backend (canned JSON) exercises the parsing without Joern; the seam has no import of any
    non-stdlib module at load time.
  - _Requirements: 4.1, 4.2, 4.3, 4.5, 11.3_
  - _Depends: 1.6_

- [ ] 2.2 The injection taint query and its verdict
  - `cpg/queries/taint.sc` — a CPGQL script parameterised by a `TaintSpec` (sources, sinks, sanitizers) that
    emits, per candidate, the JSON `{sink, source, path, sanitized: bool}`. `model/taint.py::verdict(cpg,
    spec, candidate)` → `ENTAILED` when a source→sink path exists with `sanitized=false`, `CORROBORATED` when
    a path exists but a sanitizer may apply, else `None`. Injection `TaintSpec` from `model/specs.py`.
  - Observable: on a fixture with `os.system(request.args['x'])` the verdict is `ENTAILED`; on the
    parameterised-query fixed twin it is not; the query script is deterministic.
  - _Requirements: 5.1, 5.2, 6.1_
  - _Depends: 2.1, 1.1_

- [ ] 2.3 Determinism, and the go/no-go reading
  - `test_two_runs_over_one_cpg_give_an_identical_verdict_sequence`. Run the injection taint verdict over the
    injection slice, regenerate the entailment ceiling for injection, and write the reading into the
    Implementation Notes: does Joern produce a deterministic verdict at acceptable per-target cost and time?
    If not, stop the design here and record why.
  - Observable: the determinism test passes repeatedly; the injection entailment number is committed against
    the 2.2%/multi-hop baseline; the notes state go or no-go.
  - _Requirements: 6.4, 6.5_
  - _Depends: 2.2_

## Group 3 — The ladder and the judge

- [ ] 3.1 The evidence ladder as the verdict type
  - `model/ladder.py`: `Rung` enum (suspicion/model_corroborated/model_entailed/execution_confirmed),
    `Verdict` (rung, family, witness, contradiction). Findings carry the rung in markdown, SARIF and JSON.
  - Observable: a finding at each rung round-trips through every output format with its rung intact; nothing
    is reported above `suspicion` without a `Verdict` establishing it.
  - _Requirements: 5.1, 5.3, 5.4_
  - _Depends: 2.3_

- [ ] 3.2 The judge: one bounded question, checked against the model
  - `model/judge.py::judge(candidate, cpg, spec, *, client, model)` — if the model entails, report
    `model_entailed` with no LLM call; else ask the LLM one typed question (source expression / guard / family)
    with no tools; then check the answer against the CPG — contradiction drops the claim (records why),
    corroboration advances to `model_corroborated`, neither leaves `suspicion`. Reuse `model/endpoint.py`.
  - Observable: an entailed candidate makes zero LLM calls; a claim the CPG contradicts is dropped with the
    contradiction recorded; a claim the CPG supports advances; there is no rounds/acceptance/floor/evolve code
    left to import.
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 11.4_
  - _Depends: 3.1_

## Group 4 — Absence and the rest of the taxonomy

- [ ] 4.1 Guard dominance for the absence families
  - `cpg/queries/dominance.sc` + `model/dominance.py::verdict(cpg, spec, candidate)` — `ENTAILED` when an
    obligated operation is dominated by no discharger while its siblings are, seeded from the obligation
    facts. This is the arbiter for the classes that never crash (access_control).
  - Observable: on the ThreatByte/VAmPI absence fixtures the vulnerable handler is `ENTAILED` (guard absent)
    and the fixed twin is not; a handler with no obligated operation yields no verdict.
  - _Requirements: 6.2, 7.3_
  - _Depends: 3.2_

- [ ] 4.2 The remaining TaintSpecs and the ceiling regeneration
  - Fill `TaintSpec`s for path, deserialization, untrusted_destination, output_encoding, prototype, and the
    config constant-abstraction arm (`model/taint.py`). Regenerate the full entailment ceiling per family and
    per slice and commit it; name where each family falls back to `suspicion`.
  - Observable: the entailment ceiling artifact carries every web/logic family with its entailed/corroborated
    split; the number is higher than the flat-IR 2.2% and the fallbacks are named.
  - _Requirements: 6.3, 6.5, 7.2_
  - _Depends: 4.1_

## Group 5 — Corpus calibration and reporting

- [ ] 5.1 The corpus as the model's calibration set
  - `model/calibrate.py` — over the vulnerable-parent/fix pairs, run the model on both sides and record
    whether it distinguishes them; a pair it cannot split is a named model gap (with the reason), not a miss.
    Provide the CVE-history harvest seam (recipe → parent/fix, the fix diff read as oracle).
  - Observable: the calibration report lists model gaps by family with reasons; a pair the model splits is
    recorded as covered; per-slice with the real-world slice deciding.
  - _Requirements: 9.1, 9.2, 9.4, 11.1_
  - _Depends: 4.2_

- [ ] 5.2 Reporting: per-slice, overfitting gap, rung
  - `model/report.py` — per-slice numbers, the overfitting gap beside every headline, the evidence rung on
    every finding; no cross-slice aggregate without its per-slice rows. Re-home the surviving per-slice
    honesty discipline (it was in the deleted `scoring`/`publish`).
  - Observable: the report carries a row per slice and refuses a bare aggregate; the overfitting gap is
    published; every finding shows its rung.
  - _Requirements: 9.3, 11.1_
  - _Depends: 5.1_

## Group 6 — The execution tier stub (deferred)

- [ ] 6.1 The execution_confirmed rung and the Clearwing adoption seam
  - Wire `Rung.execution_confirmed` as an optional escalation reached only where the model cannot decide
    (memory/C first), behind a capability probe for the Clearwing fork. Do **not** reimplement any sandbox
    machinery; the seam calls the adopted tool. Not required for any web/logic class at v1.
  - Observable: a memory-family finding the model leaves at `suspicion` is the only kind eligible for the
    execution tier; with Clearwing absent the rung is simply never reached and a reason is recorded; no
    web/logic path depends on it.
  - _Requirements: 10.1, 10.2, 10.3_
  - _Depends: 5.2_

## Task-plan review notes

- Group 1 is the largest and the only one with no new capability — it is pure subtraction, ~5,000 lines
  removed, gate-protected at every step. It must land and pass an independent review before group 2 begins.
- Group 2 is a go/no-go. If task 2.3 reads no-go on Joern, groups 3–6 do not start; the model layer either
  finds another CPG engine or the design returns to the maintainer. Building past a red 2.3 is the exact
  mistake this whole spec was written to stop.
- `(P)` parallelism is deliberately absent: the subtraction is sequential by dependency, and the Joern spike
  gates everything after it. Do not fan out.

## Implementation Notes — group 1 (2026-09-08)

Landed as one change. Gate baseline captured before the first edit and re-checked after every step; the three
gates are **byte-identical to `2026-09-06-gate-baseline.txt`** at the end, as Req 1.4 and 11.2 require.

**What the subtraction cost and bought.** 99 source modules -> 81; 832 tests -> 646 (642 passing, 4 skipped);
the whole `learning/` package (16 modules, ~4,100 lines) plus six `semantic/` modules removed. mypy clean over
82 files, ruff clean, core `dependencies = []` untouched.

**Sequence that made it safe.** Vocabularies ported first (1.1), importers detached second (1.2-1.3), deletion
third (1.4). Every import break during 1.4 was therefore a detachment miss in the importer, fixed there — no
module was ever restored to satisfy one. Two such misses appeared, both handled as a class rather than an
instance: `semantic/obligations/{operations,shapes}.py` both imported `trailing_name` from the deleted
`variants.py`, so the helper was re-homed to `semantic/ir.py` (its natural place — it is a pure helper over
`CallSite.name`) and both importers updated in the same edit.

**Deviations from the design, each recorded with its reason.**

1. *`improve/evolve.py` and `improve/validator.py` were stripped, not deleted.* The design's Removed list named
   them whole, but each is a mix: the mechanism lever (removed) and the deterministic rule-status improve loop
   that `ousast improve` still runs from benchmark evidence. That loop has no LLM in it, predates the noise
   architecture, and is not what this feature supersedes; deleting the files would have taken a retained
   capability with them. `test_subtraction_complete` now asserts the lever's absence **by symbol**, so it
   cannot creep back.
2. *The `learning` CLI group became `model candidates`.* Deleting the group outright would have orphaned
   `model/candidates.py` — the retained suspicion-band enumerator — by removing its only entry point, and
   Req 3 would then have flagged it for deletion. The offline ceiling report survives as `ousast model
   candidates`.
3. *`thinking` moved from `[learning]` to `[models]`.* It is a model setting, and `LearningConfig` was removed;
   its coverage moved to `test_model_endpoint` rather than being dropped.
4. *Three helpers were re-homed rather than lost:* `Region` (promoted from `_Region`, since the detector module
   that owned the type is gone), `labeled_family` and `labeled_spans` (from the deleted `rounds`/`scoring`).
   `labeled_family` no longer falls back to the LLM classifier — an unlabeled pair is honestly `unknown`, the
   same discipline the evidence ladder applies to a claim the model cannot arbitrate.

**A measured gap, named rather than papered over (Req 9.2).** Task 1.1's observable asked that every family
have a `TaintSpec` or `DominanceSpec` seed. It cannot today: the retained sink facts have **no sink whose CWE
routes to `path`, `output_encoding`, `untrusted_destination` or `prototype`** — the same hole the entailment
ceiling diagnosed ("closed literal sink table: misses per-family sinks"). Rather than weaken the test, it now
asserts the seeded set *and* the gap set exactly, so neither can change silently, and task 4.2 must update it
when it authors those sinks.

**Test reduction (Req 2), by cluster.** 34 files deleted whole: 21 `test_learning_*` (rounds, acceptance,
scoring, classify, detectors, proposer, journal, canaries, verifiers, publish, split, cli, scan, pairs_path,
cutoff, reliability, aggregation, classifier_report, pairs_evidence, round evidence x2, thinking), 4
`test_mechanism_*`, `test_variants`, `test_variant_search`, `test_loo`, `test_obligation_export`,
`test_mechanism_reports`, `test_fixture_difficulty`. Partial trims where a file mixed retained and removed
behaviour: `test_semantic_pipeline` (3 mechanism tests of 12), `test_degradation_matrix` (3 rows for removed
capabilities), `test_pair_corpus` (the hunter scorer), `test_obligation_check` (the `known_fix` assertion,
which depended on the deleted store — the id contract, suspicion rung and tags it also covered are kept),
`test_index` (the bakeoff test). Two files re-homed with their subject: `test_learning_families` ->
`test_model_taxonomy`, `test_learning_endpoint` -> `test_model_endpoint`.

**The audit (Req 3) found exactly one genuine orphan:** `vectorstore.py`, a store bakeoff harness with no
production caller and no CLI entry, alive only through its own test — removed with it. The five named
subsystems each carry a decision: `mcp`, `skills`, `fusion`, `harness_ext`, `hunter_harness` are all
`standalone_capability` (own entry point or protocol), joined by `stage_processors` and `slot_contract`, which
the zero-dependency guard in `test_gate` pins. Manifest committed at
`benchmarks/measurements/2026-09-08-module-audit.json`; a test asserts the tree still matches it.

Group 2 (the Joern go/no-go) has not started. `semantic/engines.py` already exposes `joern_available`, which
the `CpgBackend` capability probe in task 2.1 should build on rather than duplicate.
