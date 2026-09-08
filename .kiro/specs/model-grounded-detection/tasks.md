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

- [x] 2.1 The CpgBackend seam, out of process
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

- [x] 2.2 The injection taint query and its verdict
  - `cpg/queries/taint.sc` — a CPGQL script parameterised by a `TaintSpec` (sources, sinks, sanitizers) that
    emits, per candidate, the JSON `{sink, source, path, sanitized: bool}`. `model/taint.py::verdict(cpg,
    spec, candidate)` → `ENTAILED` when a source→sink path exists with `sanitized=false`, `CORROBORATED` when
    a path exists but a sanitizer may apply, else `None`. Injection `TaintSpec` from `model/specs.py`.
  - Observable: on a fixture with `os.system(request.args['x'])` the verdict is `ENTAILED`; on the
    parameterised-query fixed twin it is not; the query script is deterministic.
  - _Requirements: 5.1, 5.2, 6.1_
  - _Depends: 2.1, 1.1_

- [x] 2.3 Determinism, and the go/no-go reading
  - `test_two_runs_over_one_cpg_give_an_identical_verdict_sequence`. Run the injection taint verdict over the
    injection slice, regenerate the entailment ceiling for injection, and write the reading into the
    Implementation Notes: does Joern produce a deterministic verdict at acceptable per-target cost and time?
    If not, stop the design here and record why.
  - Observable: the determinism test passes repeatedly; the injection entailment number is committed against
    the 2.2%/multi-hop baseline; the notes state go or no-go.
  - _Requirements: 6.4, 6.5_
  - _Depends: 2.2_

## Group 3 — The ladder and the judge

- [x] 3.1 The evidence ladder as the verdict type
  - `model/ladder.py`: `Rung` enum (suspicion/model_corroborated/model_entailed/execution_confirmed),
    `Verdict` (rung, family, witness, contradiction). Findings carry the rung in markdown, SARIF and JSON.
  - Observable: a finding at each rung round-trips through every output format with its rung intact; nothing
    is reported above `suspicion` without a `Verdict` establishing it.
  - _Requirements: 5.1, 5.3, 5.4_
  - _Depends: 2.3_

- [x] 3.2 The judge: one bounded question, checked against the model
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

- [x] 4.1 Guard dominance for the absence families
  - `cpg/queries/dominance.sc` + `model/dominance.py::verdict(cpg, spec, candidate)` — `ENTAILED` when an
    obligated operation is dominated by no discharger while its siblings are, seeded from the obligation
    facts. This is the arbiter for the classes that never crash (access_control).
  - Observable: on the ThreatByte/VAmPI absence fixtures the vulnerable handler is `ENTAILED` (guard absent)
    and the fixed twin is not; a handler with no obligated operation yields no verdict.
  - _Requirements: 6.2, 7.3_
  - _Depends: 3.2_

- [x] 4.2 The remaining TaintSpecs and the ceiling regeneration
  - Fill `TaintSpec`s for path, deserialization, untrusted_destination, output_encoding, prototype, and the
    config constant-abstraction arm (`model/taint.py`). Regenerate the full entailment ceiling per family and
    per slice and commit it; name where each family falls back to `suspicion`.
  - Observable: the entailment ceiling artifact carries every web/logic family with its entailed/corroborated
    split; the number is higher than the flat-IR 2.2% and the fallbacks are named.
  - _Requirements: 6.3, 6.5, 7.2_
  - _Depends: 4.1_

## Group 5 — Corpus calibration and reporting

- [x] 5.1 The corpus as the model's calibration set
  - `model/calibrate.py` — over the vulnerable-parent/fix pairs, run the model on both sides and record
    whether it distinguishes them; a pair it cannot split is a named model gap (with the reason), not a miss.
    Provide the CVE-history harvest seam (recipe → parent/fix, the fix diff read as oracle).
  - Observable: the calibration report lists model gaps by family with reasons; a pair the model splits is
    recorded as covered; per-slice with the real-world slice deciding.
  - _Requirements: 9.1, 9.2, 9.4, 11.1_
  - _Depends: 4.2_

- [x] 5.2 Reporting: per-slice, overfitting gap, rung
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

## Implementation Notes — group 2 (2026-09-08)

**Verdict: GO.** Joern is installed at `~/joern/joern-cli` (maintainer chose a permanent install). Artifact:
`benchmarks/measurements/2026-09-08-joern-go-no-go.json`.

| | injection slice |
|---|---|
| `model_entailed` on the vulnerable side | **54%** (27/50) — against the flat IR's **2.2%** |
| ... on minimal-fix pairs only | **61.5%** (16/26) |
| pairs distinguished (vuln entailed, fix clean) | 32% overall, **38.5%** on minimal-fix pairs |
| determinism (Req 6.4) | **every verdict identical on re-run** |
| cost | median **32s**/pair, max 58s, 30 min for the slice |
| CPG build failures | 1 (a C translation unit that does not parse standalone) |

**The engine is not the constraint.** Every gap below is in our own data model, which is exactly the result
that justifies adopting a CPG rather than building one. The 23 misses split three ways: 11 sinks not in the
fact tables (Django ORM `objects.raw`, `self.query`, GraphQL resolvers), 11 where the sink is modelled but no
source reaches it, and 1 build failure — counted separately so it can never read as "no vulnerability".

**The finding that changes the design.** Classifying what the 50 injection *fixes* actually do:

    shape introduced at the sink              guard kind of the added lines
      other_or_validation   37                  none                24
      bound_parameters      10                  parameterized_call  11
      argv_list              2                  null_test            7
      sanitizer_call         1                  allowlist_test       5

The dominant injection fix is a **validation guard on the path** — allowlist, type coercion, bounds or null
test — not a sanitizer call and not a sink-shape change. Taint reachability can never separate those pairs:
the flow still reaches the sink; what changed is that a guard now *dominates* the path. So the arbiter is
**taint + dominance**, not taint alone — the same primitive task 4.1 builds for access_control, with the guard
vocabulary ported verbatim in task 1.1 as its lookup list. Two planned mechanisms collapse into one, and
task 4.1 should be built before the remaining `TaintSpec`s rather than after.

**Five bugs the live engine exposed, none visible offline.** Two of them *inverted* a verdict rather than
weakening it, which is why each was fixed as a class:
1. A sink was its own sanitizer — facts carrying a *shape* qualifier (`parameterized`, `literal_format_arg`)
   describe a safe form of the sink call, not a cleansing call. Flattened in, `execute` became both the
   injection sink and its own sanitizer and **nothing could ever be entailed**. Fixing the class immediately
   caught C's entire `printf` family.
2. `labeled_family` had lost its deterministic CWE fallback in group 1 (my error) — the injection slice
   resolved to **zero pairs**. Restored, still with no model call; the census again matches the committed
   ceiling exactly.
3. Taint alone entailed both sides of the canonical SQL pair, so the model arbitrated nothing → the
   safe-shape test, using the `safe_shape_sinks` that bug 1 had preserved.
4. Joern's `call.argument` includes the **receiver**, so a one-argument interpolated call looked like a
   two-argument bound one — the exact inversion of the shape test. Fixed with `argumentIndexGt(0)`.
5. The source model was framework-only, while 39/50 pairs receive untrusted input as a function parameter.
   Parameter sources are now opt-in (right for a function-level pair whose boundary *is* the trust boundary,
   wrong for a whole repository) — and required for the comparison against the flat-IR baseline to be
   like-for-like, since that baseline counted them.

**Corpus caveat, and why the differential is reported per stratum.** Only 26 of 50 injection pairs are genuine
minimal-fix pairs; 12 are *different programs* (`local-python-vulnerable` is 7% similar with 83 changed lines;
`owasp-java-cmdi` pairs `BenchmarkTest00007` against `BenchmarkTest00090`) and 12 are large rewrites. Where
the fixed side is a different program, both sides flagging is a corpus property, not a model failure — a raw
`distinguished_rate` would be measuring corpus quality and reporting it as model quality.

**A correction to a claim made mid-run.** The Flask-shaped source table (no `request.POST`/`request.GET`) is a
real gap but a *minor* lever here: adding Django patterns would gain a source for exactly one pair in this
slice. The larger levers are the missing sinks and guard dominance.

**Next**, in this order: 4.1 guard dominance over the tainted path; 4.2 the missing sinks (Django ORM,
GraphQL, and the four families with no sink fact at all); then the two remaining safe-shape forms, argv-list
and `shell=False`.

## Implementation Notes — group 3 (2026-09-08)

**3.1 — the rung is a new field beside `evidence_level`, not a rename of it.** The existing
`evidence_level` carries `static_corroboration`, emitted by the *flat IR overlay*. Req 4.4 demotes that path
to the suspicion band, so restating its value as `model_corroborated` would claim a CPG arbitrated something
it never saw, while rewriting every legacy finding to `suspicion` would be a product-visible regression
nobody asked for. So `StaticFinding.rung` is added, defaults to `suspicion`, and is raised *only* by
`ladder.at_rung(finding, verdict)` — which is the structural form of Req 5.4. The witness travels with the
rung, because a rung without the evidence that justifies it is just a louder assertion. The rung reaches
markdown, JSON (`asdict`, so automatically) and SARIF. `evidence_level` is now redundant in intent and should
be retired once the model layer covers every path; that is a follow-up, not a silent change.

**3.2 — the judge, and what it does *not* contain.** Three outcomes, exhaustive: the model entails (report it,
**never call the model**), the model contradicts (drop the claim, record why), the model cannot decide (report
`suspicion`, honestly). The LLM is asked exactly one bounded, typed question, with `tools=[]` so it cannot
search for the site, and only about the residual the graph cannot settle — whether a sanitizer on a *real*
flow is sufficient. Its answer can only ever confirm a flow the CPG already found; it can never conjure one.

Req 8.5 is asserted structurally rather than by prose: a test parses `judge.py` and fails if the AST contains
any name like `k_runs`, `majority`, `vote`, `average`, `acceptance`, `floor` or `budget`, or any `for`/`while`
loop at all, or an import from the deleted round machinery. The first draft of that test matched the word
"votes" inside the module's own docstring, which is the reason it now inspects code rather than text — the
docstring is allowed to name the machinery it replaced.

**Verified live against a real CPG**, not only against scripted rows:

    vuln   rung=model_entailed   witness=request.args["name"] -> db.execute("select * from users ...
    fixed  rung=suspicion        contradiction: the model resolved no flow: no source reaches this sink
    model calls made: 0

Both sides arbitrated by the graph with the LLM never consulted — which is the entire point of the arbiter,
and the thing the prior architecture could not do at any price.

678 tests passing, mypy and ruff clean, three gates byte-identical, zero orphaned modules.

## Implementation Notes — group 4 (2026-09-08)

All three arbiter forms now work against a real CPG. Artifact:
`benchmarks/measurements/2026-09-08-model-entailment-ceiling-cpg.json`.

| | full model layer | flat IR baseline |
|---|---|---|
| `model_entailed` | **39.1%** (36/92) | 2.2% |
| any verdict | **45.6%** | 24% (corroborated, one-hop) |
| pairs distinguished | **23.9%** (22/92) | — |

Per family: untrusted_destination 0.80 entailed, injection 0.58 (0.36 distinguished), deserialization 0.33,
prototype 0.14, config_secrets 0.10, path 0.00. **access_control reaches 6 of 8 pairs and 0.38
distinguished** — the class no crash oracle can reach, arbitrated deterministically with no model call.

**4.1: "governed by a guard" is three relations, not one.** Measured against the engine rather than assumed:
an identity constraint lives *inside* the operation's arguments; an identity branch is a denial whose
`controlledBy` condition names the identity (`abort(403).controlledBy == [note.owner_id != current_user.id]`)
— it runs *after* the fetch, so it never dominates the operation but does control whether the value escapes;
only the third shape is plain dominance. That is why the query uses `controlledBy`.

**The bug that mattered most.** My first commit of 4.1 made the absence arbiter *silence its own family*:
`constraint_params` were treated as dischargers, so a field named `user_id` counted as a guard — but
`filter_by(id=user_id)` off the request is what an IDOR *is*. Compounded by substring matching, `user` matched
`users` inside `"SELECT * FROM users WHERE id = ?"`, and every operation in the handler read as guarded. On
`threatbyte-api-v1-delete` the arbiter returned no verdict at all on a textbook IDOR. Both fixed; the family
went from 0 verdicts to 6 of 8, every one distinguished.

**A hypothesis I tested and had to discard.** From the group-2 misses I diagnosed path's 0/8 as a missing
`req.url` source token, and said so. The probe — the same 8 pairs with and without the token — returned
**0/8 → 0/8**. Falsified. The real cause: the sink is lexically inside an anonymous callback, so its
enclosing method is the closure (`<lambda>0`) and the `sinkMethod == function` filter drops it;
`verdict(function="")` on the same CPG returns `model_entailed`.

**And the obvious fix for that is wrong.** Relaxing the filter raises the number with a *false witness*: the
flows found in the closure are `res -> fs.readFileSync(...)` and `this -> ...`, neither of which is the
vulnerability (the real path crosses a helper: `req.url -> url -> resolveUrl(...) -> possibleFilename`).
Turning a miss into a wrong entailment is worse than the miss — it is the arbiter asserting something untrue,
the one failure mode this architecture exists to prevent. The correct fix is two-part: scope a sink to any
method *lexically nested* in the labeled function, and scope parameter sources to the labeled function's own
parameters. Then re-measure, counting only witnesses that name a real source.

**Every miss is classified**, none is architectural: 23 sink absent from the excerpt or unmodelled, 13 no
recognisable source in the excerpt, 3 source unmodelled (the idiom named).

**Two honesty items recorded in the artifact.** 16 of 92 pairs carry no function label and are therefore
arbitrated over the whole file, so a verdict can credit a different finding than the labeled one —
`owasp-python-hash` (CWE-327) is credited for a permissive `set_cookie` elsewhere in its file, on both sides.
And `config_secrets` (1/10) conflates three abstractions: permissive setting *values* (the arm implemented
here), weak *algorithm* choice (CWE-326/327 — the facts already carry `weak_literals` on the hashlib sink,
unwired), and hardcoded secrets (CWE-798, needing a credential-literal check); its settings table is also
Flask/FastAPI-shaped while the pairs are aiohttp. `hutool-cve-2018-17297` has no path spec at all — 4.2
authored path sinks for python and javascript only.

**Next, in evidence order:** the closure-scoping fix (with correct parameter scoping, then re-measure); Java
path sinks; the `weak_literals` arm for config; aiohttp settings.

693 tests passing, mypy and ruff clean, gates byte-identical, zero orphaned modules.

## Implementation Notes — closure scoping + group 5 (2026-09-08)

### The closure-scoping fix (queued by the group-4 evidence, done before group 5)

JavaScript is callback-heavy, so the method containing a sink routinely is not the labeled function; scope is
now decided by **line-range containment** in the same file (`astParentFullName` is empty for lambdas) and
reported as `inLabeledScope`, with the name comparison kept only as a fallback so an engine that cannot report
scope never has its sinks silently treated as scoped. Parameter sources stay bound to the labeled function's
*own* parameters — a callback's `err`/`stats` are not attacker input.

Fixing the scope exposed three more bugs, **each of which would have raised the number while making the
answer untrue**:

1. *Shortest-flow-wins picked the wrong witness.* With closures in scope one sink had flows from `req.url…`
   (10 steps, the vulnerability), `res` (3) and `this` (7). A flow from a modelled source now outranks a
   shorter one from a bare captured name; shortest still breaks ties, so the order stays total.
2. *The JS fact file had no `[[sanitizer]]` entries at all*, so no JavaScript fix of any family could ever be
   recognised.
3. *Adding them regressed the witness*, because `resolveUrl` **contains** `resolve` and the substring test
   marked the vulnerable flow sanitized. This is the same bug class already fixed in `dominance.sc` and not
   carried across — the exact fix-the-instance-miss-the-class failure. `taint.sc` matches on word boundaries
   now.

And the rule the fix turns on: **parameter sources are a fallback, never an override.** When a modelled source
reaches the sink those flows are the evidence; otherwise a captured `res` reaching a *sanitized* sink reports
the fix as still vulnerable on a flow that names no attacker input.

**A correction to the group-4 reading.** `req.url` was *not* a wrong diagnosis — it was untestable in
isolation. The probe returned 0/8 → 0/8 because the scoping bug blocked everything downstream of it. Both
were needed. On the pair that motivated all of it:

    vuln   model_entailed      req.url.split('?')[0] -> readFileSync(possibleFilename)   10 steps
    fixed  model_corroborated  the same flow, sanitized by path.normalize                22 steps
    distinguished: true

### Group 5

**5.1 inverts what the corpus is for.** A pair the model cannot split is a *named gap in the model*, not a
detector miss to average: the arbiter is deterministic, so it fails that pair identically every time and only
better modelling moves it. Every gap carries a reason even when the caller supplies none, because a bare gap
teaches nothing. `covered` means a strictly higher rung on the vulnerable side than on its fix — flagging both
sides equally is not coverage, which is precisely what group 2 measured taint reachability doing on every
parameterised SQL pair. The harvest seam derives the vulnerable side as the fix commit's parent, with the fix
diff as the oracle; nothing is hand-labelled.

**5.2 keeps three disciplines from the deleted publish layer**, each because its absence caused a real error
here: per-slice rows always (`render` *raises* without them — a mixed headline once hid agent-written code at
44% against the development slice's 83%); the overfitting gap beside the headline and **absent rather than
zero** when a slice is missing (reading an unmeasured slice as "no overfitting" is the flattering failure);
and the rung on every finding.

Run against the committed artifact the report says things worth not hiding: **agent-vfc 0/28 covered**,
vibe-py 40% against vfc-js 24%, **overfitting gap +16%**, and `untrusted_destination` at 80% entailed but
4 of 5 entailing on *both* sides — which the coverage metric correctly scores as zero.

These are the **pre-closure-fix** numbers. A full re-measure is in flight and the calibration report will be
regenerated from it.

713 tests passing, mypy and ruff clean, gates byte-identical, zero orphaned modules.
