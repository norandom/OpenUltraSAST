# Research Log: detection-core

## Gap analysis (2026-10-30)

### Current-state inventory (from codebase exploration)

The security trace already exists for one family (access_control) in the prover:
`Trace`/`PathRecord`/`ProverResult` (`src/openultrasast/hunt/prover.py`,
`semantic/obligations/trace.py`), three-way judgment (`PairJudgment`,
`semantic/obligations/judgment.py`), coverage counters (`Coverage`, `stage_funnel`,
resolution buckets in `semantic/obligations/resolution.py`), digest stamping
(`benchmarks/valid/run_manifests.py` `AnalyzerBundle`, `_input_digest`/`_population_digest`
in `arm_regression.py`), and the admission workflow (`benchmarks/valid/prover_admission.py`,
`admission_scoring.py`, `admission_run.py`).

### Requirement-to-asset map

| Req | Existing asset | Status |
|---|---|---|
| 1 trace object | `Trace`/`ProverResult` in prover | Exists, access_control-only; needs family-agnostic core contract |
| 2 three-way judgment | `PairJudgment`, `judgment.py` | Exists; promote to core vocabulary |
| 3 coverage accounting | `Coverage`, `stage_funnel`, resolution buckets | Exists; zero-byte refusal lives only in runners |
| 4 measured budget | static `BUDGET_SECONDS = 120.0` in runners; per-change `seconds` recorded | **Gap**: budget is a constant; complexity features not recorded; no per-class derivation. Evidence: dev pool 20/483 overruns (max 240s) vs pilot max 7.7s |
| 5 verdict contract | findings carry witness; indeterminate handling in prover | Exists; needs core-level contract (proven vs bounded silence) |
| 6 digests/provenance | `AnalyzerBundle`, input/population digests | Exists; stamping rule must become core-level |
| 7 admission gate | `prover_admission.py`/`admission_scoring.py`/`admission_run.py` | Exists for one arm; needs family-agnostic generalization |
| 8 no fitting on labels | steering rule only (detection-quality.md) | **Gap**: no reversed-pair probe harness exists |
| 9 bounded model role | zero-shot judge measured 2026-10-28 (nearly inert, safe) | Policy; core must state the boundary contract |
| 10 fact packs | `ruleset/obligations/*.toml`, `fact_init.py` | Exists per language; needs family-pack admission + scope tagging |
| 11 consumer contract | each runner has its own envelope (`prover_arm.run/summarize`, push.admission.defects) | **Gap**: no shared core interface |
| 12 measurement schema | `score.rate`, `summarize_*` | Partial; vocabulary/digest fields not unified |

### Implementation approach options

- **A. Extend in place**: grow the prover modules into the core. Minimal new files, but
  bloats family-specific code and keeps the "one arm = one contract" problem.
- **B. New core module, prover reimplemented**: clean contract, but discards measured,
  reviewer-approved code (risk of regression in the 34.8%-recall strict lane).
- **C. Hybrid (recommended)**: new thin core-contract package that the prover's existing
  types implement, and the runners consume incrementally. Contract extracted, behavior
  preserved; migration is per-consumer, each step reviewable.

### Effort / risk
- Effort: M-L (contract extraction across ~6 runner modules plus core package).
- Risk: Medium — contract extraction touches measured code paths; mitigated by keeping
  existing behavior byte-identical per consumer during migration and re-running the
  admission suite as the regression gate.

### Research needed (carried to design)
- Measured-budget model: which complexity features predict reply time on the two pools
  (dev 483 changes with seconds; pilot 264). Carry the 13.3/13.4 record sets as the fitting
  data — measurement only, never training a detector on them.
- Reversed-pair probe harness for Req 8: fix/reversed-fix pairs exist in the pools.
