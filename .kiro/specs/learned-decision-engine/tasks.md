# Implementation Plan

Order follows the design's commit sequence. Every task is a commit gated on the full suite's own exit code,
`ruff check`, `ruff format --check` and `mypy`. No reported number changes until task 9 adopts a model; without an
adopted model every path is today's. Tasks 5, 7 and 10 spend model money or host hours: each starts only after
the maintainer confirms its budget.

- [ ] 1. Schema and features
  - `learn/schema.py` (closed, typed allow-list; no identities; missing != zero), `learn/features.py` (host
    builder), new memory `KINDS`, `plane/tasks/features.py` and the `remember` input; tests enforcing the
    allow-list and the exclusion of label-carrying fields.
  - _Requirements: 1.1, 1.2, 1.3, 7.2_

- [ ] 2. Framework tags
  - `ruleset/frameworks.toml`; tag and split every framework/library entry listed in design section 2; `priors=`
    in the semantic and quick loaders (default `all`, so today's scan is unchanged -- the golden benchmark test
    stays byte-identical); a lint test that no untagged framework entry remains.
  - _Requirements: 8.2, 8.4_

- [ ] 3. Role inference
  - `learn/roles.py` (deterministic wrapper inference), `plane/tasks/roles.py` (model roles, the `model_sinks.py`
    approach), the vocabulary overlay for the engine; fixture tests with no model calls.
  - _Requirements: 8.1_

- [ ] 4. Labels
  - `learn/sources.toml` (fail-closed allowed sources, v3 excluded unread), `learn/labels.py`, `ousast learn
    labels`, repository-group normalisation and CVE merge, the `assumed_benign` source mined from non-security
    commits (separate, never merged); a first label snapshot committed as counts only.
  - _Requirements: 2.1, 2.2, 2.3, 7.1_

- [ ] 5. Harvest (needs budget go-ahead)
  - A plane Run of verify a/b on the verify-family pairs and development cases (~$6, ceiling $10), model roles on
    the candidate files (ceiling $10), engine features for the pair corpus on the host (frozen source, one
    container at a time, background).
  - _Requirements: 1.1_

- [ ] 6. Train, calibrate, evaluate
  - `learn/{folds,train,calibrate,evaluate}.py` (repository-grouped, leave-one-source-out, leave-one-framework-out,
    nested tuning), the model blob API in `plane/memory.py`, `ousast learn train|evaluate|curve`, the first
    evaluation report with priors off under `benchmarks/measurements/<date>-decision-engine-v1/`.
  - _Requirements: 3.1-3.5, 5.1, 5.2, 7.3, 7.4, 8.3_

- [ ] 7. Experiments (exp-001 needs budget go-ahead)
  - `learn/experiments.py`, `register`, `experiment-outcome`, Run annotation checks, `OUSAST_VERIFY_CALLERS`;
    exp-001 (known-callers line on/off, ~$7.7 expected, ceiling $15) registered, run and recorded -- an
    inconclusive result is pre-registered as likely.
  - _Requirements: 4.1-4.4_

- [ ] 8. Integration
  - The `decide` task, the `scan` decision stage and `dropped_by_engine.json`, `pre-push` admission with the engine
    (structural admission reasons unchanged), report fields, the fallback line, the opt-in adaptation layer.
  - _Requirements: 6.1-6.3, 7.3, 7.5_

- [ ] 9. Adopt
  - `ousast learn adopt`, packaged models for the families that pass, the priors-on/off experiment per framework
    with a recorded decision.
  - _Requirements: 3.2, 8.2_

- [ ] 10. The one-time v3 check
  - Commit `prediction-v3.json` first; then v3 is run under protocol v3 and `result-v3-engine.json` is committed.
    Nothing between the two commits may touch the engine, features, priors or thresholds.
  - _Requirements: 5.3_
