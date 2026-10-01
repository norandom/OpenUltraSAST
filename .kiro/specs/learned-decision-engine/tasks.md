# Implementation Plan

Order follows the design's commit sequence. Every task is a commit gated on the full suite's own exit code,
`ruff check`, `ruff format --check` and `mypy`. No reported number changes until task 9 adopts a compiled program;
without an adopted program every path is today's. Requirement 3 changed on 2026-10-01 (an AI classifier with local
memory, compiled DSPy-style in-house); tasks 1-5 are unaffected, tasks 6-10 are re-planned for it. Sub-tasks marked
**(budget go-ahead)** spend model money or host hours: each starts only after the maintainer confirms its budget
against the provider balance read just before it, and none starts with a ceiling above that balance. No test makes
a model or embedding call.

- [x] 1. Schema and features
  - `learn/schema.py` (closed, typed allow-list; no identities; missing != zero), `learn/features.py` (host
    builder), new memory `KINDS`, `plane/tasks/features.py` and the `remember` input; tests enforcing the
    allow-list and the exclusion of label-carrying fields.
  - _Requirements: 1.1, 1.2, 1.3, 7.2_

- [x] 2. Framework tags
  - `ruleset/frameworks.toml`; tag and split every framework/library entry listed in design section 2; `priors=`
    in the semantic and quick loaders (default `all`, so today's scan is unchanged -- the golden benchmark test
    stays byte-identical); a lint test that no untagged framework entry remains.
  - _Requirements: 8.2, 8.4_

- [x] 3. Role inference
  - `learn/roles.py` (deterministic wrapper inference), `plane/tasks/roles.py` (model roles, the `model_sinks.py`
    approach), the vocabulary overlay for the engine; fixture tests with no model calls.
  - _Requirements: 8.1_

- [x] 4. Labels
  - `learn/sources.toml` (fail-closed allowed sources, v3 excluded unread), `learn/labels.py`, `ousast learn
    labels`, repository-group normalisation and CVE merge, the `assumed_benign` source mined from non-security
    commits (separate, never merged); a first label snapshot committed as counts only.
  - _Requirements: 2.1, 2.2, 2.3, 7.1_

- [ ] 5. Harvest (in progress)
  - A plane Run of verify a/b on the verify-family pairs and development cases (~$6, ceiling $10), model roles on
    the candidate files (ceiling $10), engine features for the pair corpus on the host (frozen source, one
    container at a time, background).
  - _Requirements: 1.1_

- [ ] 6. Program, local memory and compilation (design sections 4-5)
  - [x] 6.1 Excerpts and the example store (no model)
    - `learn/excerpt.py` (function span at the label's pin, bounds 80/4,000 for candidates and 40/2,000 for
      examples, numbered lines, no path/repository/commit, advisory ids and security wording in comments
      redacted, delta diff); `learn/examples.py` and `ousast learn memory build` (label + feature record +
      excerpt -> `example` row; refuses `origin: user` and sources outside `sources.toml`; exits 2 when more than
      10% of a source has no excerpt); `example` added to `KINDS`; `put_blob`/`get_blob` on both backends.
    - Tests: `test_learn_excerpt.py`, example-builder refusals, blob round trip on FileStore (MinIO gated).
    - _Requirements: 3.2, 3.6, 7.2_
  - [ ] 6.2 Metered embeddings and the cache
    - `plane/models/openrouter-embedding.yaml` (`input_per_m: 0.02`), `MeteredEmbeddingClient` in
      `plane/budget.py`, usage kept by `parse_embedding_response`; cache `embeddings/<model>/<excerpt_sha>.json`;
      `ousast learn memory embed`; scripted-client tests.
    - **(budget go-ahead)** embedding the store: ~5.0 M tokens, ~$0.10, ceiling $1 (OpenRouter account).
    - _Requirements: 3.2_
  - [ ] 6.3 Retrieval and the evaluation boundary (no model)
    - `learn/retrieve.py`: per-instrument Gower distance with explicit missing, `n1 = 40`, embedding re-rank
      `r = lam(1 - D) + (1 - lam)cos`, `signals_only` mode, balance rule (`k_ret = 6`), `eligible(example, target,
      fold)`, near-duplicate drop in evaluation, deployment self-exclusion.
    - `learn/folds.py`: compile split (25% of groups), outer grouped 5-fold, leave-one-source-out,
      leave-one-framework-out.
    - Tests: `test_learn_retrieve.py` including `test_boundary` (every rendered example and demonstration eligible,
      for all fold kinds; `memory.seed` excludes the case's group), `test_learn_folds.py`.
    - _Requirements: 3.2, 3.4, 7.1, 8.3_
  - [ ] 6.4 The program (no model in tests)
    - `learn/program.py`: the signature, prompt rendering (instruction + demonstrations as a byte-identical prefix,
      then retrieved examples, then the candidate), JSON parsing with one retry -> `unsure, parse_failed`,
      `Classify(k)` with temperature 0 then 0.7, the score `s` and majority verdict; `responses/<sha>.json` cache
      and replay; `temperature`/`logprobs` pass-through in `MeteredClient.complete` and `DeepSeekChatClient._call`.
    - Tests: `test_learn_program.py` (no `EXCLUDED_FIELDS` in prompts, prefix identity, parsing, `unsure` cannot
      BLOCK, budget ceiling, replay).
    - _Requirements: 3.1, 3.3_
  - [ ] 6.5 Compile, calibrate, evaluate (no model in tests)
    - `learn/compile.toml` (pre-registered metric: balanced Brier score; seeds; budget), `learn/compile.py`
      (bootstrap few-shot on `C_boot`, 6 proposed + baseline instructions scored on `C_val`, 4 demonstration sets,
      alternates for leave-one-framework-out, artifact `programs/<sha>.json`), `learn/calibrate.py` (cross-fitted
      Platt, reliability/slope/intercept/ECE, ADVISORY-only downgrade), `learn/evaluate.py` (operating points from
      the other folds, repository-cluster bootstrap, strata, "insufficient data"), `ousast learn
      compile|evaluate|curve`.
    - Tests: `test_learn_compile.py` (`test_reproducible_from_cache` on both backends), `test_learn_calibrate.py`,
      `test_learn_decide.py`.
    - _Requirements: 3.3, 3.5, 5.2, 7.3, 7.4_
  - [ ] 6.6 First paid slice **(budget go-ahead: ~$5 expected, ceiling $7)**
    - Smoke run on 20 candidates (~$0.10): real token counts, prefix-cache hit share, parse rate; it fixes `k`
      (5 if samples 2..k hit the cache for >= 80% of their prompt tokens, else 1) before anything else is spent.
    - One compile per profile with data (`static` first; ~$2.2, ceiling $3).
    - Outer-fold evaluation, priors off, evaluable families only (675 candidates: ~$2.0 at k = 1, ~$3.0 at k = 5),
      with the 30-candidate canary set; report under `benchmarks/measurements/<date>-decision-engine-v1/` (counts
      and intervals only, no identities).
    - _Requirements: 3.1-3.5, 5.2, 7.3, 7.4_
  - [ ] 6.7 Second paid slice **(budget go-ahead: ~$7 expected, ceiling $10; needs a top-up)**
    - Leave-one-source-out (~$1.4-2.1), leave-one-framework-out where a framework reaches 10 groups ($0 today),
      learning curves over memory size (0/25/50/100%) and number of sources (~$5.2), recorded beside 6.6.
    - _Requirements: 5.1, 5.2, 8.3_

- [ ] 7. Experiments (exp-001 and program variants need budget go-ahead)
  - `learn/experiments.py`, `register`, `experiment-outcome`, Run annotation checks, `OUSAST_VERIFY_CALLERS`;
    exp-001 (known-callers line on/off, ~$7.7 expected, ceiling $15) registered, run and recorded -- an
    inconclusive result is pre-registered as likely.
  - Program-variant experiments (paired on candidates, repository cluster, arm A replayed from cache at $0): the
    machinery and its test; the first variant (`k = 5` vs `k = 1`, or the confidence source) **(budget go-ahead:
    ~$0.9-1.35 per arm-B pass of 300 candidates, ceiling $2 each)**.
  - _Requirements: 3.6, 4.1-4.4_

- [ ] 8. Integration
  - `plane/tasks/embed.py` (Model `openrouter-embedding`) and `plane/tasks/decide.py` (Model `deepseek-flash`,
    metered, exits 0/2/3), the host seed of the adopted program and the case's boundary-filtered memory; the `scan`
    decision stage and `dropped_by_engine.json`; `pre-push` admission with the engine (structural admission reasons
    unchanged; concurrency, `undecided: deadline`, a per-push budget); report fields (p, operating point,
    program id, verdict, rationale, cited lines); the fallback line (no program, no key, budget exhausted,
    insufficient data, calibration failed); the opt-in adaptation layer with user-local memory.
  - Tests use scripted clients; a plane fixture Run proves `decide` never receives an example of its own case.
  - _Requirements: 6.1-6.3, 7.3, 7.5_

- [ ] 9. Adopt
  - `ousast learn adopt`; the packaged `ruleset/decision/program-<profile>.json` with only licence-cleared
    demonstrations (the maintainer decides which licences qualify), re-evaluated as its own variant; the canary
    drift check before adoption; the priors-on/off experiment per framework with a recorded decision
    **(budget go-ahead per experiment, ~$1-2 each)**.
  - _Requirements: 3.3, 8.2_

- [ ] 10. The one-time v3 check **(budget go-ahead for the engine's v3 spend, ~$0.0045 per candidate)**
  - Commit `prediction-v3.json` first (program id, memory snapshot digest, model ids, operating points, predicted
    intervals, spend ceiling from the owner's candidate count); then v3 is run under protocol v3 and
    `result-v3-engine.json` is committed. Nothing between the two commits may touch the program, memory snapshot,
    features, priors or thresholds. This spec's code never opens v3 files.
  - _Requirements: 5.3_
