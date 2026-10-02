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

- [x] 5. Harvest (needs budget go-ahead)
  - A plane Run of verify a/b on the verify-family pairs and development cases (~$6, ceiling $10), model roles on
    the candidate files (ceiling $10), engine features for the pair corpus on the host (frozen source, one
    container at a time, background).
  - Done 2026-10-01 (`benchmarks/measurements/2026-10-01-decision-engine-harvest/record.json`): verify $2.54 and roles
    $1.40 by attribution. The engine job finished the same day (682 of 686 pair sides; the 2 family-unknown pairs
    not run) and the feature records were rebuilt; dev-php pins have no engine run (`missing`).
  - Advisory-fix pairs harvested 2026-10-02 (`benchmarks/measurements/2026-10-02-decision-engine-harvest-advisory/record.json`):
    194 sides, verify a/b on the 34 untrusted_destination sides and model roles on all ($0.38 metered, ceiling $5),
    engine on the host (54 ran, 58 asked no question, 82 no language model); static memory 724 -> 904 examples. The
    leak audit flags nothing new in the static profile; the plane profile newly flags `verify.flag_b` and `ms.operation`.
  - _Requirements: 1.1_

- [ ] 6. Program, local memory and compilation (design sections 4-5)
  - [x] 6.1 Excerpts and the example store (no model)
    - `learn/excerpt.py` (function span at the label's pin, bounds 80/4,000 for candidates and 40/2,000 for
      examples, numbered lines, no path/repository/commit, advisory ids and security wording in comments
      redacted, delta diff); `learn/examples.py` and `ousast learn memory build` (label + feature record +
      excerpt -> `example` row; refuses `origin: user` and sources outside `sources.toml`; exits 2 when more than
      10% of a source has no excerpt); `example` added to `KINDS`; `put_blob`/`get_blob` on both backends.
    - Tests: `test_learn_excerpt.py`, example-builder refusals, blob round trip on FileStore (S3 gated).
    - _Requirements: 3.2, 3.6, 7.2_
  - [x] 6.2 Metered embeddings and the cache
    - `plane/models/openrouter-embedding.yaml` (`input_per_m: 0.02`), `MeteredEmbeddingClient` in
      `plane/budget.py`, usage kept by `parse_embedding_response`; cache `embeddings/<model>/<excerpt_sha>.json`;
      `ousast learn memory embed`; scripted-client tests.
    - **(budget go-ahead)** embedding the store: ~5.0 M tokens, ~$0.10, ceiling $1 (OpenRouter account).
      Done 2026-10-01: 616 distinct excerpts of the 724 static examples, 198,819 tokens, 20 calls, $0.0040 metered
      (`benchmarks/measurements/2026-10-01-decision-engine-injection-slice/record.json`).
    - _Requirements: 3.2_
  - [x] 6.3 Retrieval and the evaluation boundary (no model)
    - `learn/retrieve.py`: per-instrument Gower distance with explicit missing, `n1 = 40`, embedding re-rank
      `r = lam(1 - D) + (1 - lam)cos`, `signals_only` mode, balance rule (`k_ret = 6`), `eligible(example, target,
      fold)`, near-duplicate drop in evaluation, deployment self-exclusion.
    - `learn/folds.py`: compile split (25% of groups), outer grouped 5-fold, leave-one-source-out,
      leave-one-framework-out.
    - Tests: `test_learn_retrieve.py` including `test_boundary` (every rendered example and demonstration eligible,
      for all fold kinds; `memory.seed` excludes the case's group), `test_learn_folds.py`.
    - _Requirements: 3.2, 3.4, 7.1, 8.3_
  - [x] 6.4 The program (no model in tests)
    - `learn/program.py`: the signature, prompt rendering (instruction + demonstrations as a byte-identical prefix,
      then retrieved examples, then the candidate), JSON parsing with one retry -> `unsure, parse_failed`,
      `Classify(k)` with temperature 0 then 0.7, the score `s` and majority verdict; `responses/<sha>.json` cache
      and replay; `temperature`/`logprobs` pass-through in `MeteredClient.complete` and `DeepSeekChatClient._call`.
    - Tests: `test_learn_program.py` (no `EXCLUDED_FIELDS` in prompts, prefix identity, parsing, `unsure` cannot
      BLOCK, budget ceiling, replay).
    - _Requirements: 3.1, 3.3_
  - [x] 6.5 Compile, calibrate, evaluate (no model in tests)
    - `learn/compile.toml` (pre-registered metric: balanced Brier score; seeds; budget), `learn/compile.py`
      (bootstrap few-shot on `C_boot`, 6 proposed + baseline instructions scored on `C_val`, 4 demonstration sets,
      alternates for leave-one-framework-out, artifact `programs/<sha>.json`), `learn/calibrate.py` (cross-fitted
      Platt, reliability/slope/intercept/ECE, ADVISORY-only downgrade), `learn/evaluate.py` (operating points from
      the other folds, repository-cluster bootstrap, strata, "insufficient data"), `ousast learn
      compile|evaluate|curve`.
    - Tests: `test_learn_compile.py` (`test_reproducible_from_cache` on both backends), `test_learn_calibrate.py`,
      `test_learn_decide.py`.
    - _Requirements: 3.3, 3.5, 5.2, 7.3, 7.4_
  - [x] 6.6 First paid slice **(budget go-ahead: ~$5 expected, ceiling $7)**
    - Smoke run on 20 candidates (~$0.10): real token counts, prefix-cache hit share, parse rate; it fixes `k`
      (5 if samples 2..k hit the cache for >= 80% of their prompt tokens, else 1) before anything else is spent.
    - One compile per profile with data (`static` first; ~$2.2, ceiling $3).
    - Outer-fold evaluation, priors off, evaluable families only (675 candidates: ~$2.0 at k = 1, ~$3.0 at k = 5),
      with the 30-candidate canary set; report under `benchmarks/measurements/<date>-decision-engine-v1/` (counts
      and intervals only, no identities).
    - Done 2026-10-01 for family **injection only** (the maintainer's scope for this slice; memory holds every family,
      at most 2 contrast examples per prompt): smoke fixed `k = 5` (repeat hit share 0.96); program `c1237a49...`
      (proposed instruction 5, balanced Brier 0.128 on 13 `C_val` candidates vs 0.199 baseline); 110 out-of-repository
      candidates in 29 groups: ADVISORY recall 0.90 [0.82, 0.97], precision 0.54 [0.44, 0.65]; AUC of `s` 0.74 [0.65,
      0.85]; BLOCK not offered (ECE 0.064 > 0.05, and no fold reached a Wilson lower bound of 0.95); canary agreement
      0.83; $0.91 metered at list price (provider balance $18.20 -> $17.90). Record:
      `benchmarks/measurements/2026-10-01-decision-engine-injection-slice/record.json`. The other evaluable families
      are not evaluated yet.
    - _Requirements: 3.1-3.5, 5.2, 7.3, 7.4_
  - [ ] 6.7 Second paid slice **(budget go-ahead: ~$7 expected, ceiling $10; needs a top-up)**
    - Leave-one-source-out (~$1.4-2.1), leave-one-framework-out where a framework reaches 10 groups ($0 today),
      learning curves over memory size (0/25/50/100%) and number of sources (~$5.2), recorded beside 6.6.
    - Partial 2026-10-02 (`benchmarks/measurements/2026-10-02-decision-engine-slice-2/record.json`): after the
      advisory-fix harvest (memory 724 -> 904), one compile per evaluable family and its outer-fold evaluation for all
      six (injection, untrusted_destination, path, output_encoding, deserialization, access_control); out-of-repository
      AUC 0.77-0.96, BLOCK offered for none (calibration holds only for output_encoding, where no fold reaches the
      Wilson bound); one memory-size point for injection (724 vs 904 examples, paired: AUC 0.76 vs 0.77). $2.88
      metered (ceiling $8). Not done: leave-one-source-out, the 0/25/50% curve points, the source-count curve.
    - _Requirements: 5.1, 5.2, 8.3_

- [ ] 7. Experiments (exp-001 and program variants need budget go-ahead)
  - [x] 7.1 Machinery (no model in tests): `learn/experiments.py` -- YAML manifests under `plane/experiments/<id>.yaml`
    (hypothesis, arms as program-spec overrides or plane `task_env`, unit, pairing, repository cluster, metrics with
    `[label=]` selectors and targets, MDE, two looks with O'Brien-Fleming boundaries, budget ceiling, families, folds,
    frozen units file), `register` (`experiment` row with both digests; refuses an uncommitted, modified or re-declared
    manifest), `units` (freeze the families' evaluation candidates, paired by candidate across pins; no model), `run`
    (paired arms in a seeded repository order, a seeded coin per unit for which arm goes first, `arm_outcome` rows,
    resumable, arm A replay-only at $0, canary replicates under a fresh cache salt, the first look during the run),
    `analyse` (paired repository bootstrap, exact McNemar, the looks, adopt / reject / equivalent / inconclusive,
    `experiment_result` row + `benchmarks/experiments/<id>/result.json`), `ousast learn experiment
    register|units|run|analyse`; `OUSAST_VERIFY_CALLERS=off` in `plane/tasks/verify.py`; the retrieval-ensemble
    sampling variant (`ProgramSpec.sampling = retrieval_ensemble`: `k` samples at temperature 0 over `k` disjoint
    retrieved example sets; default unchanged). Tests: `test_learn_experiments.py` (18, scripted clients, FileStore).
  - [x] 7.2 Registered, not run: `exp-001-known-callers` (plane arms, `flag_rate[label=1]`, MDE 0.15, ceiling $15;
    units `pending` -- model-free candidate generation on the 41 development repositories is not built, and plane Run
    annotation checks / the `experiment-outcome` task are not written) and `exp-002-retrieval-ensemble` (arm A today's
    k = 5 temperature sampling, arm B the retrieval ensemble; primary canary agreement (target 0.90) and within-pair
    AUC, secondary usd per candidate, AUC, ADVISORY recall/precision; families injection and access_control on the
    slice-2 candidates; ceiling $4: A $1, B $3). Both registered in `s3://sast-memory` at fbc3220
    (`benchmarks/experiments/<id>/registration.json`). exp-002's units are `pending` too: on 2026-10-02 every example
    row in the store carried null plane-only instruments (`agree`, `model_sinks`, `verify`) and `load_examples` raised
    on them, so `ousast learn experiment units` could not freeze the candidates.
  - [ ] 7.3 exp-001 run and recorded (~$7.7 expected, ceiling $15) -- an inconclusive result is pre-registered as
    likely; needs the frozen units file first.
  - [x] 7.4 exp-002 run and recorded 2026-10-02 (budget go-ahead ~$2 expected, ceiling $4): **reject B**. 160 paired
    units (injection 119, access_control 41; 56 repositories; 108 units in 54 candidate pairs), both arms, two
    replicates each, no early stop. Primary: canary agreement A 0.875 -> B 0.906 (diff +0.03, CI [-0.03, +0.10],
    spans; B meets the 0.90 target), within-pair AUC A 0.815 -> B 0.741 (diff -0.07, CI [-0.13, -0.02], **against B**).
    Secondary: AUC -0.02 (CI [-0.04, -0.003], against), ADVISORY recall -0.06 (spans; McNemar 7/2, p = 0.18),
    precision +0.01 (spans), usd per candidate A $0.0021 -> B $0.0051 (CI [+0.0027, +0.0032], against: the five
    disjoint example sets share only the prompt prefix in DeepSeek's cache). Priced usage A $0.68 (1206 paid calls,
    395 replayed), B $1.63 (1350 paid, 250 replayed). Result: `benchmarks/experiments/exp-002-retrieval-ensemble/result.json`,
    `benchmarks/measurements/2026-10-02-exp-002/record.json`. Three repairs on the way (each its own commit): example
    rows' null plane-only features (1f525ff), the 788 embedding vectors absent from RustFS (copied from the file
    store), the result row's column-type collision under S3 Select (780caaa). Further program variants (`k = 5` vs
    `k = 1`, the confidence source) as new manifests.
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
