# Implementation Plan

One task group per increment of `design.md` section 8, in that order. A group starts only after the previous
group's exit is recorded. Maintainer decisions of 2026-10-04 are folded in: a registered long-deadline arm
(`--deadline 300`) beside the hook's default 30 s (design 4.0, group 8); adoption needs no significant regression
on the unseen slice (Req 5.4 as amended, design 7.3, tasks 6.4 and 8.2); only permissively licensed repositories
are published by name, everything else goes to the gitignored private manifest under a digest (Req 1.4, design
1.4); concurrency stays at two AX lanes plus the VM lane (design 5.3).

Execution rules:

- **Who does what.** Codex implements every coding task offline: no network, no model, no store, no cluster. The
  coordinator runs every networked step (GitHub and OSV API calls, git fetches and clones, the S3 store, image
  pushes, kind and kube-ax). Those tasks are marked **(coordinator, network)**. Steps that need the coordinator but
  no network (agent label reads, adjudication, the v3 guard bisection, commits) are marked **(coordinator)**.
  Steps that spend model money are marked **paid: needs a budget go-ahead**. Each starts only after the maintainer
  confirms a ceiling against the provider balance read just before it.
- **Done means.** A coding task is done when its tests pass in the host suite, `ruff check`, `ruff format --check`
  and `mypy` are clean, and the reserved-repository guard is green. No test makes a network, model or cluster call.
- **Names stay in the pool directory.** Pool repository names and URLs appear only under `benchmarks/unseen/`
  (copyleft and other non-permissive ones only under the gitignored `benchmarks/unseen/private/`). Raw per-change
  records live in `~/ousast-results/unseen/` and the store, never in the repository.
- **Population v3 is never opened.** It is checked only through the guard test, run as a black box with its
  output discarded.
- **Every group ends with a measured exit** and a record at
  `benchmarks/measurements/<date>-unseen-NN-<slug>/record.json`: commit, image digests where used, the instrument
  checks (bytes read, JVM time, exit codes), counts and digests. No repository names. The guard sweeps these
  records.
- **Instrument first** (AGENTS.md). A zero, an empty draft or a fast run is treated as an instrument failure until
  bytes read and wall time prove otherwise.

- [x] 1. Used set and guard (design 1.2, 6; increment 1)
- [x] 1.1 Used-set builder
  - `benchmarks/unseen/eligibility.py`: normalises names (lower case, no `.git`, no trailing slash) and builds the
    used set from every source of design table 1.2: pair catalogs, recipes and datasets under `benchmarks/pairs/`
    plus the local pointer-pair manifests as `benchmarks/pairs/catalog_gen.py` reads them; `population-v1.toml`
    and `population-v2.toml`; the advisory-fix batch catalogs; memory `example` rows (`repo` field) through an
    injected `MemoryStore` (`FileStore` locally, the S3 store when the coordinator passes one); experiment units
    under `plane/experiments/`; `benchmarks/measurements/` and `benchmarks/experiments/`; a text sweep for
    `github.com/<owner>/<name>` over `benchmarks/`, `src/`, `tests/`, `plane/` and `.kiro/`. It never reads
    population v3 and never prints a name. Output: counts per source and the sha256 of the sorted set.
  - `tests/test_unseen_eligibility.py`: a synthetic tree with one repository per source, each found; case, `.git`
    and trailing-slash variants collapse; stdout and the output JSON contain no name; a v3-shaped file planted in
    the synthetic tree is not opened (open is patched to fail on it).
  - _Requirements: 1.1_
- [x] 1.2 Canonical resolution, renames and forks
  - `eligibility.py`: `resolve(candidate, api)` with an injected GitHub client returns the canonical `full_name`,
    former names (redirects) and the fork network (`parent`, `source`). A candidate is ineligible when any of them
    is in the used set; one candidate per fork network is kept.
  - Tests with a fake client: a planted used repository, a renamed one and a fork of a used one are each
    rejected; two forks of one network keep one; the rejection reason is a source label, not a name.
  - _Requirements: 1.1_
- [x] 1.3 Guard extended to pools
  - `tests/test_independent_population.py`: the sweep becomes a list of (reservation directory, names):
    `benchmarks/independent/` for populations, `benchmarks/unseen/` for pools (public manifests, plus
    `benchmarks/unseen/private/*.toml` when present). The sweep also covers `plane/`. New tests: pool and
    population names are disjoint (failure prints a count only); a frozen pool's manifest digest equals its
    `freeze-pN.json` (skipped while no pool is frozen). The existing v3 handling is unchanged.
  - Each reservation is exempt only inside its own directory: population names (v3 included) are still swept in
    `benchmarks/unseen/`, the gitignored `private/` files included. Task 3.1 depends on this.
  - `.gitignore`: `benchmarks/unseen/private/`.
  - Evidence: the guard is green with an empty `benchmarks/unseen/`, and red when a test fixture names a pool
    repository in `benchmarks/measurements/` (shown once in the record).
  - _Requirements: 1.2, 1.3, 1.4_
- [x] 1.4 Usage ledger
  - `benchmarks/unseen/ledger.py`: append-only `usage-pN.jsonl`, one row per use (slice, decision or experiment
    id, purpose `baseline | exploratory | informed | qualifies`, date, result digest, freeze digest). It refuses a
    `qualifies` row for a change whose slice already has an `informed` row for it, and refuses to rewrite rows.
  - `tests/test_unseen_ledger.py`: append, the refusal, a rewritten row detected by a digest chain.
  - _Requirements: 5.2_
- [x] 1.5 Used-set measurement and record 01 **(coordinator, network)**
  - Run `eligibility.py` against the real sources, the S3 memory store included (read only).
  - Instrument: each source reports files read and bytes; a source with zero rows fails the run unless it is
    known empty.
  - `benchmarks/measurements/<date>-unseen-01-used-set/record.json`: counts per source, used-set digest, guard
    result (green on the empty pool), test counts of 1.1-1.4.
  - _Requirements: 1.1, 1.3_

- [ ] 2. Sourcing and extraction (design 1.1, 1.3, 1.4, 2, 3; increment 2)
- [x] 2.1 Advisory candidates and repository filters
  - `benchmarks/unseen/source.py`: from GHSA advisory JSON (pip, npm, maven, composer; published 2019 or later)
    keep those whose CWE maps to a family through `src/openultrasast/model/taxonomy.py` and that link one fix
    commit with one parent in one repository; attach the OSV first affected version; flag `post_cutoff` when
    published after 2026-06-01. Repository filters: anonymous HTTPS, at most 500 MB, licence at the pinned head
    (LICENSE file, then the API's SPDX id) classed `permissive` (the design 1.4 list) or `private`.
  - `tests/test_unseen_source.py` on recorded fixture JSON (no network): CWE mapping, multi-parent and
    multi-repository fixes dropped, cutoff flag, licence classing (GPL, AGPL, LGPL, none and source-available go
    private).
  - _Requirements: 1.4, 2.1_
- [x] 2.2 Vulnerability-introducing range
  - `benchmarks/unseen/extract.py`: the `introducing` method of design 2.1 (blame of the sink line, or the
    declaration for an absence bug; absence at V's first parent; no merge or root; at most 50 files and 2,000
    lines; OSV version bracket when present; walk-back of at most five steps) and the `last_touch` fallback. Each
    change records method, family, vulnerable function resolved in head, head-side lines, `post_cutoff`, advisory
    id. Git only; no scanner or engine.
  - `tests/test_unseen_extract.py` on a synthetic repository built in a temp dir: accepted V; a reformat walked
    back; a merge rejected; size cap; bracket rejection; fallback chosen when no V passes.
  - _Requirements: 2.1_
- [x] 2.3 Ordinary-commit draw
  - `extract.py`: first-parent, non-merge commits touching an analysed language; the exclusions of design 2.2
    (security words of the narrow pattern, reverts, bot and bump commits, manifest- or lock-only, generated or
    vendored, advisory fix commits, commits touching a known vulnerable function, more than 1,000 source lines,
    counted). Seeded draw of 12 per repository over three time thirds by four size buckets, proportional, at least
    one per third; a repository with fewer than 40 eligible commits is dropped.
  - Tests: each exclusion; the narrow pattern keeps "query", "token", "session"; allocation and the seed
    reproduce the same draw; the 40-commit floor.
  - _Requirements: 2.2, 2.3_
- [x] 2.4 Draft manifest and slices
  - `benchmarks/unseen/draft.py`: writes `benchmarks/unseen/draft-p1.toml` (permissive entries by name) and
    `benchmarks/unseen/private/draft-p1.toml` (the rest); the public file holds an opaque id and
    sha256(URL, commits) per private entry. Seeded shuffle into three slices of 100 repositories, stratified by
    ecosystem and `post_cutoff`; each repository has one introducing change and 12 ordinary changes.
  - Tests: the digest covers private entries; no private URL in the public file; the same seed gives the same
    slices; per-slice strata within one repository of proportional.
  - _Requirements: 1.2, 1.4, 2.3, 5.2_
- [ ] 2.5 Sourcing run **(coordinator, network)**
  - `gh api /advisories` enumeration, OSV lookups, canonical resolution against the used set (1.2), blobless
    clones into a scratch cache, extraction (2.2, 2.3), draft (2.4).
  - Instrument: clones counted with bytes on disk; a repository whose clone reads zero source files is an
    instrument failure, not a drop. Fewer than 300 eligible repositories stops the run with counts; the
    eligibility bars are not relaxed to fill it.
  - Observable: a draft of 300 repositories (3,900 changes) on disk.
  - _Requirements: 1.1, 1.4, 2.1, 2.2, 2.3_
- [ ] 2.6 Label check and record 02 **(coordinator)**
  - Every third `introducing` change read by an agent, no model call, marked `confirmed | refactor | unclear`
    in the draft.
  - `benchmarks/measurements/<date>-unseen-02-draft/record.json`: candidates per ecosystem, rejections per used
    source, licence split (public, private), method counts, post-cutoff counts, confirmed share, ordinary-commit
    exclusion counts. No names.
  - _Requirements: 2.1, 2.2_

- [ ] 3. Freeze p1 (design 1.2, 6; increment 3)
- [x] 3.1 Guard bisection tool
  - `benchmarks/unseen/bisect_guard.py`: rewrites the draft with a candidate subset, runs
    `.venv/bin/pytest -q -p no:cacheprovider tests/test_independent_population.py -k referenced` with stdout and
    stderr discarded, reads only the exit code, and bisects until green. Reports the dropped count only.
  - `tests/test_unseen_bisect.py` with an injected fake guard (a hidden set): finds and drops exactly the hidden
    members; never logs a candidate; an exit code other than 0 or 1 aborts (instrument failure).
  - _Requirements: 1.1_
- [x] 3.2 Freeze writer
  - `benchmarks/unseen/freeze.py`: canonical `pool-p1.toml` (and the private counterpart) from the bisected draft;
    `freeze-p1.json` with used-set digest and per-source counts, guard result, dropped count, label-check counts
    and the freeze digest (sha256 of the canonical manifest). Refuses to write over a frozen pool; a correction
    is `p2`.
  - Tests: digest stable under key order; overwrite refused; the guard's digest test (1.3) passes on a fixture
    pool.
  - _Requirements: 1.2_
- [x] 3.3 Protocol p1
  - `benchmarks/unseen/protocol-p1.md`: the scoring rules of design section 4 (default flags, decision 4.0's
    long-deadline arm, catch and location rules, false alarm, coverage states), the statistics of section 3 and
    7, and the adoption gate of 7.3, stated before any replay.
  - Observable: the file exists and its sha256 is listed in `freeze-p1.json`.
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 5.4_
- [ ] 3.4 Freeze run and record 03 **(coordinator)**
  - Run the bisection (3.1), then the freeze (3.2). Guard green, digest test active.
  - `benchmarks/measurements/<date>-unseen-03-freeze/record.json`: freeze digest, protocol digest, dropped
    count, final counts per slice and kind.
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 4. Dispatcher (design 5.3; increment 4)
- [x] 4.1 Items, workloads and the AX lane
  - `benchmarks/ax/batch.py`: `Item` (id, input objects, result object name, command, extra env, input digest),
    `Workload` (image digest, allowed URL env names, deadline, result validator) and the `ax` lane, moved from
    `benchmarks/learn/engine_trace_ax.py`: manifest render, egress readiness, presigned GET and PUT as `.dat`,
    apply, poll result object and AX phase, delete, object cleanup. The `kind` lane is the same lane with the
    kind context.
  - `tests/test_ax_batch.py` with a fake `ax` CLI and a fake store: manifest holds only the allowed URL env
    names and no credential; names carry the `ousast-engine-` prefix; cleanup on success and failure.
  - _Requirements: 4.1, 4.2, 4.5_
- [x] 4.2 Scheduler, fallback and resume
  - `batch.py`: two AX lanes and one VM `docker` lane by default (one container at a time); sandbox death retried
    once under a new name, a second death or a JVM OOM goes to the VM fallback queue ahead of overflow;
    `progress.json` written by the scheduler only; a `STOP` file halts launches; resume skips items whose stored
    record has the same input digest; a cleanup failure stops dispatching.
  - Tests with fake lanes: retry then fallback; OOM straight to fallback; resume skips; `STOP`; cleanup failure
    halts; never more than two AX tasks in flight.
  - _Requirements: 4.3_
- [x] 4.3 Engine pass on the dispatcher
  - `benchmarks/learn/engine_trace_ax.py` and `engine_trace.run_plan` become an engine `Workload` over `batch.py`;
    no behaviour change.
  - Observable: `tests/test_ax_executor.py` and `tests/test_engine_trace.py` pass with their assertions unchanged
    (moved imports only).
  - _Requirements: 4.3_
- [ ] 4.4 Engine smoke on kube-ax and record 04 **(coordinator, network)**
  - Two pins through the new dispatcher on kube-ax, compared with their stored records.
  - `benchmarks/measurements/<date>-unseen-04-dispatcher/record.json`: image digest, per-pin wall time and JVM
    time, record digests equal to the stored ones (or the diff counted), cleanup result.
  - _Requirements: 4.3_

- [ ] 5. Replay task (design 5.1, 5.2; increment 5)
- [x] 5.1 Image stage
  - `plane/Dockerfile.engine-task`: second stage `FROM engine AS replay` adding `git`, the package with its
    runtime dependencies and `benchmarks/unseen/replay_entry.py`; smoke `ousast pre-push --help`. The root image
    stays `ghcr.io/norandom/ax-task-runner:v0.3.1`; the engine stage is unchanged.
  - `tests/test_unseen_image.py`: parses the Dockerfile; the `replay` stage builds from `engine`; the root image
    pin; the engine stage's text is byte-identical to before.
  - _Requirements: 4.1_
- [x] 5.2 Task entry
  - `benchmarks/unseen/replay_entry.py`, standard library only, reusing `engine_task_entry.transfer`: GET the spec;
    `git init` and depth-1 fetches of head and base over HTTPS (180 s bound), verified with `git cat-file -e`; run
    `ousast pre-push` with the spec's hook flags (defaults, or `--deadline 300` for the long-deadline arm), heap
    1700 MB and the cluster JVM flags; pack `push.json`, `push.txt`, `engine.json`, `instrument.json` (files and
    bytes in the checkout, bytes of each changed file, JVM wall time, hook exit code, step timings, image
    digest); PUT as `.dat`. Any error PUTs a failure record naming the step and status, never URL text.
  - `tests/test_unseen_replay_entry.py`: a local bare repository and a localhost presign stub; success record
    fields; a missing commit, a failed fetch and a hook crash each give a failure record; zero bytes read and a
    replay faster than JVM start are flagged `suspect_fast`.
  - _Requirements: 3.1, 4.1, 4.2_
- [x] 5.3 Replay workload
  - `benchmarks/unseen/replay.py`: builds `Item`s from a frozen slice and an arm (`default` or `long_deadline`);
    the spec object carries the repository URL so names stay out of AX status and telemetry; task names
    `ousast-engine-replay-<slug>-<digest>` with an opaque slug; the validator rejects a record without
    `instrument.json`; records go to `~/ousast-results/unseen/<pool>/<slice>/<arm>/` and the store.
  - Tests: no repository name in any task name or manifest; only the two presigned URLs in the env; input
    digest changes with the arm's flags; `instrument_failure` items queued for one re-run.
  - _Requirements: 3.1, 4.1, 4.2, 4.3_
- [ ] 5.4 Proof on kind, then kube-ax, and record 05 **(coordinator, network)**
  - Build and push the `replay` target, pinned by digest. Five changes from this repository's own history (never
    pool changes) on kind, then the same five on kube-ax, then on the VM lane.
  - Exit: instrument fields show bytes read and realistic JVM time on every lane; quick-tier findings equal
    across lanes.
  - `benchmarks/measurements/<date>-unseen-05-replay-task/record.json`: image digest, per-lane timings, bytes,
    exit codes, the quick-tier comparison.
  - _Requirements: 4.1, 4.2, 4.5_

- [x] 6. Scorer (design 3, 4, 7.1, 7.3; increment 6)
- [x] 6.1 Coverage states
  - `benchmarks/unseen/score.py`: each record gets one state (`instrument_failure`, `unanalysable`, `quick_only`,
    `engine_covered`) from `instrument.json` and the artifact; `suspect_fast` goes to failure; a slice above 5%
    `instrument_failure` after re-runs is refused.
  - `tests/test_unseen_score.py` on synthetic records: every state; the refusal; a failure never counts as quiet
    or missed.
  - _Requirements: 3.3_
- [x] 6.2 Catch and false-alarm rules
  - `score.py`: family match (engine family, quick-rule CWE through `taxonomy.py`), the location table of design
    4.1, all three streams with the stream named per catch; false alarm on any finding of any stream; the
    alerts-only rate.
  - Tests: right family wrong place misses; `access_control` on the handler; `config_secrets` file scope; a
    quick-rule-only catch; one advisory finding on an ordinary change is a false alarm.
  - _Requirements: 3.2_
- [x] 6.3 Rates, intervals and breakdowns
  - `score.py`: Wilson 95% intervals; repository-cluster bootstrap for false alarms; ICC; breakdowns per family,
    method, `post_cutoff`, stream, coverage state and the confirmed subset.
  - Tests: the n values of design section 3 (315, 483, 756, 62, 88, 97) reproduced; bootstrap seeded; ICC on a
    synthetic clustered set.
  - _Requirements: 2.3, 3.3_
- [x] 6.4 Budgets, paired tests, the gate and record 06
  - `score.py`: per-budget thresholds (1%, 5%, 10%), labelled `exploratory` in-slice and `fixed` when supplied;
    a binary arm's single operating point with the budgets it meets; exact two-sided McNemar for catch and for
    false alarm; `gate(A, B)` returning `pass | regression | not_run` per design 7.3.
  - Tests: thresholds on a synthetic score set; McNemar exact values; a binary arm with a significant
    false-alarm increase gives `regression`; missing slice or excess failures give `not_run`.
  - `benchmarks/measurements/<date>-unseen-06-scorer/record.json`: test counts and the digest of the scorer's
    output on the committed synthetic fixture.
  - _Requirements: 3.4, 5.4_

- [ ] 7. Baseline (design 4, 6; increment 7; G0 exit)
- [ ] 7.1 Frozen source and dry run **(coordinator, network)**
  - Export HEAD to a frozen tree; build and push the `replay` image from it, pinned by digest.
  - `benchmarks/push/python_overhead.py` run with the stub engine to size per-replay Python cost; dispatcher dry
    run on slice 1 lists 1,300 items without launching.
  - _Requirements: 5.1, 4.1_
- [ ] 7.2 Baseline replay of slice 1 **(coordinator, network)**
  - Default arm, 1,300 replays over two AX lanes and the VM lane (about 9 hours); `instrument_failure` items
    re-run once; the run stops for a cause above 5% failures.
  - Observable: 1,300 records in `~/ousast-results/unseen/p1/1/default/` and the store, each with
    `instrument.json`.
  - _Requirements: 3.1, 4.3, 5.1_
- [ ] 7.3 Adjudication **(coordinator)**
  - Flagged ordinary changes adjudicated against protocol-v2's standard (all if 30 or fewer, else every third);
    the adjudicated share kept beside the false-alarm rate. ICC measured; above 0.05 noted as "next pool sizes
    up".
  - _Requirements: 3.2, 2.3_
- [ ] 7.4 Record 07 and the ledger **(coordinator)**
  - `benchmarks/measurements/<date>-unseen-07-baseline/record.json`: `score.py` output (counts, rates, Wilson and
    bootstrap intervals, coverage per state, per family, method, stream), freeze digest, image digest, commit.
    `usage-p1.jsonl` row `baseline`.
  - Observable: guard green over the record; G0's exit met.
  - _Requirements: 5.1, 5.2, 3.3_

- [ ] 8. Arms on slice 1 (design 4.0, 5.4, 7.1-7.3; increment 8; G1)
- [ ] 8.1 Registered long-deadline arm
  - `plane/experiments/` manifest for the long-deadline arm: hook flags with `--deadline 300`, budget 0,
    `unseen: {pool: p1, slice: 1}`, committed before its first replay. `src/openultrasast/learn/experiments.py`
    accepts `unseen` and a hook-flag arm.
  - `tests/test_learn_experiments.py`: the manifest loads; an `unseen` block without pool or slice is refused.
  - _Requirements: 3.4, 5.3_
- [ ] 8.2 `unseen` block and adoption gate in `analyse`
  - `experiments.py` `analyse`: writes `unseen` into `result.json` (catch at each budget per arm, paired B - A,
    McNemar, `gate`) from `score.py`; checks the usage ledger; adoption requires the fold rule and
    `gate == pass`.
  - Tests: `regression` and `not_run` each block adoption; an `informed` slice cannot qualify; result JSON shape.
  - _Requirements: 5.2, 5.3, 5.4_
- [ ] 8.3 Engine-evidence arm
  - `benchmarks/unseen/arms.py`: a score per change from `engine.json` (witness rows on head-side changed
    functions), no model; plugs into the budget thresholds of 6.4.
  - Tests on synthetic records: score monotone in witness strength; a change without engine coverage gets no
    score and is reported, not counted quiet.
  - _Requirements: 3.4_
- [ ] 8.4 Model-arm adapter
  - `arms.py`: candidates from head-side changed functions of stored records, scored by the current decision
    engine program (and the combiner when its program exists; else its row reads `not_built`); change score is the
    maximum; metered client, dry run first, response cache, the manifest's `budget_usd` as the hard ceiling.
  - Tests with a scripted client: dry-run estimate, ceiling stop, cache replay; no model call.
  - _Requirements: 4.4, 3.4_
- [ ] 8.5 Long-deadline replay of slice 1 **(coordinator, network)**
  - 1,300 replays of the `long_deadline` arm, bounded at about 345 s each (up to about 42 hours over three
    lanes), with `STOP` and resume across sessions; failures re-run once.
  - Observable: 1,300 records under `~/ousast-results/unseen/p1/1/long_deadline/`, JVM time in each.
  - _Requirements: 3.1, 3.4, 4.3_
- [ ] 8.6 Model arms on slice 1 **(coordinator, network; paid: needs a budget go-ahead)**
  - Dry run gives the candidate count; estimate at the injection slice's measured cost (about $0.008 per
    candidate at k = 5); the maintainer sets the ceiling against the balance read just before. Then the decision
    engine arm (and the combiner if built) on the VM.
  - _Requirements: 4.4, 3.4_
- [ ] 8.7 Record 08: the arms table **(coordinator)**
  - `benchmarks/measurements/<date>-unseen-08-arms/record.json`: per arm (hook 30 s, hook 300 s, engine evidence,
    decision engine, combiner or `not_built`) catch at 1/5/10% budgets with Wilson intervals and realised
    false-alarm rates, coverage per state, spend; `exploratory` rows in `usage-p1.jsonl`.
  - Observable: one committed table of arms on slice 1; G1's table exists.
  - _Requirements: 3.4, 5.2, 5.3_

## Implementation Notes

- 2026-10-04: Tasks 1.1–1.4 implemented offline and independently reviewed. Task 1.5 remains for the
  coordinator; no networked measurement or commit was performed. Command and API contracts:
  `benchmarks/unseen/README.md`. Offline evidence:
  `benchmarks/measurements/2026-10-04-unseen-01-offline/record.json`.
- Population guard scope is preserved under the maintainer's hard rule: benchmarks/src/tests for
  populations, plus plane for pools. Each directory exemption is reservation-specific, including private
  pool manifests. Extending population scope to plane exposed 30 existing references; no historical
  records were changed or exempted inside the existing population scope.
- S3 inventory opens through `open_store(read_only=True)` because ordinary store construction writes a
  Select capability probe. Default store behavior is unchanged; inventory uses LIST/GET only.
- The freeze writer must match the canonical TOML digest encoding documented in the pool README and
  exercised by `test_independent_population.py`; final pool discovery does not trust mutable status.

### Group 2 implementation evidence (2026-10-04)

Tasks 2.1–2.4 are implemented offline and independently reviewed. Task 2.5 is
`python -m benchmarks.unseen.draft --root "$PWD" --s3-store s3:// --seed 20260601`
with the documented PATH/PYTHONPATH and GH_TOKEN environment. No networked draw,
label check, group-2 measurement record, guard bisection, or commit was performed.
The group header remains pending its coordinator exits 2.5/2.6.

The command rebuilds the group-1 used set, resolves renamed/fork repositories,
uses disposable external blobless clones, re-reads licences at extracted heads,
and emits counts/digests only. The README documents injected clients, method bias,
the hard 300-repository floor, and an explicitly unmeasured resource estimate.
Independent review caught and fixed ambiguous parent-function absence and stale
candidate-404 handling; regression tests cover both.

Validation: requested pytest selection 103 passed, 1 skipped, exit 0 (population-test
output discarded); `ruff check .` exit 0; `ruff format --check .` exit 0 (411 files);
`mypy src/openultrasast` exit 0 (160 source files). The CLI `--help` smoke exited 0.
Source-read instrumentation printed 20,101 bytes for the extraction implementation.

### Groups 4–6 offline implementation (2026-10-04)

Tasks 4.1–4.3, 5.1–5.3 and 6.1–6.4 are implemented and independently reviewed.
Tasks 4.4 and 5.4 remain coordinator-owned network proofs; group headers 4 and 5 stay
pending those exits. No commit, network request, Docker, AX or kubectl command was run.
The sourcing job's draft.py, source.py, extract.py and journal.py are unchanged.

The shared dispatcher retains the engine adapter's historical questions.json object
name to preserve its unchanged assertions; replay uses spec.dat and result.dat.
The engine Dockerfile body is unchanged except its required AS engine alias; CI builds
engine and replay separately. S3Store's read_only class default preserves existing
constructor-bypassing transport fixtures; initialized read-only stores still refuse writes.

Exact coordinator commands and input contracts are in benchmarks/unseen/README.md,
including frozen TOML/private pointer verification, scoring joins, own-history proof
preparation and anonymous measurement-record generation. JVM wall time is the hook's
aggregate scan build/query timing and is labelled as such. Unsupported-only partitions
with explicit language_not_covered evidence do not pretend to have launched a JVM.

Record 06 contains the committed synthetic fixture and scorer-output digests. The
reserved-repository guard was run as a black box with both output streams discarded.
Independent review: APPROVED; all reported integration and coverage defects resolved.

Final verification: requested pytest command 279 passed, 8 skipped, exit 0; separate
`tests/test_ax_batch.py` 5 passed, exit 0; `ruff check .`, `ruff format --check .`,
`mypy src/openultrasast`, and the output-discarded reserved-repository guard all exit 0.
The own-history proof preparer and replay dry run read five items and exit 0.
