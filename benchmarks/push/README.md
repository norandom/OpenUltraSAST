# Reproducible push evaluation inputs

`inputs.json` schema 1 declares 11 cases and 9 snapshots before any new scanner run.
Run `.venv/bin/python -m openultrasast.push_inputs benchmarks/push/inputs.json`.
It is offline by default, even if the ordinary repository network environment variable is set.
`--fetch` explicitly permits the existing repository resolver to fetch missing pinned commits.
No project scripts, npm installation, or scanner are executed. Nonzero exit means at least one
case has invalid input or an explicit missing prerequisite; the complete population stays in JSON.

Each snapshot references an existing repository recipe (with an optional full commit override),
plus a census of readable witness/context/license blobs. The commit identifies the whole tree;
the file list is provenance evidence, **not an analysis scope or graph allowlist**. Future replay
must materialize the pinned tree and apply declared authored edits before the ranker chooses scope.
Bytes come from `git cat-file` at the full SHA rather than the mutable cached working tree.
SHA-256 and byte length are checked for every listed blob. An authored replacement must match
exactly once, declare provenance, and verify both the original and resulting identity.

PMPro uses upstream 2.9.7 and 2.9.8. Its SQL query changes from interpolation to `$wpdb->prepare`.
The introducing replay reverses the reviewed pair; it does not claim that 2.9.7 historically
introduced the CVE. NodeGoat's contribution handler evaluates three request fields before numeric
validation. Its authored repair replaces these eval calls with `Number`, eliminating JavaScript
execution; it is not represented as an upstream security fix or a comprehensive numeric-validation
repair. Its commented tutorial repair remains unchanged. Existing injection facts include JavaScript
`eval`; actual frontend, ranker and arbiter behavior remains to be measured.

Both benign variants change only a comment on the **vulnerable** base. They mean no new defect,
not repository-clean, and deliberately retain backlog to test whether the hook becomes a nag.
The PMPro source pair is GPL-2.0; NodeGoat is Apache-2.0. Only hashes and small authored edit
instructions are stored here; repository source stays in the external opt-in cache.

Ghost is reserved independently for its production Node API, CommonJS module boundaries and async
endpoint methods, with public reviewable history at
https://github.com/TryGhost/Ghost/security/advisories. The pin declares Ghost 6.64.0-rc.0 and
Express 4.22.2. It does not establish ESM or Express 5 coverage. Selection inspected only the
manifest, license and endpoint shape, not scanner results. Their source bytes were read at the
pinned raw GitHub URLs and hashed; the offline validator still requires Git object availability.
Its supported-family positive/fixed/benign population must be independently reviewed and frozen
before scanning. If inspected results inform tuning, retire its holdout status. No reserved
security case is silently inferred from the existence of an advisory.

All capabilities remain experimental: NodeGoat is inspected transfer/development data and cannot
qualify production Node support; Node evidence cannot qualify PHP or Python. Independent PHP and
Python populations are explicitly missing in `capability_prerequisites`. VAmPI retains all three
known targets (including SQLI), with `vulnerable=1`; these snapshot regressions are not paired pushes.
Libpng is an envelope/unsupported-arithmetic control, not a detection success or a supported miss.
The validator makes no finding, precision, recall, silence, latency or admission claim.

## Frozen diagnostic scoring (task 1.3)

`push_scoring` consumes recorded execution evidence; it does not run the scanner or
implement push delta/admission policy. Freeze the workload and expected configuration
**before** executing it:

```sh
.venv/bin/python -m openultrasast.push_scoring freeze benchmarks/push/inputs.json benchmarks/push/diagnostic-config-v1.json > /tmp/profile.json
.venv/bin/python -m openultrasast.push_scoring score /tmp/profile.json benchmarks/push/input-validation.json benchmarks/push/unmeasured-run-v1.json
```

The committed v1 profile reserves the 11 declared cases and exact tip target locations.
It is a proposed 30-second evidence-mode experiment, not measured performance. The
`unmeasured-run-v1.json` deliberately contains no executions: scoring it exits **1**,
retains all 11 unresolved cases, and earns no recall, coverage or admission. An invalid
profile/runtime identity exits **2**. A fully resolved diagnostic score exits **0**;
that exit status is not capability admission. Freeze a new version when configuration,
source manifest, core, facts, query semantics or scope changes; do not edit a measured
profile to match later execution. Runtime `context` must record the actual values,
not merely copy an expected profile hash. Profiles are content identities, not signatures.

Each `records` entry supplies `case_id`, actual `ranking_mode`, `rank` (or null), exact
`selected`/`deferred` question IDs, `queries`, `alerts`, `delta`, `coverage`, `cache_state`
and nonnegative elapsed `timings` including `total`. Cache states distinguish `cold`,
`warm_changed` and `identical_tip`; stage costs remain beside each outcome. Queries
supply `id`, `status` and `outcome`. A positive needs a finding with the exact frozen
`site` and `family`, a supported `rung`, and a nonempty actual `witness`. A transitive
claim additionally needs a recorded `origin` and ordered `flow` from that region to
the frozen target's path/function. Missing rank never proves transitivity. Negative
answers require the exact `target` and a witnessed discharge; empty/failed queries
cannot earn fixed-side silence. These checks establish evidence association, not the
truth of an arbitrary supplied witness: use engine output and review the attribution.

Alerts are separate from raw findings. Only reviewed `actionable_true` alerts with
`review_evidence`, `question_id` and exact `site` association can contribute precision;
unreviewed/wrong-target alerts remain in its denominator. Benign comment changes retain
vulnerable backlog, so a raw positive is not automatically a new alert. The scorer
consumes a recorded delta; task 5.1 supplies replay, and the policy tasks establish it.

Reports retain unresolved cases, sample counts, Wilson intervals, separate regression
results, per-capability metrics, coverage and cold/warm latency. Missing benign runs
have unknown interruption rate. VAmPI's readable regression may be measured while
independent admission prerequisites remain missing. Unsupported/unreviewed populations
stay visible. All results remain experimental pending the later joint admission gate.

## First full replay experiment (task 5.2)

`measure.py` runs the six prepared PMPro/NodeGoat security, fixed and benign cases
through the production `ousast pre-push` CLI. It does not supply a hand-selected
source slice or regions. The complete 11-case population remains in the scorer;
Ghost is not scanned, and the separate VAmPI/libpng populations are retained as
unexecuted regression/envelope evidence rather than being silently dropped.

Build the local image first, then run with a writable output parent and the existing
repository-object cache mounted read-only:

```sh
docker run --rm --network none --memory 3g --entrypoint python \
  -v "$PWD:/context:ro" \
  -v "$HOME/.cache/openultrasast/repos:/cache:ro" \
  -v /path/to/output-parent:/results \
  openultrasast:dev /context/benchmarks/push/measure.py \
  --manifest /context/benchmarks/push/inputs.json --cache /cache --out /results/new-run
```

The output directory must not already exist. Input validation opens and verifies
pinned source/license blobs before any measurement. A private bare Git repository
reads the existing objects and creates reproducible authored commits using only the
specified edits. Every other tracked blob remains in the tree; the cache's files,
index and refs are unchanged. No project code, package installation or network is used.

`profile.json` is written before the first replay. PMPro runs first, followed by an
explicit `freeze-after-pmpro.json` checkpoint and Node with identical installed core,
facts, queries and policy. Both analysis and cancellation allowances stay 30 and 2
seconds. Whole CLI elapsed time, separate available stage costs, exact input pins,
source byte counts, selected/deferred identities, raw artifacts, process exits and
terminal output remain available. `rank` denotes an observed selected-question position;
an unlocated/unselected target retains null. A completed empty query cannot earn a
witnessed negative or fixed-side silence. No transitive path is fabricated from rank.

`scorecard.json` uses the existing frozen-population scorer. `decision.json` explicitly
returns NO-GO because this initial cold diagnostic does not qualify independent
capabilities or prove joint quality and warm latency. Exit **1** with a completed
`decision.json` means measured NO-GO; a traceback without that completion record is a
failed instrument. Zero CLI exit means advisory allow, never complete analysis.
Missing artifacts and unanswered questions remain errors/unresolved, not clean results.

Cold here means no persisted graph/query/comparison reuse; filesystem caches are not
flushed. Six one-shot runs are diagnostic samples, not representative warm p95 evidence.
Normal capabilities remain disabled, so zero alerts do not establish precision or useful
recall. A separately named longer lab run may obtain witnesses, but cannot replace the
30-second measurements or satisfy the hook's latency gate.

### Group 6 reuse correctness control

`reuse_control.py` creates an isolated, authored JavaScript history and invokes the packaged
replay command for a cache-populating run, a 30-second identical-revision run, an uncached
control, and dependency/one-function edits. It retains every artifact and checks equal evidence
and current admission for compatible completed questions. This is development control data,
not the untouched eligibility population or the representative warm p95 gate.

```sh
docker run --rm --network none --memory 3g \
  -v /path/to/empty/results:/results \
  -v "$PWD/benchmarks/push/reuse_control.py:/control.py:ro" \
  --entrypoint python openultrasast:dev /control.py --out /results
```

The output directory must be empty and writable by the image's nonroot user. Cold runs use a
600-second laboratory budget; the identical-revision and changed-code controls retain the
30-second deadline and 2-second cancellation allowance. Default normal capabilities remain
empty. A passing reuse control cannot authorize rollout or turn unresolved coverage into clean
analysis; groups 7–8 still own the real interface and joint evaluation.

### Frozen runtime feasibility (task 8.2)

`feasibility.py` prepares a full pinned NodeGoat history in a private bare repository,
verifies the declared source/license blobs, and freezes 21 transactions before any
scanner invocation: three each of identical-tip, function edit, dependency edit,
configuration edit, cold, 100-module growth and multi-ref workloads. Each changed-code
repetition has distinct content. It invokes the production CLI through `trace_cli.py`,
which records engine-process durations and exit receipts without changing analysis.
Frontend, overlay, census and query costs remain separate. A 600-second priming attempt
is outside the gate population; each measured transaction retains the 30+2-second
budget. An incomplete priming run does not establish warm graph reuse.

```sh
docker run --rm --network none --memory 3g --entrypoint python \
  -v "$PWD:/context:ro" \
  -v "$HOME/.cache/openultrasast/repos:/cache:ro" \
  -v /absolute/writable/results:/results \
  openultrasast:dev /context/benchmarks/push/feasibility.py \
  --manifest /context/benchmarks/push/inputs.json --cache /cache --out /results/new-feasibility
```

The output directory must not exist. `profile.json` records the planned commits,
source byte receipt, installed semantics, CPU information/affinity and container memory
limit. Every run retains the full artifact, stdout/stderr, process-stage receipts and
measurement. `scorecard.json` retains missing runs and timeouts in the declared population,
reports nearest-rank p50/p95 with sample counts, and never treats no answers as complete.
Exit 1 with a complete scorecard is measured NO-GO; a missing scorecard is an instrument
failure. Three samples per workload on development NodeGoat cannot independently qualify
a production language/framework/family or establish broad multi-project performance.

### Capability qualification (task 8.3)

The same `measure.py` replay instrument accepts `--selection development` (the
six PMPro/NodeGoat changes), `--selection regression` (three VAmPI targets), or
`--selection envelope` (libpng). Each profile retains the full declared population.
Readable regression snapshots may execute while their missing independent evaluation
prerequisites remain unresolved. `--deadline 600 --cache-dir /results/lab-cache`
is a separately frozen laboratory experiment, never a replacement for the 30-second
hook profile. A ranked or directly detected VAmPI target does not prove a transitive path.

`qualify_registry.py --evidence DIR --runtime SCORECARD --out NEW_FILE` recomputes
eligibility from the frozen profile, validated inputs, actual run and runtime scorecard.
Without `--declarations` it creates explicitly unreviewed, experimental declarations.
A reviewed declaration must match its frozen capability key, operation symbols, advice,
review identity, untouched workload and exact installed analysis semantics; all quality,
completion and runtime gates must pass. Synthetic positive controls in the unit suite
verify this contract and do not qualify real capabilities.

The installed `openultrasast/push/eligibility.json` is a trusted release input, not
repository configuration. The runner recomputes its decision and rejects stale or
modified evidence. This integrity check is not a cryptographic reviewer signature.
The versioned NO-GO registry enables no capability. Regenerate evidence after changes
to core, engine, facts, queries, policy or semantics; do not relabel old measurements.

### Packaged acceptance smoke (task 8.4)

After rebuilding the image with its installed eligibility resource, run:

```sh
docker run --rm --network none --entrypoint python \
  -v "$PWD:/context:ro" -v /absolute/writable/results:/results \
  openultrasast:dev /context/benchmarks/push/package_smoke.py \
  --out /results/new-package-smoke --ops /context/ops
```

This smoke verifies packaged CLI startup, the installed reproducible NO-GO registry,
non-overwriting installation, exact prior-hook stdin/remote arguments, accept/reject
behavior and explicit removal in disposable Git repositories. Its 0.1-second deadline
intentionally exercises unavailable coverage, not vulnerability detection. No hook is
installed in this project. Run `measure.py` separately on the final image for the full
supported security/fixed/benign workload, preserving its real partial outcomes.
The artifact and `.kiro/specs/pre-push-safety-net/validation-group-8.md` distinguish
working integration from the remaining NO-GO quality/runtime prerequisites.
