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
