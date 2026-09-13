# Implementation verification: group 5

Group 5 was authorized by the maintainer's “approved” after group 4 completion.
Tasks 5.1–5.2 are implemented and verified (16/27 total); the measured feasibility decision is NO-GO.
Real capability eligibility and rollout readiness remain unproven.

## Execution and review mode

Fresh implementer dispatch for 5.1 returned `agent thread limit reached`.
The [Kiro implementation skill](../../../.opencode/skills/kiro-impl/SKILL.md) explicitly
states: “If multi-agent is not available, fall back to manual mode execution for all tasks.”
Its manual review rule permits review in the main context when a fresh reviewer is unavailable.
This run therefore uses manual implementation and adversarial review, not independent review.

## Task 5.1 brief

Wire explicit immutable base/head replay through the existing mapper, ranker, driver,
base comparison and admission/report contracts. Preserve the shared elapsed deadline,
source/index/ref state, completed evidence on failure, and separate coverage/exit policy.
Requirements: 1.1, 2.1, 3.1, 3.4, 4.1, 4.2, 5.5, 7.1, 7.3. Design sections are named:
Snapshot Adapter, Ranker Scope Contract, Delta and Actionability Policy, Result and Hook
Adapter, Cache and Engine Boundary. No new detector, ranking weights, framework facts,
cache or hook installation belongs to this task.

### Integration findings

- Snapshot resolution previously used fresh per-command timeouts. An optional shared
  execution budget now covers constructor probes and explicit revision resolution.
- Discovery and provenance are bounded in a Linux child process. The parent drains output
  incrementally, checks the deadline, kills a stalled worker and requires a valid receipt;
  exit zero with no result is failure. No project code or engine runs in this child.
- The first real controlled PHP replay found the exact request-to-eval witness but novelty
  was unknown: comparison policy treated another question's context gap as global. The
  owning task 4.1 policy was repaired here with a failing regression first. Only recognized
  boundaries attached to a different recorded question can be ignored for that candidate;
  aggregate coverage retains every gap. Own-question and global boundaries still prevent
  supported novelty. This is policy ownership repair, not a new upstream graph abstraction.
- Artifacts must resolve outside the analyzed repository. The runner refuses a destination
  that could overwrite live source/index/ref state and preserves the real enforcement result.

### Evidence in progress

Initial OFF-state tests: `/tmp/ousast-replay-red.log`, six failures before implementation.
Policy ownership regression: `/tmp/ousast-replay-policy-red.log`, one failure before repair.
Live-source overwrite regression: `/tmp/ousast-replay-review-red.log`, reproduced before repair.
Final validation: 1,236 tests passed, nine skipped; Ruff/format, mypy (112 source files), compileall and all three regression gates passed. Final packaged CLI boot and the controlled positive replay passed. See `benchmarks/measurements/2026-09-13-replay-smoke.json`.


Additional integration repairs retain snapshot omissions in engine change context and distinguish
base questions proven tier zero from unfinished queries. The exact required base question still
must have completed, valid evidence; budget-deferred work still prevents a complete comparison.
RED evidence: `/tmp/ousast-replay-tierzero-red.log` and `/tmp/ousast-replay-snapshot-red.log`.

## Task 5.1 review verdict
- VERDICT: APPROVED
- TASK: 5.1
- MECHANICAL_RESULTS: Full suite exit 0 (1,236 passed, 9 skipped); Ruff/format/mypy/compileall and detection/map/pair gates PASS; no new placeholder markers or secrets; boundary WITHIN; behavioral RED VERIFIED.
- FINDINGS: Integration defects above repaired with regressions; no outstanding task-blocking finding.
- SUMMARY: Manual adversarial review approves bounded local replay; this is not independent review or rollout admission.

## Task 5.1 verification
- STATUS: VERIFIED
- CLAIM_TYPE: TASK
- CLAIM: Explicit local replay traverses the production mapper/ranker/arbiter/comparison/report path and retains uncertainty and shared deadlines.
- EVIDENCE: Final packaged controlled security change yields new/source_connection_absent_from_comparable_base. Fixed twin emits no modeled head finding. The packaged deadline control returns incomplete in 30.785 seconds, within 30 + 2 seconds. Exact final package policy/core/facts/query digests match the workspace. Complete commands and captured raw answers live in the measurement artifact.
- GAPS: Aggregate coverage remains incomplete, real capabilities are disabled, and lab timings do not satisfy the latency gate. Source-mounted fixed and earlier packaged deadline provenance is explicitly separated in the artifact. PMPro/Node transfer is task 5.2, not inferred from a small PHP control.

## Predecessor deadline regression discovered by task 5.2

The first frozen trial completed six CLI invocations, retaining all 11 declared cases.
All three PMPro cases timed out during preparation; both snapshots were fully materialized.
Node hit the engine deadline but then took 34.6–37.4 seconds and could not publish its artifact.
Task 5.2 is blocked pending the owning 3.1/5.1 deadline integration repair and a newly frozen run.
The initial trial overlaps regression testing; it is diagnostic evidence, not the final latency sample.

### Debug report
- ROOT_CAUSE: After an engine timeout, the generic scan driver's failure census reloaded semantic facts and taxonomy for every question. The replay runner then launched an unbudgeted engine-availability subprocess before attempting base comparison. Main-thread stack samples at 30–34 seconds prove both paths.
- CATEGORY: LOGIC_ERROR
- FIX_PLAN: Route failure bookkeeping through the existing driver without loading new semantic facts after a failed build; instantiate the budget-aware Joern backend once rather than running legacy availability probes in replay. Preserve every declared question as deferred and keep ordinary backend selection unchanged outside replay.
- VERIFICATION: Two failing regressions (including 400 declared failed questions), real Node deadline replay, full suite and packaged validation before re-freezing the experiment.
- NEXT_ACTION: RETRY_TASK
- CONFIDENCE: HIGH
- NOTES: This repairs the already-approved generic deadline integration in task 3.1 and replay in 5.1. It changes no detector facts, ranking features or abstract capabilities. No workaround is hidden in the evaluation harness; task 5.2 stays blocked until this contract is repaired. Manual Kiro debug/review fallback applies after the recorded agent thread limit. Runtime trace proves a local logic error; no external dependency/version hypothesis is needed.

RED: `/tmp/ousast-node-deadline-flag-red.log`, two failures with flags OFF. Flags were
removed after GREEN; the focused scope/replay suite passed 30 tests.


The first repair exposed the same repeated fact-read path after evidence planning rather than
build failure. The absolute budget now also reaches `_collect` and `_scope_work`; planning
stops loading facts when time expires but retains the entire question census. No ranking weights,
facts or detector semantics changed. The additional regression failed before repair in
`/tmp/ousast-node-planning-red.log` and then passed.

### Predecessor repair review verdict
- VERDICT: APPROVED
- TASK: 3.1/5.1 deadline integration regression
- MECHANICAL_RESULTS: Full current suite 1,242 passed, nine skipped (including three pending experiment-harness checks), exit 0; Ruff/format/mypy/compileall and all regression gates PASS; behavioral RED VERIFIED; no new placeholders/secrets; scope is the existing driver/deadline integration.
- FINDINGS: Both measured post-deadline paths are repaired, including successful-build/evidence-planning cancellation; all declared questions remain recorded. No outstanding repair blocker.
- SUMMARY: Manual review approves the predecessor repair; task5.2 may resume with a new frozen profile.

### Predecessor repair verification
- STATUS: VERIFIED
- CLAIM_TYPE: FIX
- CLAIM: The reproduced Node cancellation path retains diagnostics and returns within 30 + 2 seconds.
- EVIDENCE: Final packaged real Node replay returned in 30.1255 seconds with one complete diagnostic artifact and incomplete coverage. Final policy/core/facts/query hashes match the workspace. See `benchmarks/measurements/2026-09-13-replay-deadline-repair.json` for initial/partial-repair traces and final raw artifact.
- GAPS: This proves the reproduced cancellation path, not representative warm performance or security coverage. Normal capabilities remain disabled.

## Task 5.2 brief and measurement method

Requirements 6.2–6.5 and 8.1–8.4: execute the prepared PMPro and Node security/fixed/benign
changes through full replay, freeze the core before transfer, retain unresolved populations,
and make an explicit feasibility decision. This task owns the evaluation harness, not new
engine abstractions, framework facts, ranking weights or normal alert eligibility.

The harness freezes the full input population and runtime profile before invoking the CLI.
Authored variants are reproducible commits in a private Git object store, with byte/hash
checks and the rest of each tree retained. The original cache is mounted read-only. All six
cases run under 30 seconds plus a 2-second cancellation/report allowance, with complete CLI
elapsed time measured. Exact artifacts/process exits remain separate from the scorer's
witness association. Empty completed rows cannot manufacture a witnessed negative.

Initial OFF-state evidence: `/tmp/ousast-experiment-red.log`, three failed acceptance tests.
After implementation and flag removal, the same three tests pass, including whole-tree
retention, unchanged source/index, reproducible authored identity, bad-hash refusal,
timeout accounting and absence of fabricated negative evidence.

The first v1 trial is retained as diagnostic history. Its Node post-deadline failures
triggered the predecessor repair above; PMPro measurements overlapped regression tests.
The v2 profile is frozen anew after repair; final timed runs have no competing test/build
workload from this session. Both profiles and their distinct core/policy hashes are retained.
The reserved Ghost workload remains untouched. No framework/fact adaptation or ranking
retune is made from these Node results.

## Final experiment: measured NO-GO

[Joint scorecard](../../../benchmarks/measurements/2026-09-13-first-replay-experiment.json)
records the final v2 profile, all metrics, hardware, exact case identities, initial trial
and final-trial bundle hashes. The two gzip bundles are JSON mappings from each original
filename to its exact UTF-8 contents; decompression was checked against every original file.
They preserve all detailed CLI artifacts, stdout/stderr, pins, profiles and scorer inputs.

| Workload | Cases | Whole CLI elapsed | Reached analysis | Result |
|---|---:|---|---|---|
| PMPro | 3 | 30.61–30.64 s | No; both trees materialized, discovery/preparation expired before change context | Timeout, no completed target check |
| NodeGoat | 3 | 30.55–30.58 s | Driver reached after 7.78–7.96 s preparation; deadline consumed in head analysis/planning | Timeout, 436 deferred questions per case |

All six processes exited 0 (advisory allow), saved artifacts and explicitly reported
incomplete analysis. The harness exited **1 with a completed NO-GO decision**, distinct
from an instrument crash. Both the initial and post-PMPro freeze match each final runtime
and the current workspace's core/facts/query/policy hashes. CPU: Intel Core i7-8700,
four exposed CPUs, 3 GiB container memory limit, network disabled. Tests/builds were not
running during these final measurements. Filesystem caches were not flushed.

The scorer retains all 11 unresolved cases; six were executed and the regression,
unsupported-envelope and reserved populations were not scanned. No security change was
recovered within budget, no witnessed fixed-side negative was established, and no normal
alert was admitted. Precision has denominator zero and is undefined. The two benign
pushes emitted no alert, but an empty registry cannot establish product usefulness.
There are no warm-changed or identical-tip samples. Cold sample p50 is 30.58 s and p95
30.64 s for six one-shot deadline-limited runs; these are not warm latency acceptance evidence.

The negative result points first to preparation/discovery cost for PMPro, before graph
persistence can help that path. Group6 can implement valid reuse, including compatible
preparation work, but must not claim scale from identical-tip hits or bypass the ranker
with another slicer. No new abstract capability or incremental graph mutation is justified
by this measurement. Normal capability qualification remains task8.3.

## Task 5.2 review verdict
- VERDICT: APPROVED
- TASK: 5.2
- MECHANICAL_RESULTS: Full suite 1,242 passed, nine skipped, exit 0; Ruff/format (243 files), mypy (112 source files), compileall and detection/map/pair gates PASS; three behavioral OFF-state failures reproduced before implementation; no new placeholder markers/secrets; evaluation boundary respected.
- FINDINGS: Initial instrument failures repaired in their owning driver/replay integration before the final freeze. All six final runtime provenance records match the frozen profile; scorer replay and complete compressed-artifact round trips reproduce exactly. No outstanding implementation blocker.
- SUMMARY: Manual review approves the executed diagnostic experiment and truthful NO-GO assessment; it does not approve usefulness, warm latency or capability admission.

## Group 5 verification and integration assessment
- STATUS: VERIFIED
- CLAIM_TYPE: TASK
- CLAIM: Tasks5.1–5.2 implement full local replay and execute the first frozen PMPro/Node experiment with truthful evidence, failures, deadline accounting and an explicit feasibility decision.
- EVIDENCE: Controlled security/fixed replay, packaged deadline repair, 1,242 passing tests, fresh static/regression checks, six final real CLI replays, exact frozen runtime hashes and reproducible 11-case scorecard. Task5.2 acceptance requires publishing the actual decision; this decision is NO-GO.
- GAPS: No completed target checks in the 30-second cold workload, no warm measurements, no independent eligibility, and remaining groups6–8. The first usefulness/quality/latency milestone has not passed; the feature is not complete.

Implementation and measurement integration: GO for the scoped work in group5.
Product feasibility and rollout: **NO-GO**. Kiro state is 16/27 tasks verified; group6 next.
