# Group 8 implementation and qualification

The maintainer authorized group 8 on 2026-09-13. Fresh agent dispatch failed with
`agent thread limit reached`; the explicit manual Kiro fallback applies. Reviews
are main-context reviews, not independent reviewer evidence. Joint rollout gates
remain unchanged; implementation progress does not imply capability eligibility.

## Task 8.1 brief

Requirements 1.1–1.4, 2.2, 2.3, 4.2, 4.4, 5.2, 5.5, 7.1, 7.4 and 8.2;
design: Snapshot Adapter, Cache/Engine Boundary, Push runner and Result/Hook Adapter.
Combine immutable non-HEAD/tag/force/new-branch/deletion updates, unusual paths,
external boundaries, physical vendor exclusion, census failure and interrupted report
publication. Use production transaction/backend seams; preserve source/index/refs,
truthful scope and prior artifacts, and prove worker cleanup. Tests only: no production
behavior or feature toggle introduced. Existing focused suites retain the full cache,
missing-base, hook-exit and ordinary-scan regressions.

## Status Report
- STATUS: READY_FOR_REVIEW
- TASK: 8.1
- RED_PHASE_OUTPUT: N/A: tests-only integration coverage; no production behavior changed.
- TESTS_RUN: Three added combined controls pass. Full suite 1299 passed, 9 skipped in 117.83s; ruff, formatting and mypy pass.

## Review Verdict
- VERDICT: APPROVED
- TASK: 8.1
- MECHANICAL_RESULTS: actual new tests inspected, full regression suite passes, no placeholders or secrets; test-only integration boundary maintained.
- FINDINGS: mixed push control verifies all three exact comparisons and four dispositions, readable snapshot bytes, live state preservation and external-content exclusion. Failed census control inspects physically filtered source before returning missing answers. Interrupted writer control checks previous bytes and absence of its process PID.
- SUMMARY: Combined failures remain explicit and do not masquerade as clean checks.

## Verification Result
- STATUS: VERIFIED
- CLAIM_TYPE: TASK
- CLAIM: Task 8.1 integration regression coverage delivered.
- EVIDENCE: `/tmp/group8-1-focused.log`: 3 passed; `/tmp/group8-1-full.log`: 1299 passed, 9 skipped; static checks exit 0.
- GAPS: These controlled failures do not qualify real detector capabilities or representative latency.

## Task 8.2 brief

Requirements 4.1, 4.2, 6.2, 6.3, 6.5 and 7.3; evaluation/runtime integration boundary.
Freeze full pinned NodeGoat histories before measuring: three distinct function edits,
dependency edits, configuration edits, growth histories and multi-ref transactions,
plus three identical-comparison and three uncached controls. Each edit repetition has
a distinct tree, avoiding accidental identical-tip reuse. Retain all 21 transactions,
exact source byte receipt, installed semantics, hardware, selected/deferred counts,
expected target checks, stage process receipts and whole CLI elapsed time. A separate
600-second priming run is diagnostic and cannot replace a 30-second gate sample.

Nearest-rank p50/p95 include timeout durations and report small sample counts explicitly.
A missing artifact or abnormal CLI exit is an instrument error, never a clean result.
Source/vendor/context/coverage gaps remain gaps. NodeGoat remains development data;
this runtime experiment cannot qualify independent alert precision or broad production
performance. Engine lifecycle costs route to contributor-scan's runtime follow-up.

### Task 8.2 measured outcome

Packaged image `af5b896b406fe98acb3d00bb2180a7549febd6dd285f0b63087538118e52e1f4`,
network disabled, UID 1000, 3 GiB memory limit; CPU/affinity and installed identities
are in `benchmarks/measurements/2026-09-13-nodegoat-feasibility.json`. All 21 artifacts
match the frozen core/facts/queries/policy/runtime/semantics. All 24 declared target
checks remain incomplete. Priming took 224.47 seconds and did not qualify graph/answer
reuse; subsequent cache attempts establish discovery reuse only.

| Workload | n | p50 seconds | p95 seconds | Timeouts | Completed target checks |
|---|---:|---:|---:|---:|---:|
| Identical comparison | 3 | 30.635 | 30.644 | 3 | 0/3 |
| Distinct function edits | 3 | 30.611 | 30.663 | 3 | 0/3 |
| Dependency edits | 3 | 30.627 | 30.712 | 3 | 0/3 |
| Configuration edits | 3 | 30.606 | 30.728 | 3 | 0/3 |
| Cold | 3 | 30.609 | 30.631 | 3 | 0/3 |
| Growth | 3 | 30.894 | 30.912 | 3 | 0/3 |
| Multi-ref | 3 | 30.652 | 30.692 | 3 | 0/6 |

These are observed timings of the declared attempts, not proof of a qualified warm
graph path. All timeouts remain in the population. Cancellation/reporting meets the
2-second allowance in these samples; latency and completion do not meet the joint gate.
Runtime and rollout verdict: **NO-GO**. The n=3 quantiles do not establish multi-project
production performance. The full 116-file receipt bundle is 1,254,241 bytes compressed,
SHA-256 `3174bfc0bd39e10b685d06d8bc28ab39450368f1a441e64bbb5a27a256bf13c6`.
Decompression was compared to every original file. Both measured instrument bytes and
the original frozen scorecard are retained; later scorer hardening preserves the
measurements and adds missing-workload and multi-ref-denominator checks.

Owner routing: `../contributor-scan/pre-push-runtime-followup.md` separates raw named
census reconciliation from frontend/overlay/JVM/query lifecycle optimization. Do not
retune the ranker or weaken the population/gates to compensate.

## Status Report
- STATUS: READY_FOR_REVIEW
- TASK: 8.2
- RED_PHASE_OUTPUT: `/tmp/group8-2-red.log` (missing scorer) and `/tmp/group8-2-flag-off.log` (disabled scorer). ON passed; switch removed, seven final scorer tests passed.
- TESTS_RUN: full suite 1306 passed, 9 skipped in 117.63s; ruff, formatting, mypy and diff checks pass. Frozen packaged measurement completed with exit 1 and full NO-GO scorecard, no missing artifacts or abnormal CLI exits.

## Review Verdict
- VERDICT: APPROVED
- TASK: 8.2
- MECHANICAL_RESULTS: actual harness, fixtures, scorecard and receipt bundle reviewed. Input bytes/pins, distinct edit histories, all 21 runs, stage exits, fixed target denominators and source/runtime identity checks retained. Invalid numbers, duplicate/unplanned rows, missing workload classes and missing cases cannot qualify runtime. No production/ranker/fact changes.
- FINDINGS: Initial warm-graph precondition failed; the report explicitly limits reuse claims. The unchanged runtime gates fail. Engine lifecycle and named census follow-up routed to contributor-scan.
- RED phase: VERIFIED.
- SUMMARY: Reproducible runtime evaluation is complete with a measured NO-GO result.

## Verification Result
- STATUS: VERIFIED
- CLAIM_TYPE: TASK
- CLAIM: Task 8.2 completed its prescribed measurement and owner routing; rollout remains NO-GO.
- EVIDENCE: Versioned scorecard and 116-file verified bundle; seven scorer controls and full regression suite pass.
- GAPS: No qualified warm graph path or independent capability eligibility established. These failed gates cannot authorize rollout.

## Task 8.3 brief

Requirements 3.1, 3.2, 6.1–6.5 and 8.1–8.4; evaluation and actionability integration.
Implement a trusted installed eligibility resource whose evidence is recomputed against
exact core/engine/runtime/facts/query/policy/semantic identities. Require reviewed
operation/advice scope, vulnerable/fixed/benign populations, nonzero actual positive
controls and reviewed alerts, untouched per-capability evaluation and all joint gates.
The normal runner consumes only eligible declarations; stale or inconsistent resources
admit nothing. This is integrity checking of trusted release evidence, not signing or
permission to load repository-authored eligibility.

Freeze the current packaged candidate before the six PMPro/Node development replays.
Run readable VAmPI regression snapshots under a separate 600-second laboratory profile;
keep their missing independent pairs unresolved. Execute libpng as an unsupported
30-second envelope control. Do not inspect or tune on Ghost before its reviewed
population exists. Missing required evidence leaves task 8.3 qualification blocked,
even when the reproducible NO-GO artifact and admission implementation are delivered.

### Review scope

Synthetic controls prove that a matching reviewed population can reach the real runner
admission seam, while stale facts/runtime, missing positive observations, absent reviews,
wrong untouched workloads and changed consequence/repair semantics cannot. They are
contract controls, not real capability qualification. The installed NO-GO resource must
recompute identically and enable zero capabilities. The source has no repository- or
language-specific rank changes, frontend adaptations or new abstract domains.

### Task 8.3 measured outcome

Packaged candidate `9464e229ccfdc873a02e3a0db7c1e83a6d6ec6d3e8234ae7b97677b4aed836fd`
executed offline as UID 1000 with a 3 GiB memory limit. Each profile was written before
its runs. All six development pushes saved artifacts, timed out in 30.559–30.678s and
retained all 11 declared cases. Source snapshot receipts read 57.9–58.1 MB per PMPro
comparison and 5.95 MB per Node comparison. These are snapshot bytes, not graph census.
The supported introducing-change recall is 0/2, Wilson 95% interval [0, 0.658]; actual
reviewed alert precision is undefined (0/0), never 100%. Neither fixed case has a
completed witnessed negative. The two benign pushes emitted no alerts; that silence
with incomplete coverage does not establish a useful safety net.

VAmPI's 600-second laboratory profile executed all three pinned regression targets,
reading 139,164 snapshot bytes per replay. First run 112.415s; subsequent identical
comparisons 6.816s and 6.684s, each with two graph hits and 403 query hits. Raw findings
retain the known SQLI and two authorization sites, but the SQLI exact function question
is unlocated and authorization questions are `change_context_incomplete`. All three
remain unresolved; no transitive witness or completed regression detection is credited.
There are 138 selected and 20 deferred head questions. Context/witness normalization
is routed to the shared scan owner. A registry-generation provenance probe overlapped
startup of the first lab run; these timings are diagnostic, not runtime-gate samples.

The initial instrument labeled all regression replays cold. The two proved identical
cache replays were relabeled `identical_tip` and rescored without changing measurements,
profile or population; original run/scorecard/instrument and correction are retained.
Future instrument output distinguishes these identical comparisons. None is a warm edit.

The libpng unsupported envelope saved a partial artifact after 30.590s. Ghost's checkout
and reviewed independent cases remain missing and were not scanned. Independent PHP
and Python admission populations also remain missing. No ranker, fact, adapter or query
retune occurred. The 59-file compressed evidence bundle is verified against originals:
`benchmarks/measurements/2026-09-13-push-qualification.json.gz`, SHA-256
`79226b4e54042559ba5cc2b94b69b1dcddb550872fd0783b2380368be72f90bd`.

The installed eligibility resource is reproducible NO-GO, digest
`2ddd94d4dc3fd6b84e7de38e5f211d2653fb993c64e4e43cedf7e06062c3265c`, with zero enabled
capabilities. Task 8.2 runtime evidence remains failed and predates the eligibility
policy addition; it is correctly rejected as admission evidence, not relabeled current.

## Status Report
- STATUS: BLOCKED
- TASK: 8.3
- RED_PHASE_OUTPUT: `/tmp/group8-3-red.log`: eight failures with eligibility disabled; ON passed, switch removed; final synthetic and installed-resource contracts verified separately.
- IMPLEMENTED: Versioned eligibility generation/loading, production admission integration, real offline replay and NO-GO artifact.
- BLOCKER: Required independent Node/PHP/Python reviewed populations and verified VAmPI transitive question witness are absent. Runtime/completion gates fail.

## Review Verdict
- VERDICT: REJECTED
- TASK: 8.3 completion claim
- MECHANICAL_RESULTS: Eligibility and runner implementation inspected; fixed semantic/advice scope, observed controls and exact provenance required. No language-specific ranker changes, placeholders or secrets. RED phase verified.
- FINDINGS: Implementation and reproducible NO-GO decision are concrete, but task 8.3's mandatory independent transfer and transitive-regression evidence is not established. Main-context fallback does not provide independent review.
- REMEDIATION: Repair the shared context/witness and census/runtime prerequisites; obtain reviewed untouched paired populations, refreeze and rerun all joint gates. Keep capabilities disabled meanwhile.
- SUMMARY: Retain the useful implementation, leave task 8.3 unchecked and feature rollout NO-GO.

## Verification Result
- STATUS: NOT_VERIFIED
- CLAIM_TYPE: TASK
- CLAIM: Full task 8.3 qualification complete.
- EVIDENCE: Real frozen replay and installed decision explicitly preserve failed gates and missing evidence.
- GAPS: Independent populations, completed positive/fixed controls, VAmPI transitive witness and representative runtime/coverage.
- NOTES: Proceed with authorized task 8.4's explicit NO-GO acceptance reconciliation; it does not depend on pretending qualification passed.

Task 8.3 implementation verification: full suite **1317 passed, 9 skipped in 115.80s**
(`/tmp/group8-3-complete-suite.log`, exit 0). After the measurement-label correction,
14 focused eligibility/replay-instrument tests passed in 0.95s. Ruff, format, mypy
(116 source files) and diff checks pass. These verify the delivered code and recorded
NO-GO behavior, not the rejected full qualification claim above.
