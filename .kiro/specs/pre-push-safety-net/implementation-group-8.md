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
