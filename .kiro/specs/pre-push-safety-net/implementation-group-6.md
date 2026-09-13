# Group 6 implementation and verification

The maintainer authorized 6.1–6.4 together on 2026-09-13. A fresh implementer dispatch
failed with `agent thread limit reached`; the explicit kiro-impl manual fallback applies.
Reviews below are main-context adversarial reviews, not independent reviewer evidence.
The design amendment makes measured preparation/discovery costs explicit. Rollout gates
and the empty default capability registry are unchanged.

## Task 6.1 brief

Requirements 4.2, 4.3, 4.4 and 7.3; design: Cache and Engine Boundary.
Backend-owned identities bind readable source paths/bytes, declarations, exclusions,
frontend/engine versions, overlay implementation and options. Complete graphs require a
named source census, methods, calls and the dataflow overlay. Loading checks identity and
streamed graph digest, then issues a disposable copy through the existing CpgResult driver
contract. Old structural manifests without source paths cannot qualify. Sharded or partial
graphs cannot qualify. Query locations normalize to repository-relative paths.

## Status Report
- STATUS: READY_FOR_REVIEW
- TASK: 6.1
- RED_PHASE_OUTPUT: `/tmp/group6-1-red.log` and `/tmp/group6-1-flag-off.log`: four failures before implementation/with the temporary switch OFF. ON passed; switch removed and five final tests passed.
- TESTS_RUN: 105 focused tests passed; full suite 1246 passed, 9 skipped (105.31s), followed by the final additional driver integration test and focused rerun. Ruff and mypy passed.
- EVIDENCE: source-mounted nonroot Docker Joern 4.0.625, network disabled, 3 GiB limit: read 45 JavaScript bytes, census 1 file/4 methods/3 calls, sealed graph loaded through a disposable lease, original digest unchanged after query and cleanup. This is a correctness control, not a latency benchmark.
- CONCERNS: persistent publication and runner selection belong to 6.2–6.4; this task provides the validated backend lease contract. Main-context review fallback.

## Review Verdict
- VERDICT: APPROVED
- TASK: 6.1
- MECHANICAL_RESULTS: focused tests, full regression suite, ruff, mypy and diff whitespace checks passed; no introduced placeholders or secrets.
- FINDINGS: review repaired unbounded full-graph buffering to streamed hashing/copy; unreadable source walks fail explicitly; single PHP graph census passes through unchanged while sharded graphs cannot seal. Existing driver accepts and releases the leased CpgResult.
- SUMMARY: Backend identity and isolated leases satisfy task 6.1 within the approved boundary.

## Verification Result
- STATUS: VERIFIED
- CLAIM_TYPE: TASK
- CLAIM: Task 6.1 identity and lease behavior, not persistent runner reuse or rollout readiness.
- EVIDENCE: tests/test_graph_reuse.py, 105 focused passing tests, full suite and real Joern control above; measurement JSON retained in benchmarks/measurements/2026-09-13-graph-lease-control.json.
- GAPS: Warm push feasibility and independent capability eligibility remain unproven.
