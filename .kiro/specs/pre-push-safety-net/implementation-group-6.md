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

## Task 6.2 brief and review

Requirements 4.1, 4.3, 4.4 and 7.3; design: Cache and Engine Boundary. Private
0700 cache roots, 0600 files, fixed lock stripes plus a publication lock, streamed payload
digests, manifest receipts, atomic completed directory publication and size accounting
(payload plus manifests) implement local storage. Incomplete data is never published as
complete. A lookup holds a shared lease; eviction requires an exclusive lock and skips
leased entries. Abandoned private partials count toward the limit and can be reclaimed.
All lock waits and copying check the caller's absolute deadline; cleanup uses its allowance.
No graph node mutation, executable deserialization or repository writes are introduced.

## Status Report
- STATUS: READY_FOR_REVIEW
- TASK: 6.2
- RED_PHASE_OUTPUT: `/tmp/group6-2-red.log`: seven tests failed with the temporary cache switch OFF. ON passed; switch removed; nine final cache tests passed.
- TESTS_RUN: 13 cache/audit tests passed, full suite 1256 passed and 9 skipped (104.11s); ruff and mypy passed. Final receipt-validation repair was followed by the 13-test focused rerun.
- EVIDENCE: concurrent subprocess writers, corrupted payload/manifest, interrupted atomic replace, abandoned partial files, bounded lock contention, leased eviction, unsafe paths and preservation of consumer exceptions.

## Review Verdict
- VERDICT: APPROVED
- TASK: 6.2
- MECHANICAL_RESULTS: canonical suite and final focused regression passed; static checks and diff whitespace passed; no new placeholders or secrets.
- FINDINGS: review added metadata receipt validation and fixed contextmanager exception ownership; lock inodes are retained in 64 bounded stripes to avoid unlink/recreate races. Storage size means bytes of payloads/manifests, not filesystem allocation overhead.
- SUMMARY: Complete publication or explicit miss is preserved through tested concurrency, corruption and interruption paths.

## Verification Result
- STATUS: VERIFIED
- CLAIM_TYPE: TASK
- CLAIM: Task 6.2 bounded local artifact publication and eviction.
- EVIDENCE: nine cache contract tests and full suite above; production cache implementation, not a mocked storage path.
- GAPS: Semantic keys and live replay integration follow in 6.3 and 6.4; no warm-latency claim.

## Task 6.3 brief

Requirements 3.4, 4.3, 4.4, 6.4, 7.2 and 7.3; design: Cache and Engine Boundary
and Admission Policy. Query keys include graph, actual question parameters/context/depth,
facts/sanitizers, query versions and configuration. Comparison/final keys additionally bind
ranking, admission, optional model/prompt, eligibility and mode; comparisons include both
revisions and actual completed evidence. Ranking-only changes preserve query keys.

Comparison reuse is integrated into the existing policy entry point. Only complete, comparable
evidence can populate/look up comparisons. Unknown outcomes never qualify. Loaded CandidateDelta
contracts must match revision and semantics ownership. Current admission still runs afterwards;
the cache never confers eligibility. JSON decoding is non-executable and bounded to 32 MiB.

## Status Report
- STATUS: READY_FOR_REVIEW
- TASK: 6.3
- RED_PHASE_OUTPUT: `/tmp/group6-3-red.log`: two failing semantic-key tests with switch OFF; `/tmp/group6-3-policy-red.log`: missing policy cache integration failed. Enabled implementation passed; switch removed.
- TESTS_RUN: 71 focused policy/admission/cache tests passed; full suite 1260 passed, 9 skipped in 103.17s. Final ruff, formatting and mypy passed.
- EVIDENCE: real on-disk comparison hit returns identical supported delta; policy/revision changes miss; unanswered comparisons do not populate complete entries; exhaustive key-dimension and final-scope invalidation tests.

## Review Verdict
- VERDICT: APPROVED
- TASK: 6.3
- MECHANICAL_RESULTS: full regression suite, 71 focused tests, static checks and whitespace checks passed; no new placeholders or secrets.
- FINDINGS: cache does not store or replay push permission. Comparison data remains separate from current admission. Query reuse deliberately ignores ranking-only/mode changes, whereas comparison/final keys include them. Decoder and deadline checks were tightened during review.
- SUMMARY: Semantic identities preserve compatible evidence without transferring obsolete policy eligibility.

## Verification Result
- STATUS: VERIFIED
- CLAIM_TYPE: TASK
- CLAIM: Task 6.3 semantic keys and completed comparison evidence reuse.
- EVIDENCE: production policy integration and cache key tests, 1260 passing suite tests and final static checks.
- GAPS: Graph/query/preparation reuse must still be connected to replay under 6.4; no rollout claim.
