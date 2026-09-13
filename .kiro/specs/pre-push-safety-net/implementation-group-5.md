# Implementation verification: group 5

Group 5 was authorized by the maintainer's “approved” after group 4 completion.
Task 5.1 is verified complete (15/27 total); task 5.2 is next.
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
