# Group 3 implementation verification

Date: 2026-09-13. Scope: tasks 3.1–3.4. The maintainer authorized continuing this
group after the group 2 completion and next-step summary. Tasks remain unchecked
until independent review and fresh verification establish their completion.

## Boundary

This group integrates the existing backend and ranker with generic execution,
change-context and scope contracts. It does not implement new detector semantics,
alert admission, persistent caching, or hook installation. Equivalent normalized
PHP and JavaScript evidence must retain equivalent core decisions. Vendor sources
must remain outside both graph inputs and targets; missing external semantics are
coverage limits.

## Verification state

Implementation is in progress. No group-level completion claim is made yet.

## Baseline

Groups 1 and 2 completed at commit `948ee02`; the working tree was clean before
this group began. The prior final suite recorded 1,069 passing and nine skipped
tests. Three pre-existing mypy diagnostics concerned reuse of `candidates` in
`model/scan.py`; fresh checks will report whether they remain.

Historical Joern query failures cannot be declared resolved merely because a
bounded failure returns promptly. Runtime smoke establishes readable source,
nonempty graph census and query payloads for its declared small fixtures. It does
not establish full-workload detection, actionable precision or hook latency.

## Task 3.1 evidence

The backend accepts an optional generic `ExecutionBudget`. Each build binds an
independent session to its graph callbacks; probes, builds, overlays, census,
queries and retries consume the same remaining time. Process startup also counts.
A timed-out stage prevents further retries. The budgeted process path kills the
original process group even after its launcher exits, bounds reaping and owned
scratch cleanup, and exposes incomplete cleanup explicitly. The driver releases
graph ownership on exceptions as well as normal return. Legacy backends cannot
silently discard a supplied deadline; optional unbounded judge calls are withheld
with an explicit reason. Ordinary scans retain their existing budget behavior.

`benchmarks/measurements/2026-09-13-engine-budget-smoke.json` records the locally
rebuilt non-root image and exact packaged backend/driver hashes. Under one
900-second lab budget, native PHP read 45 source bytes and JavaScript read 48;
both produced populated graphs, dataflow overlays and exact source-node witnesses.
Unreadable PHP source was explicitly refused. PHP took 73.620 seconds and JavaScript
34.756 seconds in this small smoke; these are runtime checks, not hook latency.

An independent controlled process probe read its 241-byte input script, launched
a parent and child ignoring SIGTERM, and observed termination in 0.804 seconds
under a 0.8-second deadline plus 0.8-second cancellation allowance. Signal delivery
may briefly leave a child visible immediately after return; the probe polls only
within the original allowance. Zombies count as terminated, not running descendants.
Concrete reusable graph leases and persisted completion records remain later tasks.

The three former mypy errors were resolved by renaming the evidence-region list
inside the driver; this does not change the ranker. Global mypy now checks all
108 source files successfully. Independent review APPROVED task 3.1. Its fresh final suite passed: 1,089 tests,
nine skipped, 96.85 seconds; global Ruff, formatting (219 files), mypy and diff
checks passed. Verification status: VERIFIED, claim type TASK. This completes
8/27 tasks; tasks 3.2–3.4 remain in progress for this group.

## Task 3.2 evidence

Independent review APPROVED; verification status VERIFIED, claim type TASK.
The fresh reviewer suite passed 1,105 tests with nine skipped in 101.18 seconds.
Global Ruff, formatting (221 files), mypy (108 source files) and diff checks passed.
The reviewer also exercised 24 combinations of order, budget and failed query
families, retaining all 12 declared questions and reconciling coverage totals.

The driver accepts explicit `ranking_mode`, `unit` and `population_complete` while
preserving ordinary defaults. Scope and execution requests are produced together
from the existing ranker's final order. Selected/deferred identities, normalized
evidence, unchanged tier/score, per-question outcomes and per-family completion
travel to the CLI directly. Missing evidence stays unknown. Partial graphs cannot
justify tier-zero pruning or completed coverage. Raw query answers survive a later
timeout even when arbitration cannot complete. A completed outcome denotes query
and arbitration completion within the modeled boundary, not a safety assertion.

`benchmarks/measurements/2026-09-13-ranker-scope-smoke.json` records a rebuilt image
whose backend, driver, contracts and CLI hashes match the source. Real PHP (78 bytes)
and JavaScript (69 bytes) fixtures each selected `risky` over the initially higher
static-ranked `safe`. Both selected questions had tier 4 and score 2.5; execution
outcome IDs matched selection, and each family reported one selected/completed,
one deferred and zero unanswered questions. Each produced one controlled finding.
PHP took 61.57 seconds and JavaScript 51.27 seconds under one 900-second lab budget.
This manually declared entry-region smoke does not validate mapper discovery,
PMPro/NodeGoat replay, capability admission or hook latency.

Nine of 27 tasks are now complete; tasks 3.3–3.4 remain for this group.

## Task 3.3 evidence

Independent review APPROVED after one required repair; verification status VERIFIED,
claim type TASK. The fresh reviewer suite passed 1,128 tests, nine skipped, in
105.95 seconds. Global Ruff, formatting (224 files), mypy (108 source files) and
diff checks passed. The context suite contains 23 focused cases.

The generic driver accepts `change_context` and retains its enriched form. Existing
taint evidence optionally projects full first-party method paths/ranges for entry,
callee, same-file field, known hook and sanitizer context. Decoded snapshot changes
and lexical anchors attach to exact questions without changing ranking weights or
introducing another scope selector. Missing base, locations, empty projections,
dynamic/external/depth dependencies and unsupported configuration/deleted-dependency
projections remain explicit gaps. Missing context prevents tier-zero pruning and
complete-negative outcomes; raw answers remain available.

Review found that broad source/sink/sanitizer text matching could mistakenly exempt
an unknown consumer such as `unknown(req.body)` from missing-context reporting.
The production-query regression reproduced exit 1 with that question incorrectly
pruned as tier zero. The task-local repair restricts the exemption to directly
invoked fact-modeled operations. Existing detector matchers are unchanged. After
repair, consumers of a source, nested sink and sanitizer name all remain unresolved;
a direct modeled sink completes, and the direct sanitizer retains tier zero without
a false context gap.

`benchmarks/measurements/2026-09-13-change-context-smoke.json` retains the final image
and matching backend/driver/regions/snapshot/query hashes, plus both runtime checks.
Real Git histories remove a caller guard while keeping helper code unchanged. PHP
reads 124 source bytes and reaches `helper.php:2:helper` in 63.48 seconds; JavaScript
reads 133 bytes and reaches `helper.js:1:helper` through an ES-module import in
39.63 seconds. Both preserve the dirty checkout/index and remove snapshot scratch.
These are controlled change-to-question/witness checks, not proof that the removed
line enforced security, that the defect is new, or that a hook meets its latency bar.

Ten of 27 tasks are now complete; task 3.4 remains for this group.
