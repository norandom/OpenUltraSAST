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
