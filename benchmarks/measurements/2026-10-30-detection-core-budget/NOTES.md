# Measured budget derivation (detection-core task 2.2, 2026-10-30)

The static 120s gate was replaced by per-workload-class budgets derived from
measurement. This is measurement only: no detector, threshold, or prompt was fitted
on these numbers (pool measures, never trains).

## Result

| class | n | max | over static 120s | p90 | p95 | p99 |
|---|---|---|---|---|---|---|
| dev-pool (four-arm cacfon records) | 483 | 240.0s | 20 | 61.4s | **88.7s** | 210.0s |
| admission-pilot (264 records) | 264 | 7.7s | 0 | 2.6s | **3.2s** | 3.8s |

(derivation.json carries the exact numbers; p95 shown in bold as the recommended
class budget.)

## Reading

One static constant cannot serve both classes: 120s over-fails the dev pool (20/483
overruns, max 240s) while being ~37x the pilot's p95 (3.2s). Per-class measured budgets
fix both directions. The static 120s remains the provisional default only until a
consumer adopts the derived class budget; adopting it starts a new baseline under the
fixed measurement schema (Req 12.2).

## Method

Complexity features (regions = changed files, calls = resolution-bucket total,
changed_bytes = instrumented changed bytes) and seconds come from the existing
record sets; budget = linear-interpolated percentile of measured seconds per class,
with n, percentile, and hardware disclosed in `derivation.json`. Hardware:
local dev host, records of 2026-10-30.

Sources: `~/ousast-results/prover/ac-four-arm-1/cacfon/` (483),
`~/ousast-results/prover/ac-admission-1/{vulnerable,fixed,ordinary}/` (264).
Script: `/tmp/opencode/derive_budget_2.py`.
