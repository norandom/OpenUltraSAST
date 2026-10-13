# Both arms over the frozen access-control training pool, one run each (2026-10-13/14)

## Setup

- **Pool:** `benchmarks/valid/train/pool-train.toml`, digest 53f9f364. 5 fix pushes with 48 verified locations
  (reviewer mc, all accepted), 100 ordinary pushes, 20 per fix, from the same 5 repositories: three Jenkins plugins
  (Java), shopper (PHP), trigger.dev (TypeScript).
- **Arm DSPy:** `python -m openultrasast.hunt.cli run`, the baseline instruction, every annotation on, ReAct over the
  repository tools, `--max-iters 8`, own empty response cache. Program id e79db45f. The producers were version 1
  (before 537b61e): the hunks annotation did not show where a push removed lines.
- **Arm hunter:** `benchmarks/valid/hunter_arm.py`, classifier on, as in the pilot.
- **Runs:** DSPy 21:39 to 00:29, hunter 00:29 to 01:08, one after the other on the training clones.
- **Analysis:** `analyse.py` in this folder; a push is caught when any verified location of its fix is caught
  (`benchmarks.unseen.score.catches` on the per-location view, as `benchmarks/valid/metrics.py` scores), a location
  when its own view is caught. Instrument failures and unparsed hunts stay in the denominators.
  `benchmarks.valid.metrics` refused the DSPy run (more than 5% instrument failures); `metrics_hunter.json` is its
  output for the hunter arm.

## Results

| | DSPy baseline | Pilot hunter |
|---|---|---|
| Pushes caught | 2 of 5 (Wilson 12-77%) | 2 of 5 (Wilson 12-77%) |
| Locations caught | 4 of 48 (Wilson 3-20%) | 4 of 48 (Wilson 3-20%) |
| Per repository (locations) | dependency-track 0/3, job-import 2/2, p4 2/5, shopper 0/31, trigger.dev 0/7 | dependency-track 2/3, job-import 0/2, p4 0/5, shopper 2/31, trigger.dev 0/7 |
| Ordinary pushes flagged | 14 of 90 scanned = 15.6 per 100 (Wilson 9-24) | 99 of 100 = 99 per 100 (Wilson 95-100) |
| Suspicions raised, true | 25, 3 true (12%) | 594, 3 true (0.5%) |
| Instrument failures | 11 of 105 (10.5%), all `LMInvalidRequestError` | 0 |
| Unparseable final answer / loop step | 2 / 12 (the loop fix of 455637b kept those 12 hunts) | 0 / 0 |
| Cost | $6.13 at the registered deepseek-flash prices: 28.9M prompt tokens (61% cached), 0.70M completion | engine only |

- **The two arms catch different pushes.** DSPy: job-import and p4. Hunter: dependency-track and shopper. Together
  4 of 5; nothing in trigger.dev from either. Every true suspicion of both arms is in the access_control family.
- **The pilot hunter is not a hook on this pool.** It flags 99 of 100 ordinary pushes with 594 findings, 3 of them
  true. 348 of its findings carry the family `unknown`.
- **The DSPy baseline is far quieter** (25 suspicions, 15.6 flagged ordinary pushes per 100) at the same recall, but
  its 11 failed hunts sit entirely in shopper and trigger.dev, the two repositories where 38 of the 48 locations
  are. The exception class is `LMInvalidRequestError`, not its subclass `ContextWindowExceededError`, so the
  request was rejected for another reason; the message is never recorded (it can carry a key), so the next check
  is one re-run of a failed change that records the provider's error code field only.
- **Nothing here is a comparison with intervals that separate the arms**: 5 positive pushes. The location-level
  numbers (48) are the ones to read, and they say both arms miss more than 90% of the verified locations of this
  class.

## Instrument findings recorded along the way

- `--budget-usd` did not stop the DSPy run at 5 dollars: the runner booked 0.0 per change. Fixed after this run
  (the ledger now prices every LM call of the change at the registered prices; the record carries `usd`).
- The diff producer the model saw was blind to removed lines (537b61e); the hunter arm did not undo the sparse
  checkout of training clones (c01e61c, fixed before it ran); an empty product file failed the source producer on
  every row of a change (fcb43fd). See `benchmarks/measurements/2026-10-13-access-control-screen/NOTES.md`.

## Files

- `analysis.json`: the numbers above, per arm.
- `suspicions.jsonl`: every suspicion of both arms with repo, push, path, line, family, confidence and a
  true/false label against the verified locations (619 rows, 6 true).
- `metrics_hunter.json`: `benchmarks.valid.metrics` for the hunter arm.
- Raw records: `~/ousast-results/hunt/ac-train/{dspy-1,hunter-1}` (not in the repository).
