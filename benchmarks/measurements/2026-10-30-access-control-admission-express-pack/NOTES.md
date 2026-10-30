# Admission with the express entry pack (detection-core 8.2 gate, 2026-10-30)

Second admission run of the access-control arm on the untouched pilot population, with
the recognition workstream active: the express entry fact pack (inside the frozen fact
digest) plus the JS handler-extraction fix (bind(this)/arrow/class methods).

## What ran

| Input | Value |
|---|---|
| Analyzer revision | a8a28f8 (benchmark plumbing at 6024152; analyzer code identical) |
| Fact set | 19 artifacts (18 ruleset TOMLs + entries/express.json), digest 1433214dd34e, bundle 124871987a06 |
| Configuration | (arm=access-control-admission, judgment_mode=strict, entry_pack=express), digest 06e9304ee277 |
| Population | unchanged pilot pool, freeze c866c0e812c0, guard 0 |
| Criteria | identical to the 2026-10-30 run (copied verbatim before the run) |
| Records | 264 fresh proofs in ~/ousast-results/prover/ac-admission-2 (266s, 0 instrument failures) |

## Result: NO-GO — recognition doubled, recall unchanged

| Metric | 2026-10-30 (before) | this run |
|---|---|---|
| Decision | NO-GO | **NO-GO** (same four gates failed) |
| fix_recall | 0/12 | 0/12 |
| coverage (repos recognized) | 4/12 = 0.333 | **8/12 = 0.667** |
| dbhub frameworks | 0 | 20 |
| matrix frameworks | 0 | 4 |
| ckan frameworks | 0 | 11 |
| webpack frameworks | 0 | 10 |
| gitlab-mcp frameworks | 2 | 34 |
| flagged ordinary / precision | 2/240, 0/14 | 2/240, 0/14 |
| instrument failures | 0 | 0 |

## Reading

The recognition lever moved exactly what it claimed: framework recognition on the
express-family repos went from zero to double digits, coverage doubled. It was necessary
but not sufficient: with entries recognized, the vulnerable sides still produce zero
judged pairs — the funnel is all-zero because no obligation pairs form at those entries.
The next bottleneck in the pre-registered ordering (recognition -> resolution -> judgment)
is **operation facts and call resolution for the express/TS handler shapes**.

## Stop condition fired

This is the **second consecutive admission NO-GO** for this arm against the same
pre-registered criteria (detection-quality.md rule 10). Per the pre-registered stop
conditions the arm is **parked**: no third incremental fix round. The next step is a
maintainer strategy review; the recorded fallback (rule 11) is the narrowed
one-ecosystem advisory product plus proof-based BLOCK.

Task 8.2's done-when (a pack passing admission gates) is **not met**; the gate ran and
refused. The task stays open with this run as its outcome.

## Reproduction

```sh
.venv/bin/python /tmp/opencode/freeze_82gate.py   # verify facts/pool, author manifest+criteria
.venv/bin/python /tmp/opencode/run_82gate.py      # 264 proofs -> report.json
.venv/bin/python /tmp/opencode/compare_82.py      # per-repo before/after table
```
