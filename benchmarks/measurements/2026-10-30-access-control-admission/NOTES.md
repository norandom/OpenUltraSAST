# Access-control prover admission measurement (Task 13.4)

First admission run of the amended access-control prover arm on the untouched pilot
population, consumed through the reviewed `valid-detection-benchmark` manifest. Result:
**NO-GO** — the development score does not generalize to the admission population.

## What ran

| Input | Value |
|---|---|
| Admission manifest | `manifest.json` (this directory), consumed and validated by `benchmarks/valid/admission_run.py` |
| Analyzer revision | `d063167b28ed7db2335737fdb0dae0555225ea85` (HEAD at freeze) |
| Fact set | 18 ruleset TOMLs, manifest digest `e7db4031d3d5` (unchanged since the 2026-10-30 four-arm run), bundle artifact digest `3eb5bf699434` |
| Configuration | `(arm=access-control-admission, judgment_mode=strict)`, digest `095b5a4905ad` |
| Population | `benchmarks/valid/pilot/pool-valid.toml`, freeze digest `c866c0e812c0`, held-out guard 0, labels 31 confirmed / 0 unchecked |
| Population contents | 12 repositories, 252 changes (12 vulnerability twins + 240 reviewed ordinary) |
| Isolation | No pilot repository referenced by any fact artifact (verified at freeze); facts trace to pool-train clones and approved documentation only |
| Criteria | Pre-registered in `criteria.json` BEFORE the run: min_fix_recall 0.5, min_pair_correctness 0.5, min_verified_location_recall 0.5, min_precision 0.25, max_flagged_ordinary_per_100 10.0, max_indeterminate_rate 0.5 |

The freeze script verified facts-on-disk == facts-at-HEAD, re-derived the pool freeze
digest, checked the held-out guard, proved isolation, materialised the bundle and wrote
the manifest and criteria before any prover execution (Req 12.1 ordering).

## Result

| Metric | Value |
|---|---|
| Decision | **NO-GO** |
| Failed gates | `min_fix_recall: 0.0 < 0.5`, `min_pair_correctness: 0.0 < 0.5`, `min_precision: 0.0 < 0.25`, `min_verified_location_recall: not measured (n=0)` |
| Pairs | n=12, correct=0 |
| fix_recall | 0/12 (Wilson95 0.0-0.243) |
| flagged_ordinary_per_100 | 2/240 = 0.83 (Wilson95 0.23-2.99) |
| precision | 0/14 |
| indeterminate_rate | 3/264 sides = 1.1% (Wilson95 0.4-3.3) — the three fixed-side locator misses below |
| coverage | 4/12 repositories (0.333) |
| runtime | mean 2.8s, max 7.1s per pair; max ordinary change 7.7s (every change budget-gated at 120s, gate passed) |
| instrument failures | 0 (all 264 records prove nonzero input reads) |

Fixed-side twin protocol: 9 of 12 labelled functions were located by name at the fix
revision (e.g. dbhub `scanTokenMySQL` shifts from lines 135-143 vulnerable to 158-165
fixed); the remaining 3 are **locator misses** — the function name is still present at
the fix but the declaration scan cannot name it (md-editor `fenceGroup`, i18next
`extendOptionsWithDefaults`, webpack `chartData`, as const-arrows/getters/import-moved
syntax). Locator misses score `indeterminate` on the fixed side and are never converted
to clean results (design.md:371); a function genuinely absent from the fixed revision
would count as quiet ("removed"). No pair was affected: all 3 fixed records carry empty
evidence and the vulnerable sides were not detected.

## Reading

The zero is a **recognition failure, not a judgment failure**. On 9 of 12 repositories
the prover recognized no framework at the vulnerable sites, and every vulnerable-side
judgment funnel came back all-zero: no obligation pair was ever formed, so no guard
evidence and no unguarded evidence existed. Under the pair vocabulary these sites score
as completed-quiet ("discharged" per the documented quiet-or-discharged mapping, Req
12.5); the indeterminate rate of 1.1% counts exactly the three fixed-side locator
misses — nothing on the vulnerable side was incomplete; the engine simply had no
knowledge to apply. The obligation facts were promoted from pool-train
clones (Jenkins/Stapler-shaped Java, plus Spring/Servlet documentation); the admission
population is TypeScript/JavaScript/Python MCP-and-web ecosystems. Four repositories
had any recognition at all (fastapi-users 117, malla 161, jupyterlab-lsp 10 framework
hits, gitlab-mcp 2 on ordinary changes only); none produced a site finding.

The false-alarm side improved against development (0.83 vs 5.2 flagged/100) and the
budget gate passed everywhere (max 7.1s vs 120s), but with zero recall the arm cannot
enter pre-push admission. This is exactly the generalisation check Requirement 12
exists to force: the development evidence (recall 34.8% on pool-train) does not
transfer to untouched repositories.

## Verification

- Instrument: 264/264 records carry nonzero `hook_bytes_read`; zero zero-byte reads;
  0 instrument failures; `status=prover_covered` everywhere.
- Determinism: 4/4 spot re-proofs (2 vulnerable sites + 2 ordinary) byte-identical on
  findings, funnel, status and read counts; the independent reviewer re-proved 4/4
  more, including both flagged ordinary records.
- Unit tests: 24/24 (`tests/test_admission_run.py`). Statics: ruff check, format,
  C901 and mypy (6-file anchor set) all exit 0.
- Keyword regression (handover-documented expression): 682 passed + 2 skipped, exit 0.
  The full suite still fails `test_no_reserved_repository_is_referenced_by_the_development_tree`
  — a pre-existing clean-HEAD failure from committed 2026-10-12 artifacts, documented
  at the 2026-10-30 four-arm run and outside this task's boundary.
- Boundary: no fact, strategy or threshold file was modified (`git status` shows only
  this measurement directory plus the runner and its tests).

## Corrections (round-1 review)

The first review round rejected the task on two points, both remediated:

1. The fixed-side protocol mapped every locator miss to `fixed_operation="removed"`
   and thence to a clean `discharged` judgment — an inflationary path that contradicts
   design.md:371. Remediated by the three-state protocol (located / missed / removed,
   `classify_fixed_site`), with locator misses scored `indeterminate`. All 12 fixed
   sides were re-proved under the new stamps (19s); the three misses are disclosed
   above and the report was re-assembled from the resumable records.
2. Ordinary changes are now individually budget-gated (design.md:370), and the
   regression count was re-measured under the documented keyword expression.

No measurement number changed except `indeterminate_rate` (0 -> 3/264, the honest
locator-miss accounting); the decision remains NO-GO on the same four gates.

## Reproduction

Records: `~/ousast-results/prover/ac-admission-1/{vulnerable,fixed,ordinary}/<change-id>.json`
(resumable by input digest; `population_digest` on every record is the authoritative
freeze digest `c866c0e812c0`).

```sh
.venv/bin/python /tmp/opencode/freeze_134.py        # verify + author manifest + criteria
.venv/bin/python /tmp/opencode/run_134.py           # prove population, write report.json
.venv/bin/python /tmp/opencode/determinism_134.py   # 4/4 reproducibility spot-check
```

The run is resumable: re-running `run_134.py` after the round-1 protocol fix reused
the 252 unchanged records and re-proved only the 12 fixed sides.

Smoke trail: `/tmp/opencode/smoke_134.py` proved one twin pair end-to-end before the
full run (fixed-side function located at shifted lines by name, e.g. dbhub
`scanTokenMySQL` 135-143 vulnerable vs 158-165 fixed).
