# Access-control prover arm -- training pool (gate 1)

Date: 2026-10-28. Roadmap: `.kiro/steering/roadmap.md`, "measure the trace first", gate 1.

## Setup

- Arm: `benchmarks/valid/prover_arm.py`, deterministic trace + dominance check. No model
  calls, no API key, no fitted components.
- Pool: `benchmarks/valid/train/pool-train.toml` (frozen 2026-10-14 09:31, freeze digest
  e6a67487) -- 23 repositories x (1 vulnerability fix push + 20 ordinary pushes) = 483
  changes, 93 confirmed vulnerable locations.
- Clones: `~/ousast-results/valid/train/hist/<owner__name>`; repos mapping
  `~/ousast-results/valid/train/repos_hist_pool23.json` -- rebuilt for this run. The
  previous mapping (`repos_hist.json`, 29 entries from the 5-repo pool era) lacked 18 of
  the 23 pool repositories and produced 378/441 `KeyError` instrument failures on a first
  launch; those records were deleted and never summarized. `prover_arm._prove` records
  only the exception type, so the missing key was invisible in records; it was recovered
  from the run log. Follow-up candidate: record the exception message in instrument
  failures.
- Command: `PYTHONPATH=$PWD .venv/bin/python -m benchmarks.valid.prover_arm run
  benchmarks/valid/train/pool-train.toml --repos repos_hist_pool23.json --out
  ~/ousast-results/prover/ac-train-1 --only all`, then `summarize` on the same out dir.
- Runtime: mean 27.9 s/change, median 0.9 s (ordinary pushes are fast; first touch of a
  repo pays tree walk + framework scan, max 1063 s). 483/483 records,
  **0 instrument failures**, no zero-byte read refusals.

## Result (whole pool, 23 repos)

Headline (from `summary.json`): on the training pool, recall 65.2% (Wilson 44.9-81.2),
false alarms 15.0 per 100 pushes, precision 17.9%; exploit-verified 0 of 78 (78 not yet
proved -- runtime proof is the async lane, out of scope here).

| metric | value |
|---|---|
| recall (fix pushes) | 15/23 = 65.2% (Wilson 44.9-81.2; repo-clustered 95% 43.5-82.6) |
| location recall | 55/93 = 59.1% (Wilson 49.0-68.6) |
| false alarms | 69 on 460 ordinary pushes = 15.0 per 100 pushes |
| precision (suspicion level) | 15/84 = 17.9% |
| instrument failures | 0 |

## Comparison with the DSPy and hunter arms (5 overlapping repos only)

The 2026-10-14 hunt arms ran the old 5-repo pool (dependency-track, job-import, p4,
shopper, trigger.dev; digest 53f9f364, 48 locations, 100 ordinary pushes). The prover ran
the 23-repo pool; restrict to those 5 repositories for a like-for-like recall comparison.

| arm | recall on 5 repos | notes |
|---|---|---|
| DSPy (2026-10-14) | 2/5 | 4/48 locations, 15.6 FA/100, 11 LMInvalidRequestError failures |
| hunter (2026-10-14) | 2/5 | different repos; union of the two arms 4/5, 99/100 ordinary pushes flagged |
| **prover (this run)** | **4/5** | misses p4 only; includes trigger.dev, which neither arm found |

The prover alone matches the union of both learned arms on their own training pool, at
DSPy-level false-alarm rate (15.0 vs 15.6 FA/100) and with zero instrument failures and
zero model cost. False-alarm counts come from different ordinary-push sets (460 vs 90),
so treat the FA comparison as indicative, not paired.

## Misses (8 fix pushes)

Zero coverage (no entry points found -- framework facts absent, fix site never reached):
- apache/seatunnel (Java, JettyService) -- 0 entry points.
- friendsofflarum/byobu (Flarum JS) -- 0 entry points.

Covered but not flagged:
- jenkinsci/analysis-core -- 172 entry points, 0 operations checked.
- jenkinsci/crx-content-package-deployer -- 12 checked, 2 discharged.
- jenkinsci/git -- 15 checked, 11 discharged.
- jenkinsci/global-build-stats -- 1 checked, 1 discharged.
- jenkinsci/p4 -- 38 checked, 3 discharged (the only overlap-repo miss).
- kimai/kimai -- 80 checked, 78 discharged; the fix's protected operation is dominated by
  an existing check on every traced path, or the fix site is not entry-reachable under
  current facts.

Reading: 2 of 8 misses are fact-coverage failures (grow the entry/fact tables, gate 5's
"fact-coverage failure grows fact tables first"), 6 are trace/logic failures for gate 3
ablation (what the checked-but-unflagged traces lack: entry reachability of the fix site,
missing operation kinds, or real dominance by an existing check).

## Per-repository coverage

| repository | recall | entry points | reached | ops checked | discharged |
|---|---|---|---|---|---|
| apache/seatunnel | 0/1 | 0 | 0 | 0 | 0 |
| friendsofflarum/byobu | 0/1 | 0 | 0 | 0 | 0 |
| jenkinsci/analysis-core | 0/1 | 172 | 7 | 0 | 0 |
| jenkinsci/azure-credentials | 1/1 | 100 | 29 | 6 | 0 |
| jenkinsci/azure-keyvault | 1/1 | 133 | 6 | 7 | 4 |
| jenkinsci/blueocean | 1/1 | 475 | 18 | 35 | 2 |
| jenkinsci/compuware-scm-downloader | 1/1 | 297 | 6 | 6 | 0 |
| jenkinsci/crx-content-package-deployer | 0/1 | 168 | 67 | 12 | 2 |
| jenkinsci/database | 1/1 | 93 | 38 | 8 | 5 |
| jenkinsci/dependency-track | 1/1 | 159 | 7 | 15 | 0 |
| jenkinsci/ec2 | 1/1 | 742 | 24 | 29 | 10 |
| jenkinsci/git | 0/1 | 584 | 24 | 15 | 11 |
| jenkinsci/global-build-stats | 0/1 | 448 | 32 | 1 | 1 |
| jenkinsci/hashicorp-vault | 1/1 | 179 | 15 | 17 | 2 |
| jenkinsci/jiratestresultreporter | 1/1 | 187 | 13 | 6 | 0 |
| jenkinsci/job-import | 1/1 | 103 | 43 | 17 | 9 |
| jenkinsci/opentelemetry | 1/1 | 157 | 9 | 5 | 2 |
| jenkinsci/p4 | 0/1 | 1018 | 35 | 38 | 3 |
| jenkinsci/rocketchatnotifier | 1/1 | 57 | 10 | 6 | 0 |
| kimai/kimai | 0/1 | 1951 | 78 | 80 | 78 |
| mage-ai/mage-ai | 1/1 | 214 | 1 | 63 | 0 |
| shopperlabs/shopper | 1/1 | 2645 | 53 | 115 | 1 |
| triggerdotdev/trigger.dev | 1/1 | 7164 | 20 | 14 | 0 |

Raw records: `~/ousast-results/prover/ac-train-1/` (483 records + `summary.json`, also
copied here). Watcher log: `~/ousast-results/prover/ac-train-1.log.watch`.

## Gate decision

Gate 1 passes its purpose: the trace-based prover holds recall the learned arms only
reached as a union, at comparable false alarms, with a clean instrument. Next gate (2):
zero-shot judge pass over these same traces where judgment remains.
