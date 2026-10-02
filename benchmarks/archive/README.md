# Archived benchmark scripts

Reference-only scripts, moved here with `git mv` on 2026-10-02 (legacy cleanup) so their history
follows them. Nothing in `src/` imports them and no current workflow runs them. They stay because
committed records cite them and their numbers: to re-run a record, check out the commit the record
names rather than running these copies against today's package.

The old paths still appear inside committed records and in some docstrings. [paths.md](paths.md)
maps each old path to the new one. The records themselves are not rewritten.

| script | what it was | records that cite it | last recorded run |
|---|---|---|---|
| `verify_batched.py` | Stage-2 verifier, second design: triage per file, verify per file, report what two passes agree on. Replaced by the plane's `verify` + `agree` tasks. | `independent/results-v2-model-pipeline.json`, `independent/verifier-batched-check-2026-09-29.json`, `independent/plane-increment-2.json` (parity baseline) | `072a102` (named in `results-v2-model-pipeline.json`) |
| `score_batched.py` | Exploratory scorer for the batched verifier: sites anchored to the candidate, matched by `evaluate.matches_v2`. | `independent/verifier-batched-check-2026-09-29.json`, `independent/plane-increment-2.json`; `tests/test_plane_scoring_parity.py` still loads it as the reference | added in `6acd354` (2026-09-29); the parity test replays it on hosts with the recorded scans |
| `verify_sinks.py` | The first stage-2 verifier, one candidate at a time. `verify_batched.py` imports `ACCOUNT_ERRORS` and `_Recording` from it. | `independent/verifier-check-2026-09-29.json` | the known-answer check after `041d871` |
| `model_sinks.py` | Stage-1 source-only model classification of sinks. Moved into the package as `plane/tasks/roles.py`. | `independent/selection-v2-model-sinks.json`, `measurements/2026-10-01-decision-engine-harvest/record.json`, both `2026-10-01-decision-engine-leak-audit` records | `05d5699` (named in `selection-v2-model-sinks.json`) |
| `sink_candidates.py` | Diagnostic: vocabulary-declared sink candidates per case. Its declaration patterns live on in `plane/tasks/repo_facts.py`. | `independent/results-v2-model-pipeline.json` ("vocabulary sink-first: 2/17") | no commit recorded |
| `hunt.py` | The v2 tool-hunter run over the population (protocol `hunter-protocol-v2.md`, including its `FAMILY_WORDS` table). Replaced by the plane's `verify` / `agree` tasks. | `independent/hunter-protocol-v2.md`, `independent/results-v2-hunter.json` (a label source in `learn/sources.toml`) | `6bfb05f`, the commit that introduced the protocol, which pins the runner |
| `harnessx_removal_equality.py` | One-off equality proof for `harnessx-removal` (record and compare deterministic outputs). The spec is closed; its unit test was dropped on 2026-10-02 so the archived copy is reference only like the rest. | `measurements/2026-09-30-harnessx-removal-baseline/`, `measurements/2026-09-30-harnessx-removal-equality/` | baseline `ca5caf7`, candidate `b9afb66` |

The six `independent` scripts still read the population, `evaluate.py` and the results from
`benchmarks/independent/`. Their `HERE` points there, so outputs land where they always did.
`evaluate.py` and `freeze.py` are current and were not moved.

`verify_sinks.py --help` fails with an argparse `%` formatting error. That bug was already there
before the move. The script still imports cleanly.
