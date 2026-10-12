# Valid detection benchmark, pilot (2026-10-12)

First build of the benchmark defined in `.kiro/specs/valid-detection-benchmark/`. Labels come from
the fix, not SZZ. The frozen manifest is at `benchmarks/valid/pilot/` (`pool-valid.toml`,
`freeze-valid.json`). This directory keeps the provenance.

## What was built

| Step | Result |
|---|---|
| Sourcing | 32 held-out Python/JS advisories taken from the public part of `pool-p1` (pip 12, npm 20). CWE and advisory text fetched from OSV by GHSA id. No fresh GitHub harvest. |
| Fix-site catalog | 133 candidate locations across 31 repos, labelled at `fix^1` (the commit just before the fix). 125 after dropping 7 test files and 1 minified file. `method = "fix_site"` on every row; the SZZ methods were never called. |
| LLM verification | 125 DeepSeek calls (`deepseek-flash`). 31 locations passed all three checks (vulnerable before the fix, fix addresses it, reachable from an in-repo entry point) across 12 repos. 94 rejected. |
| Human spot-check | All 12 repos accepted by the maintainer (reviewer `mc`, 2026-10-12), recorded on the 31 locations. |
| Negatives | 20 ordinary first-parent commits per positive change, drawn from the same repo, fix excluded. 240 in total. |
| Held-out guard | 0 dropped against the training-only used set (1777 names: pairs, pointers, harvest, units, sweep). |
| Freeze | 252 changes: 12 `vulnerability` + 240 `ordinary`. Digest in `freeze-valid.json`. |

## The 12 positives

| Repo | Lang | Family | Advisory | Vulnerable function |
|---|---|---|---|---|
| bytebase/dbhub | ts | access_control | GHSA-mwwr-p57h-56pf | `src/utils/sql-parser.ts::scanTokenMySQL` |
| contentful/contentful-mcp-server | ts | untrusted_destination | GHSA-2xhg-73j7-rrgx | `.../exportSpace.ts::tool` (+1) |
| fastapi-users/fastapi-users | py | access_control | GHSA-5j53-63w8-8625 | `fastapi_users/router/oauth.py::get_oauth_router` (+2) |
| i18next/i18next-http-middleware | js | output_encoding | GHSA-c3h8-g69v-pjrg | `lib/index.js::extendOptionsWithDefaults` |
| imzbf/md-editor-v3 | ts | output_encoding | GHSA-3rm2-h79c-8qw6 | `.../useMarkdownIt.ts::useMarkdownIt` (+1) |
| jupyter-lsp/jupyterlab-lsp | py | path | GHSA-4qhp-652w-c22x | `.../virtual_documents_shadow.py::shadow_virtual_documents` |
| matrix-org/matrix-appservice-bridge | ts | access_control | GHSA-35g4-qx3c-vjhx | `src/components/room-upgrade-handler.ts::onJoinedNewRoom` |
| nvbn/thefuck | py | path | GHSA-8wwf-2644-f8x4 | `thefuck/rules/dirty_untar.py::side_effect` (+1) |
| ondata/ckan-mcp-server | ts | untrusted_destination | GHSA-798p-78g2-v556 | `src/utils/http.ts::validateServerUrl` (+1) |
| webpack/webpack-bundle-analyzer | js | output_encoding | GHSA-pgr8-jg6h-8gw6 | `src/viewer.js::chartData` |
| zenitram/malla | js | output_encoding | GHSA-ch57-39q2-4crm | `src/malla/static/js/chat.js::refreshPop` (+12) |
| zereight/gitlab-mcp | ts | path | GHSA-cv3r-c5h8-f4g5 | `index.ts::startSSEServer` (+1) |

"(+N)" means the fix touched N more functions the verifier also accepted. They collapse into one
positive change per fix commit in the manifest; the extra functions are listed as `targets` on that
change.

## Decisions made while building

- **Parent is `fix^1`, read from git**, not the `parent` field stored in `pool-p1`. That field did
  not always equal the fix commit's real first parent. "The code just before the fix" is `fix^1`.
- **Candidates are every function the fix touched.** `fix_sites()` does not know which function
  holds the vulnerability, so the catalog over-generates and the LLM check plus the human spot-check
  select the real location. One repo (`zenitram/malla`) produced 40 candidates from one fix.
- **The negative ratio is per positive change**, not per accepted function. `assemble.py` was
  corrected; the old count would have drawn 260 negatives for malla alone.
- **The held-out guard runs against training sources only.** `build_used()` also scans
  `measurements/` and `populations/`, which contain the SZZ pool and analysis of it, so it flagged all
  12 repos as "used" by my own earlier measurements. That is circular. None of the 12 appear in any
  training source (pairs, pointers, harvest, units, sweep).
- **Catalog enumeration skips a site it cannot read** (fix renamed or removed the function) instead
  of aborting the whole run. Verification stays strict.

## Not done yet

- **Replay** (whole tool, all tiers on) has not run. 252 changes at the engine's ~200 s fixed cost is
  about 14 hours one container at a time on the local host; that scale belongs on the kube `ax` lane,
  still blocked on the gVisor checkpoint path.
- **Metrics** (recall, precision, false alarms per 100 pushes, exploit-verified rate) follow the replay.
- Growing from 12 to the ~40 positives `score.py:required_n` asks for.

## Reproduce

```
# clones: fetch each repo single-branch with history, then fetch <fix> <parent>
python -m benchmarks.valid.catalog  sources.json --repos repos.json --out catalog.toml
DEEPSEEK_API_KEY=... python -m benchmarks.valid.verify run catalog.toml --repos repos.json --out verification.json
python -m benchmarks.valid.verify spot-check verification.json <id> accept --reviewer mc --date 2026-10-12
python - <<'PY'   # assemble with the training-only used set
from benchmarks.valid import assemble
...  # see this directory's provenance files; used = build_used(root) minus {measurements, populations}
PY
```
