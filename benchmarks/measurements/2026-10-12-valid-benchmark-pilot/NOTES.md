# Valid detection benchmark, pilot (2026-10-12)

First build and first run of the benchmark defined in `.kiro/specs/valid-detection-benchmark/`.
Labels come from the fix, not SZZ. The frozen manifest is at `benchmarks/valid/pilot/`
(`pool-valid.toml`, `freeze-valid.json`). This directory keeps the provenance and the numbers.

## Numbers (read 2026-10-13 morning)

Two arms over the same 252 changes (12 verified positives, 240 ordinary pushes from the same 12
repos), as R6 of the requirements asks:

- **(a) push hook as shipped**: quick rules + engine, 300 s deadline, the Docker replay lane, no
  model key in the container. Still running when this was written: 163 of 252 records done (all 12
  positives, 151 ordinary). The final numbers land in `MORNING.txt` outside the repo and will replace
  the `*_interim_163.json` files here.
- **(b) hunter arm**: the LLM tool hunter (`scan --mode deep`'s search) run off-cluster over the
  changed files at head, every finding classified into the taxonomy by the decision-engine
  classifier. Finished: 252 of 252. Reported twice: raw (every hunter suspicion counts) and
  filtered (only suspicions the classifier judged `vulnerable`).

| Metric | (a) push hook, 163 done | (b) hunter, raw | (b') hunter, classifier-filtered |
|---|---|---|---|
| Recall (12 positives) | 0 / 12 = 0% (Wilson 0 to 24.3) | 6 / 12 = 50% (25.4 to 74.6) | 5 / 12 = 41.7% (19.3 to 68.0) |
| False alarms per 100 ordinary pushes | 1 / 149 = 0.7 (0.1 to 3.7) | 221 / 239 = 92.5 (88.4 to 95.2) | 130 / 239 = 54.4 (48.1 to 60.6) |
| Precision (flagged pushes that were positives) | 0 / 1 | 6 / 232 = 2.6% | 5 / 139 = 3.6% |
| Exploit-verified | 0 (no proof run) | 0 (no proof run) | 0 (no proof run) |
| Instrument failures | 2 / 163 | 1 / 252 | 1 / 252 |

Neither arm meets the gate (recall at least 90%, false alarms under 10 per 100 pushes). The hook as
shipped is quiet and blind on this set. The hunter finds about half and alarms on more than half of
ordinary pushes even after the classifier. The whole-tool number the brief holds the tool to is
(a) plus (b'); since (a) caught nothing, it equals (b') on recall and adds one false alarm.

Files: `scored_a_interim_163.json`, `metrics_a_interim_163.json`, `scored_b_raw.json`,
`metrics_b_raw.json`, `scored_b_filtered.json`, `metrics_b_filtered.json`. Scorer:
`benchmarks/unseen/score.py` (a catch needs the labelled family and a location inside the labelled
function or within 10 lines of it). Metrics: `benchmarks/valid/metrics.py`.

### Per positive

| Repo | Label | (a) hook | (b) raw | (b') filtered | What the hunter did |
|---|---|---|---|---|---|
| bytebase/dbhub | access_control | miss (engine ran) | miss | miss | 8 suspicions in the right files, all `not_vulnerable` or `unsure`, none typed access_control |
| contentful/contentful-mcp-server | untrusted_destination | miss | miss | miss | 2 `vulnerable` hits in the labelled file, typed `path`; family mismatch, not credited |
| fastapi-users/fastapi-users | access_control | miss | miss | miss | 0 suspicions |
| i18next/i18next-http-middleware | output_encoding | miss | hit | miss | hit at `lib/index.js:96`, classifier said `unsure`, dropped by the filter |
| imzbf/md-editor-v3 | output_encoding | miss (engine ran) | hit | hit | 9 `vulnerable` html-injection suspicions at the labelled sites |
| jupyter-lsp/jupyterlab-lsp | path | miss | hit | hit | 3 `vulnerable` path hits in the labelled file |
| matrix-org/matrix-appservice-bridge | access_control | miss (engine ran) | miss | miss | 5 "complexity hotspot" suspicions in the right file, all `not_vulnerable` |
| nvbn/thefuck | path | miss (engine ran) | hit | hit | both labelled functions hit, `vulnerable` 0.85 to 0.9 |
| ondata/ckan-mcp-server | untrusted_destination | miss | hit | hit | 2 `vulnerable` ssrf hits in `http.ts` |
| webpack/webpack-bundle-analyzer | output_encoding | miss | miss | miss | `vulnerable` output_encoding hit in `viewer.js:185`, outside the labelled function |
| zenitram/malla | output_encoding | miss | hit | hit | 7 `vulnerable` dom-xss hits |
| zereight/gitlab-mcp | path | miss | miss | miss | 5 suspicions, none typed path |

Two misses are scorer strictness rather than blindness: contentful (right file, family typed `path`
instead of `untrusted_destination`) and webpack (right file and family, other function). Keep the
strict scorer; note them.

### Arm (a) detail

- Engine finished inside 300 s on 100 of 163 changes (61%); 61 fell back to quick rules only; 2
  instrument failures (`contentful` 9e706114, `matrix` 7018468e, nothing readable at the hotspots).
  On the positives: engine ran on 4 of 12, quick only on 8.
- Every record proves the instrument: hook exit 0, bytes read per changed file, base and head
  verified.
- The one false alarm: `bytebase/dbhub` 5bd45460, quick rule `js-command-exec` (CWE-78) at
  `src/connectors/sqlite/index.ts:132`, "Node child_process command execution needs review".

### Arm (b) detail

- 1398 suspicions over 251 pushes: mean 5.6 per ordinary push, median 5, max 23.
- Classifier verdicts: 377 `vulnerable`, 968 `not_vulnerable`, 53 `unsure`, 0 errors. Families among
  the `vulnerable` ones: config_secrets 103, injection 74, output_encoding 58, access_control 54,
  path 39, untrusted_destination 33, prototype 10, other 6.
- The hunter's own `family:` tag is free text (`sql-parser`, `complexity-hotspot`, `dom-xss`), so
  without the classifier every finding scored `unknown`. Product follow-up: constrain the hunter
  prompt to the taxonomy (`tool_hunter.py`) so the push path emits taxonomy families natively.
- The instrument failure: `matrix` 7018468e, no readable hotspot (`hook_bytes_read: 0`).

### What to do with this

1. The push hook needs the LLM tier (owned by `pre-push-safety-net`): the hook as shipped caught
   none of the 12. That is the product gap R6 names.
2. The hunter needs a precision step before it can sit on pre-push: 54 alarms per 100 pushes after
   the classifier is far from 10. Candidates: require `vulnerable` with confidence at or above 0.7,
   drop `config_secrets` noise in ordinary pushes, restrict to changed lines, or run the proof arm on
   the survivors.
3. Twelve positives give intervals 50 points wide. Grow to the ~40 positives `score.py:required_n`
   asks for before quoting a single recall number.

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
| Replay, arm (a) | `benchmarks/unseen/replay.py --arm long_deadline`, Docker lane, one container at a time on the local host, about 14 records per hour. Started 2026-10-12 19:51. |
| Hunter, arm (b) | `benchmarks/valid/hunter_arm.py run`, positives 20:23 to 20:51, ordinary 20:51 to 22:00. |

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
- **The hook has no LLM detection tier.** `push/assistance.py` only picks witnesses for defects the
  engine already admitted. R6 was amended to measure the hook as shipped and the hook plus the
  hunter arm; the second is the number the tool is held to.
- **Hunter findings are classified, never relabelled.** The classifier gets the finding's excerpt
  and the taxonomy list; the change's own label is never shown to it. The raw hunter family, title
  and rationale stay on the defect for audit.
- **Replay output kept every result twice** (top level and `attempt-*/`), 30 MB a record, and the
  host hit 1.1 GB free at record 162. Byte-identical `attempt-*/` copies of finished records were
  removed; a guard repeats that while the replay runs. Nothing in Docker was touched.

## Not done yet

- Final arm (a) numbers on all 252 changes (replay finishing 2026-10-13 afternoon), then the
  combined (a)+(b') score with `hunter_arm combine --keep-verdicts vulnerable`.
- Exploit-verified rate: the proof arm has not run on any of the 26 flagged positive findings.
- Growing from 12 to the ~40 positives `score.py:required_n` asks for.
- The 252-change replay at the engine's ~200 s fixed cost is about 17 hours one container at a time
  on the local host; that scale belongs on the kube `ax` lane, still blocked on the gVisor
  checkpoint path.

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
# arm (a): replay.py --arm long_deadline, docker lane, --docker-image-bytes 3608729816, output outside the repo
# arm (b): DEEPSEEK_API_KEY=... python -m benchmarks.valid.hunter_arm run benchmarks/valid/pilot/pool-valid.toml --slice 1 --repos repos_hist.json --out <hunter_out>
python -m benchmarks.unseen.score <records_dir> --out scored.json --slice-id 1
python -m benchmarks.valid.metrics <records_dir> --scored scored.json --out metrics.json
```
