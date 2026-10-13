# Training set for the hunter learning loop: sourcing run (2026-10-13)

Spec task 4.1 of `.kiro/specs/hunter-learning-loop/` (requirements R2.1 to R2.3). This is the record of the
sourcing run. **The training set is not frozen yet.** The model checks are done; the maintainer's spot-check is
not, and `assemble` only freezes accepted locations. Even if every candidate is accepted, the set has **28
positive changes, short of the 40 R2.3 asks for.** A run on it is a dry run until more positives are sourced.

## Files

In the tree (`benchmarks/valid/train/`):

| File | What it is |
|---|---|
| `sourcing.py` | Every step of this run (`used`, `sources`, `clone`, `filter`, `overlap`, `merge`, `verify`, `candidates`, `precheck`) |
| `sources.json` | 163 advisories that survived every exclusion, in the pilot's `sources.json` shape plus `origin`, `ecosystem`, `license_spdx` |
| `catalog.toml` | 413 fix-site locations for those advisories (test, vendored and minified files removed) |
| `verification.json` | One verifier record per catalog location (all `rejected` or `pending_human`) |
| `CANDIDATES.md` | The 99 locations that passed all three model checks, by repository, for the spot-check |

Out of the tree (`~/ousast-results/valid/train/`): `hist/<owner>__<name>` clones, `repos_hist.json`, and
`work/`, which holds the exclusion lists (`used.json`, `used_strict.json`, `named_elsewhere.json`), the per-batch
sources, catalogs and verifications, the drop lists, the clone log and the run logs. These stay out of the tree on
purpose: the repository guards in `tests/` scan `benchmarks/` for repository names, and an exclusion list is by
construction a list of names used elsewhere.

## Counts at every step

**Candidates.** Three batches, all with seed 1, in the order the task gave:

| Origin | Sourced | Dropped by the overlap check | Kept |
|---|---|---|---|
| `pool-fresh` (permissive `pool-p1` entries the pilot never sourced) | 17 | 17 | 0 |
| `pool-retry` (pilot-sourced, verifier rejected, not held out) | 20 | 20 | 0 |
| `osv` (batch 1, OSV dump) | 75 | 11 | 64 |
| `osv-extend` (batches 2 and 3, same order continued) | 100 | 1 | 99 |
| **Total** | **212** | **49** | **163** |

OSV source: the public bulk dumps (`osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`, no token)
for PyPI, npm, Maven and Packagist. Go was left out because the catalog and the function cutter do not read Go
fix sites. The filter is `benchmarks/unseen/source.py:candidate()`, run unchanged: GitHub-reviewed, not
withdrawn, published 2019 or later, exactly one taxonomy family from the CWEs, exactly one GitHub fix-commit
reference, public repository under 500 MB, fix with exactly one parent, and a permissive licence read at the
fix's parent (unknown licences are skipped). One advisory per repository. Over the three batches the GitHub
checks rejected 306 advisories for a non-permissive or unknown licence, 71 for an ambiguous version bracket, 74
for a merge or root fix, 64 for the repository check, 2 not found, and 4 for transient `http_failure`. GitHub
calls: 584, 710 and 593 for the three batches (the token came from `gh auth token`). A first run of batch 1 read
only npm and Maven, because OSV calls the other two ecosystems `PyPI` and `Packagist` while the shared code
expects GitHub's `pip` and `composer`. The adapter maps the names now, and batch 1 was re-run before anything
was cloned.

Kept, by ecosystem: npm 52, Maven 49, pip 41, Composer 21.

**Overlap check (pilot and corpus exclusion).** A candidate is dropped if anything in the development tree
already names its repository. That means `github.com/<name>` or a `repo = "<name>"` line anywhere under
`benchmarks/`, `src/`, `tests/`, `plane/` or `.kiro/` (vendored trees skipped, as the pair guard skips them),
or a name in the strict used set (`build_used(root)` with every label). This removed:

- all 17 `pool-fresh` and all 20 `pool-retry`: they are reserved `pool-p1` repositories, and the retries are
  also named by the pilot's measurement files;
- 11 `osv`: hkuds/lightrag, jenkinsci/job-config-history-plugin, decolua/9router, code16/sharp,
  chainlit/chainlit, mineadmin/mineadmin, netflix/lemur, pheditor/pheditor, mockoon/mockoon and
  xorbitsai/inference (named in `benchmarks/independent` or `benchmarks/unseen`), plus startreedata/mcp-pinot,
  whose advisory text links jlowin/fastmcp, a repository in the `advisory-fixes-2` and `-3` pair corpora;
- 1 `osv-extend`: googleapis/google-oauth-java-client (named in `benchmarks/unseen`).

The first `used` step built a looser set that left out free text under `benchmarks/measurements` and
`benchmarks/independent`. Pool and population repositories got through that set into the first sourcing pass,
and the overlap check removed them afterwards. The merge step also dropped 3 catalog locations whose code
comments link a repository named elsewhere: jenkinsci/pipeline-maven-plugin (links jenkinsci/jenkins, and this
was its only passing location), snapappointments/bootstrap-select (links angular/angular) and
livehelperchat/livehelperchat (links axios/axios); the last two had been rejected anyway.

**Pilot exclusion check.** None of the 12 held-out pilot repositories appears in `sources.json`, `catalog.toml`,
`verification.json` or `CANDIDATES.md`: the overlap is 0, and `sourcing.py` asserts it. None of the 163 kept
repositories appears in the strict used set either.

**Clones.** 212 of 212 cloned with `--single-branch --no-tags` and full first-parent history. Each fix was
present or fetched, and the parent was read from git as `fix^1`; 0 of 212 differed from the stored parent. The
disk guard fired once: free space reached 6.0 GB after 64 clones, so cloning stopped. I then emptied the working
trees with `git sparse-checkout set --no-cone /__worktree_emptied_for_disk__`, which freed 3.4 GB. Nothing
downstream reads a checkout; `git sparse-checkout disable` restores one. Cloning then resumed with
`--no-checkout`. Free space later fell to 4.8 GB while the engine replay was writing, so clones of repositories
that could no longer contribute a positive were deleted (no catalog site, then no passing site, then not a
candidate after the overlap check). What is left: 29 clones, 2.4 GB, of which 28 are candidate repositories plus
pipeline-maven-plugin, whose only passing site was dropped. Peak use was about 6.5 GB. Host free space at the
end: 8.1 GB.

**Catalog.** Sites before filtering, then after:

| Batch | Sources | Raw sites | Test / vendored / minified dropped | Kept | Sources with a site |
|---|---|---|---|---|---|
| 1 | 112 | 463 | 112 / 5 / 1 | 345 | 75 |
| 2 | 60 | 217 | 74 / 0 / 2 | 141 | 34 |
| 3 | 40 | 111 | 38 / 3 / 3 | 67 | 30 |

Three sources hung in the catalog's regex function parser on large PHP files and were skipped after a 90 to 280 s
cap: tribalsystems/zenario, getgrav/grav-plugin-admin and genixcms/genixcms. After the overlap check and the
merge, the tree catalog holds **413 locations across 96 advisories and repositories**: Java 114, Python 104,
TypeScript 94, JavaScript 54, PHP 47.

`benchmarks/valid/catalog.py` now maps `.java` and `.php`. Before, it only read Python, JavaScript and
TypeScript, although `extract.fix_sites` and `function_bounds` read all five. The scope test in
`tests/test_valid_benchmark.py` now expects `.php` to give `php` and checks `.rb` as the out-of-scope suffix.

**Verification.** `deepseek-flash` through the shipped `verify_case`, temperature 0, 1200-token output cap.

- Calls: **553 of the 600 budget** (345 + 141 + 67), with 0 provider errors and no exception types seen. Every
  call logs the function bytes read on both sides first, so no verdict comes from an unread function.
- Locations ordered round-robin by advisory, so one advisory with many sites could not use up the budget.
- On the 413 locations in the tree: 306 vulnerable before the fix, 259 where the fix addresses it (258 both),
  107 reachable from an in-repo entry point, **99 passing all three with an entry point**.
- Across all 553 calls (including dropped candidates): 433, 371 and 143 per check; 132 passing.

**Candidates for the spot-check (`CANDIDATES.md`).** 99 locations, 28 repositories, 28 positive changes (one
fix commit each).

- Repositories by language: Java 10, Python 9, TypeScript 7, JavaScript 2, PHP 1 (apache/atlas has both
  JavaScript and TypeScript sites).
- Families: access_control 7, path 6, output_encoding 4, injection 4, config_secrets 4,
  untrusted_destination 3.
- Origin: 13 from batch 1 (`osv`), 15 from batches 2 and 3 (`osv-extend`).

## What blocks the freeze

1. **Human acceptance.** `assemble.freeze` only takes `accepted` verdicts, so I stopped before assemble. No
   spot-check was run.
2. **Too few positives.** At most 28 changes, against the 40 R2.3 asks for. The yield was about 18% of sourced
   advisories (29 of 163 survivors had a passing site before the last drop). Reaching 40 accepted needs roughly
   70 to 100 more advisories, about 200 to 250 more verifier calls, and about 3 GB of transient clone space.
   With this run's 47 remaining calls, that is a new budget decision for the maintainer.
3. **Ordinary-push availability.** A pre-check of `extract.ordinary_history`, the function `assemble` uses, on
   the first two repositories alphabetically found two failures. Both stop the whole freeze (`freeze` raises):
   - andrea9293/mcp-documentation-server has 8 usable ordinary commits, short of the 20 needed;
   - apache/atlas fails with `Rejected: function_parse` after 456 s (a Python file in its history does not parse).

   dtwang/line-desktop-mcp (56 first-parent commits) and modoboa/modoboa-dmarc (87) are also likely short. I
   stopped the pre-check there: it parses every changed file of every first-parent commit, and five candidates
   have 7,000 to 22,600 commits (trigger.dev, inventree, apache/pdfbox, home-assistant/frontend,
   htmlunit/htmlunit). That would be hours of CPU next to the running replay. Expect `assemble` to be slow on
   those repositories, or reject them in the spot-check.

## What the maintainer runs after accepting

Spot-check each location in `CANDIDATES.md`:

```
.venv/bin/python -m benchmarks.valid.verify spot-check benchmarks/valid/train/verification.json <id> accept|reject --reviewer mc --date YYYY-MM-DD
```

Then freeze with ratio 20 and seed 1. The used set must be the pre-run snapshot `work/used_strict.json` plus the
12 pilot repositories. A fresh `build_used(root)` would now sweep `benchmarks/valid/train/` itself and drop every
training repository.

```
PYTHONPATH=. .venv/bin/python - <<'PY'
import json, tomllib
from pathlib import Path
from benchmarks.valid import assemble
from benchmarks.valid.catalog import local_git
H = Path.home() / "ousast-results/valid/train"
T = Path("benchmarks/valid/train")
used = set(json.loads((H / "work/used_strict.json").read_text()))
used |= set(json.loads(Path("benchmarks/measurements/2026-10-12-valid-benchmark-pilot/accepted_repos.json").read_text()))
repos = {k: local_git(Path(v)) for k, v in json.loads((H / "repos_hist.json").read_text()).items()}
record = assemble.freeze(H / "work/freeze", cases=tomllib.loads((T / "catalog.toml").read_text())["case"],
                         verifications=json.loads((T / "verification.json").read_text())["cases"],
                         repos=repos, used=used, seed=1, ratio=20)
(T / "pool-train.toml").write_bytes((H / "work/freeze/pool-valid.toml").read_bytes())
(T / "freeze-train.json").write_bytes((H / "work/freeze/freeze-valid.json").read_bytes())
print(json.dumps({k: record[k] for k in ("freeze_digest", "dropped_count", "label_check_counts")}))
PY
```

`dropped_count` should be 0. A non-zero count means an accepted repository is in the used snapshot, which the
overlap check should have prevented.

## Reproduce

```
B=benchmarks/valid/train/sourcing.py; W=~/ousast-results/valid/train/work
python $B used
python $B sources --osv-dir <dir with PyPI/npm/Maven/Packagist all.zip> --target 75 --seed 1      # batch 1
python $B sources --osv-dir ... --target 60 --seed 1 --extend                                    # batch 2, then 40 for batch 3
python $B clone [--sources <batch file>]
python -m benchmarks.valid.catalog <batch sources> --repos $W/repos_hist.json --out <raw.toml>   # per source, with a time cap
python $B filter <raw.toml> --out <catalog.toml>
DEEPSEEK_API_KEY=... python $B verify <catalog.toml> --repos $W/repos_hist.json --out <verification.json> --budget <n>
python $B overlap sources_batch1.json sources_batch2.json sources_batch3.json
python $B merge --catalogs catalog_batch{1,2,3}.toml --verifications verification_batch{1,2,3}.json
python $B candidates benchmarks/valid/train/verification.json benchmarks/valid/train/catalog.toml --out benchmarks/valid/train/CANDIDATES.md
```

The verifier ran before the overlap check, so 137 of the 553 calls went to locations that were dropped later
(134 by the overlap check, 3 by the merge). A fresh run should call `overlap` before `clone`.
