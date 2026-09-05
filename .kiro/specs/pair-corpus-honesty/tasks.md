# Implementation Plan

- [x] 1. Foundation: label schema and vocabulary
- [x] 1.1 Add the closed mechanism vocabulary as data
  - A versioned TOML next to the catalogs lists every mechanism id with a one-line definition.
  - Catalog load rejects an expected row whose mechanism is not in the vocabulary.
  - Observable: loading a catalog with an unknown mechanism fails with the pair name; the vocabulary file lists the v1 set from the design.
  - _Requirements: 2.1, 2.4_
  - _Boundary: Vocabulary, LabelSchema_

- [x] 1.2 Extend pair and expected fields with provenance, split, known_limit, function
  - Pair rows accept `provenance` from the closed set, `split` of train or holdout, and an optional `known_limit` reason.
  - Expected rows accept `function`; rows with `sink = "unknown"` and no function and no rule id are rejected.
  - Defaults: sast is synthetic, local/github/vfc are human, split is train.
  - Observable: a unit test loads a row with each new field and rejects an unknown provenance value and a sink-unknown row without function or rule id.
  - _Requirements: 2.2, 2.3, 2.4, 2.5, 2.6_
  - _Boundary: LabelSchema_
  - _Depends: 1.1_

- [x] 2. Core: honest scorer
- [x] 2.1 Count coverage with a source as detection and as leak
  - Overlay pair scoring treats a coverage record with a non-empty source the same as a promote on both the vulnerable and the fixed side.
  - Outcome records which detection kinds contributed.
  - Observable: the owasp-java-sqli vulnerable side counts as detected via coverage; a coverage record on a fixed tree under silent policy counts as a leak.
  - _Requirements: 1.1_
  - _Boundary: Scorer_

- [x] 2.2 Match by function and flag weak labels
  - `OverlayRecord` gains an optional `function` filled from the enclosing function's line range; default stays None.
  - When an expected row names a function, a record matches only inside that function; CWE equality alone never matches; rows without function, sink, or rule id are counted as weak labels.
  - Observable: a promotion outside the named function does not match; a CWE-only row is reported under weak_labels and produces no match.
  - _Requirements: 1.2, 1.3_
  - _Boundary: Scorer_
  - _Depends: 1.2_

- [x] 2.3 Report side-by-side scorers and loss counters for every overlay slice
  - Every overlay slice gets `overlay` and `inventory` scorers, not only vfc.
  - Payload reports parse_failed files and unadjudicated proposals per side and per slice, plus known_limit and achievable metrics.
  - Observable: `pairs --slice sast --json` contains both scorers and a loss block; known-limit pairs are listed and excluded from achievable metrics.
  - _Requirements: 1.4, 1.5, 2.3, 4.3_
  - _Boundary: Scorer_
  - _Depends: 2.1, 2.2_

- [x] 2.4 Migrate existing vfc rows and record the new baseline
  - `generate_catalog.py` emits function, mechanism, provenance, and split from recipes; every existing recipe gains a mechanism and half the pairs are declared holdout.
  - Roadmap records sast and vfc numbers before and after the scorer change.
  - Observable: no vfc expected row is a weak label; the catalog loads under the new validation; the roadmap has a before/after table.
  - _Requirements: 2.6, 1.6_
  - _Boundary: LabelSchema_
  - _Depends: 2.3_

- [x] 2.5 Add the hunter scorer for overlay slices
  - With a hunter model configured, each pair function is run through the tool hunter and scored with the same detection and leak rules; results appear as `scorers[slice].hunter`; without a model the scorer is skipped with a degradation.
  - Default tests use a scripted client; no network.
  - Observable: `pairs --slice sast --json` with a scripted client shows a `hunter` scorer; without a model the payload records `hunter_model_unavailable`.
  - _Requirements: 1.7_
  - _Boundary: Scorer_
  - _Depends: 2.3_

- [x] 3. Core: harvest library (parallel with 2)
- [x] 3.1 (P) Anchor name extraction at the declarator
  - Comments and string literals are masked before the name search; the anchor line must not be inside a mask and must be followed by a parameter list and a body before a semicolon.
  - Existing vfc harvest tests still pass through a thin shim.
  - Observable: a fixture whose doc comment mentions `Curl_follow()` above the definition extracts from the definition line; existing prototype-skip test still passes.
  - _Requirements: 3.1, 3.6_
  - _Boundary: HarvestLibrary_

- [x] 3.2 (P) Add line-range, hunk, and Python block modes
  - A recipe may give a line range, or a fix commit whose first changed hunk selects the enclosing function on both sides; Python functions are cut by indentation.
  - Observable: each mode round-trips a local string fixture; no network in tests.
  - _Requirements: 3.2, 3.3, 3.4, 3.6_
  - _Boundary: HarvestLibrary_
  - _Depends: 3.1_

- [x] 3.3 Re-harvest the curl pairs
  - All curl recipes are re-run with the anchored extractor; excerpts start at the declarator.
  - Pairs that still fail to parse because of preprocessor-split control flow are kept and show up in the loss counters, not removed.
  - Observable: no vfc excerpt has a mid-comment first code line; the loss block for vfc reports the remaining parse failures.
  - _Requirements: 3.5_
  - _Boundary: SliceCatalogs_
  - _Depends: 3.1, 2.3_

- [x] 4. Core: sast hygiene (parallel with 3)
- [x] 4.1 (P) Restore the Juliet strcpy buffer declarations and mark the Java hash pair
  - The Juliet CWE-121 vuln and fixed excerpts include the differing buffer declarations from the full case file.
  - The OWASP Java hash pair is declared known_limit with reason cross_artifact, or vendors the property file.
  - Observable: the two Juliet bodies differ; owasp-java-hash appears under known_limit; sast achievable count is 10 or 11 accordingly.
  - _Requirements: 4.1, 4.2, 4.3_
  - _Boundary: SliceCatalogs_

- [x] 5. Integration: new slices
- [x] 5.1 Add the vibe-py slice from Real-Vuln-Benchmark _(the "at least one agent provenance" observable is met by the 80 `agent`/`seeded` pointer rows of task 8.4, Req 10; nothing unlicensed is vendored)_
  - Recipes carry pinned commit, file, line range, function, primary and acceptable CWEs, authorship, and vulnerable or trap flag; harvest uses line-range mode; traps become fixed-side twins; provenance from authorship.
  - README states the educational and CTF caveat and the license.
  - Observable: the slice loads offline with tens of pairs, at least one agent and one human provenance, and scores with per-profile metrics.
  - _Requirements: 5.1, 5.4, 5.5_
  - _Boundary: SliceCatalogs_
  - _Depends: 3.2, 1.2_

- [x] 5.2 (P) Add the vfc-js slice from SecBench.js fix commits
  - Recipes point at upstream package repositories with parent and fix commit, file, and sink line; harvest uses hunk mode; command injection, path traversal, and code injection first; prototype pollution and ReDoS rows carry their mechanism and may be known_limit.
  - No SecBench.js test files are vendored; each pair records the upstream package license.
  - Observable: the slice loads offline with tens of pairs and JavaScript or TypeScript files; no file from the SecBench.js repository is present.
  - _Requirements: 5.2, 5.4, 5.5_
  - _Boundary: SliceCatalogs_
  - _Depends: 3.2, 1.2_

- [x] 5.3 (P) Add the agent-vfc slice from agent-trailer security fixes _(re-scoped by Req 9: rows load at tier `title` and never gate; task closes when 8.1 lands and the slice scores)_
  - Recipes record repo, parent, commit, file, the agent trailer or marker, mechanism, and reviewer; harvest uses hunk mode; provenance is agent.
  - README carries the review checklist: real vulnerability, single mechanism, no secrets, license stated.
  - Observable: the slice loads offline with tens of reviewed pairs in JavaScript, TypeScript, or Python and scores under the agent profile.
  - _Requirements: 5.3, 5.4, 5.5_
  - _Boundary: SliceCatalogs_
  - _Depends: 3.2, 1.2_

- [x] 5.4 Point datasets.toml at the researched corpora and document slices
  - Rows for Real-Vuln-Benchmark, SecBench.js, AIDev, BaxBench, SecurityEval, CodeSecEval, CWEval, CyberSecEval with license and caveats; CyberSecEval is marked rule-defined, not recall ground truth.
  - Pair README lists the new slices and the profile and mechanism views.
  - Observable: dataset test sees the new names; README mentions each slice.
  - _Requirements: 5.6_
  - _Depends: 5.1, 5.2, 5.3_

- [x] 6. Integration: provenance and profile gate
- [x] 6.1 (P) Compute a deterministic provenance fingerprint at scan time
  - Signals from agent configuration paths, generation markers, and git trailers over a bounded commit sample; agent at 85 percent trailer share, mixed on any signal, human otherwise; never synthetic.
  - Manifest records the value and the signal list; no model call.
  - Observable: an empty tree is human with no signals; a tree with AGENTS.md is mixed; a synthetic git log of Claude trailers is agent; git absence is recorded as a signal.
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 7.5_
  - _Boundary: ProvenanceFingerprint_

- [x] 6.2 Add per-profile and per-mechanism metrics and a profile filter
  - Payload gains per_profile and per_mechanism; the pairs command accepts a profile filter.
  - Observable: `pairs --slice all --json` contains both maps; `--profile agent` evaluates only agent pairs.
  - _Requirements: 7.1_
  - _Boundary: Scorer_
  - _Depends: 2.3, 5.4_

- [x] 6.3 Reject improve-loop changes that regress any profile on holdout
  - After the existing four clauses pass, holdout pairs are evaluated per profile; a drop in pair-correct or Youden beyond tolerance for a profile with at least the minimum pairs rejects with a profile reason; smaller profiles are reported only; at most four profiles.
  - Observable: a test change that improves synthetic and regresses agent holdout is rejected with `profile_regression:agent`; a profile under the minimum appears in the journal and does not gate.
  - _Requirements: 7.2, 7.3, 7.4_
  - _Boundary: ProfileGate_
  - _Depends: 6.2_

- [x] 7. Validation
- [x] 7.1 Prove offline load, CLI, and unchanged gates
  - Default catalog load sees the three new slices and every file on disk; each slice command exits zero with per-profile metrics; new names are absent from the stage-1 fixture list; detection gate, map gate, and local pair gate outputs are unchanged; extra-free suite is green with overlay assertions skipping.
  - Observable: extra-free pytest green; gate entrypoints produce the same verdicts as before this spec.
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 1.6_
  - _Depends: 5.4, 6.3_

- [x] 7.2 Close real-world-vfc-slice as superseded
  - Its spec.json records superseded_by; its brief carries a closure note; the roadmap lists this spec and the two engine specs in dependency order.
  - Observable: spec status for real-world-vfc-slice shows closed and superseded; roadmap has the new order.
  - _Requirements: 8.3_
  - _Depends: 7.1_

- [x] 8. Amendment: review tiers and pointer slices
- [x] 8.1 Add review tiers to the label schema and the payload
  - `review_tier` on every pair with per-slice defaults; `per_tier` metrics in the payload; `title` rows load and replace the candidates file; `reviewed` requires a reviewer name.
  - Observable: agent-vfc rows load with tier `title`; `pairs --json` reports `per_tier`; a `reviewed` row without a reviewer is rejected by the loader.
  - _Requirements: 9.1, 9.2, 9.4, 9.5_
  - _Boundary: LabelSchema, Scorer_

- [x] 8.2 Gate the improve loop on seeded and reviewed tiers only
  - The per-profile holdout clause filters pair cases to `seeded | reviewed` before scoring; `advisory` and `title` pairs never gate.
  - Observable: a regression confined to `title` pairs does not reject a round; the same regression on `reviewed` pairs does.
  - _Requirements: 9.3_
  - _Boundary: ProfileGate_
  - _Depends: 8.1_

- [x] 8.3 Score non-vendored pointer pairs through a local cache
  - Catalog rows with `vendored = false` carry the recipe; evaluation harvests both sides into the cache when `OPENULTRASAST_PAIRS_NETWORK=1` (or `pairs --pointers`), otherwise skips with a degradation; the cache is git-ignored; tests and gates select vendored pairs only.
  - Observable: a pointer row evaluates to the same outcome shape as a vendored row when network is on, is skipped with `pointer_pair_skipped` when off, and no cache file appears under the repository.
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_
  - _Boundary: Scorer, HarvestLibrary_
  - _Depends: 8.1_

- [x] 8.4 Add the LLM-generated Real-Vuln repositories and unlicensed agent fixes as pointer pairs
  - vibe-py gains the 40 LLM-generated repositories as `agent`, `seeded`, `vendored = false` rows built by `build_recipes.py --pointers`; agent-vfc gains the license-less candidates as `title`, `vendored = false` rows.
  - Observable: `pairs --slice vibe-py --pointers --json` scores both provenances; the default suite and gates are unchanged.
  - _Requirements: 10.6, 5.1_
  - _Boundary: SliceCatalogs_
  - _Depends: 8.3_

## Implementation Notes

- Review round 1 (kiro-review, 2026-09-04) REJECTED groups 1, 2, 3, 5, 6; group 4 APPROVED. Remediated in round 2: mypy/ruff clean; `tool_hunter.py` reverted (HarnessX-preferring hunter client moved to `reachability-flow-model` as a task); weak labels never match on the inventory-fallback path; exact/alias sink matching restored; loader requires a named function on vfc-style slices; `catalog_gen.derive_function` ignores provenance headers and never emits `<anon>`; vfc-js rebuilt without duplicate/misattributed fixes; vendored Google API key redacted and a code-safe redaction pass added to `harvest.write_excerpt`; improve CLI fails loud on a missing pair catalog; profile tolerance compares pass rates; known-limit pairs emit no improve signals. RED evidence for the remediation tests was captured before the fixes (5 + 1 failing tests).
- Review round 2 (2026-09-05) APPROVED groups 1, 3, 4, 6; REJECTED groups 2 and 5. Remediated RED-first (4 failing tests captured, then green): `function_at` skips `<anon>` as well as `<module>`; the scorer matches a labeled function by line-range containment from the vulnerable side's parse (`_in_named_function`), name equality only when no range exists; the loader rejects reserved words as function labels; `catalog_gen` derives labels from the declarator on the range's start line (chained and property arrows covered), drops parse-failed excerpts instead of regex-labeling them, and `--prune` removes excerpt directories that are neither cataloged nor candidates (vfc-js: 16 pairs, 17 dirs incl. one candidate-less prune); the agent-vfc test asserts the empty-until-reviewed invariant explicitly.
- Review round 3 (2026-09-05) REJECTED groups 2 and 5 again; per protocol a fresh kiro-debug agent produced the fix plan (ROOT_CAUSE: scorer ranges used raw parser names while labels used declarator names; labels followed formatting hunks; no sink on vfc-js rows). Remediated RED-first (8 failing tests captured, then green): one shared helper `src/openultrasast/semantic/functions.py` (`declarator_name`, `named_function_ranges`, `function_at`, `spans_named`) used by `overlay._flows_for`, `pairs._overlay_scan`, `pairs._with_functions`, and `catalog_gen`; bare-parameter arrows and callback callees are never names; `_in_named_function` is containment-only and an unresolvable label is counted as `unresolved_function_labels` loss with a `!unresolved` miss marker; hunter matching uses containment too; harvest records `upstream_start` in every excerpt header (`extract_pair_with_lines`); `catalog_gen.derive_function` maps `sink_location` through `upstream_start` (±10 lines, CWE-family sink tokens, regex `.exec(` excluded), falls back to the unique function owning a sink token, then to the mapped line itself for wrapper sinks, and only then to the first non-whitespace hunk; vfc-js re-harvested with headers, regenerated with `--prune` (17 pairs, 17 dirs), `sink` emitted on 13/17 rows.
- Measured after review round 4 remediation (2026-09-05): sast 4/11 (achievable 4/10), Youden +0.273, unresolved 0; vibe-py 13/35, Youden +0.371 (inventory 7), unresolved 0, parse-failed 0; vfc-js 5/17, Youden +0.235, unresolved 0; vfc 0/176, Youden -0.131, parse-failed files 36, unresolved labels 23 after round 5: 18 pairs parse-failed on both sides (36 files, walker gap for overlay-ir-completeness); 3 pairs whose `.in` files `preprocess_repository` never lists as targets (`openssl-cve-2022-1292` and `openssl-cve-2022-2068-hash_dir` Perl `c_rehash.in`, `openssl-cve-2026-31790-rsasve_generate` C template `rsa_kem.c.in`; the Perl `sub` rule is dead on the scorer path until `.in` files are targeted, accepted as visible loss); 2 pairs whose multi-line declarators the walker leaves `<anon>` and the one-line regex cannot rescue (`chromium-cve-2022-2162`, `openssl-cve-2025-69421`: walker gaps). No unresolved label remains inside the Scorer boundary.
- Review round 4 (2026-09-05) REJECTED groups 2 and 5 on two defects, both fixed RED-first (4 failing tests captured): the shared helper now demotes undeclared parser names to `<anon>` only for JavaScript/TypeScript (bare-parameter arrows), so C/Java/Python keep their parser names when the return type sits on the previous line; `declarator_name` knows Perl `sub` and never names a statement (`return foo(`, `print(`, `synchronized (`); `catalog_gen` imports the package at module top and exits loud without it, `_ranges` no longer swallows exceptions, and `--prune` refuses to run when no recipe derived a label; the Python block extractor decides indentation on masked lines so triple-quoted strings never end a block (`vfapi-main-put-user` re-harvested, now parses).
- Review round 5 (2026-09-05) APPROVED group 5; REJECTED group 2 on one defect, fixed RED-first (2 failing tests captured, then green): `declarator_name` returned C++ qualified names (`FileReaderLoader::ArrayBufferResult`) that no unqualified catalog label matches, so both C++ vfc pairs were unresolvable and had been misattributed to the walker; the helper now returns the unqualified tail for the method form, `chromium-cve-2019-5786` resolves (vfc unresolved 24 -> 23), sast/vibe-py/vfc-js numbers unchanged, and the measured note above carries the corrected per-cause breakdown.
- Review round 6 (2026-09-05) APPROVED group 2 (verify-completion: `pytest -q` 468 passed / 4 skipped, extra-free 455 / 17 skipped, ruff/mypy clean, three gates PASS, reviewer reproduced RED by deleting the fix line and re-measured all four slices). Feature-level verdict stays REJECTED for completeness only: groups 7 and 8 open, two escalations undecided. Reviewer suggestions carried to the roadmap, not blocking: a multi-line-aware declarator rescue in `functions.py` would name the two `<anon>` C/C++ ranges without touching `cst.py`; the inventory-fallback miss strings lack the `!unresolved` suffix the overlay path attaches (counter is correct).
- Task 8.1 (2026-09-05, RED first: 6 failing tests captured — `REVIEW_TIERS`/`select_tier` missing, `reviewed` without reviewer accepted, no `per_tier` payload, agent-vfc absent from the default catalog, CLI payload lacked `per_tier`; then green): `PairCase.review_tier`/`reviewer`, `PairOutcome.review_tier`, `PairEvalResult.per_tier`, `select_tier`, `GATING_TIERS`; loader derives the tier from the row, else from `reviewer` (pending -> title, a name -> reviewed), else the slice default, and rejects unknown tiers and `reviewed` without a reviewer; `catalog_gen` stamps `review_tier` (and `reviewer`) on every generated row, `title` rows enter `catalog.toml`, `catalog-candidates.toml` is retired (deleted on regenerate); local rows carry `reviewer = "Marius Ciepluch"` (fixture author per git history). Task 7.1 evidence: default catalog loads 277 pairs across local/github/sast/vfc/vibe-py/vfc-js/agent-vfc with every file on disk and no name on the stage-1 `LANGUAGE_MANIFESTS`; `pairs --slice {vibe-py,vfc-js,agent-vfc} --json` exit 0 with `per_tier`, `per_profile`, `per_mechanism`; detection/map/local-pair gate outputs byte-identical to commit 0116f9b (pre-spec); extra-free suite 459 passed / 17 skipped; full suite 472 passed / 4 skipped; each of the six task commits is green in isolation (worktree bisect: 413 -> 430 -> 430 -> 430 -> 459 -> 465 -> 468 passed, ruff clean). Measured agent-vfc at tier `title`: 0/29, Youden +0.000 ({'typescript': 18, 'python': 6, 'javascript': 5}; no row in any language yields a finding on either side: the excerpts carry no rule-known sink (CORS defaults, missing guards, prototype pollution: title-guessed mechanisms, several wrong on inspection, e.g. `dnf-plugin-anyrepo-config-26d19a` has no path join); inventory rules do run on `.ts` files, but the overlay plane reports `language_unsupported` for TypeScript (18 rows) and counts them neither as parse-failed nor as a separate loss — mechanisms {'source_reaches_sink': 7, 'permissive_default': 6, 'path_join_user_input': 3, 'prototype_pollution': 7, 'missing_auth_guard': 1, 'identity_from_request_body': 5}), unresolved labels 1. This is the honest title-tier baseline the engine specs measure against, not a scoring defect. Task 5.3 closes with 8.1 as re-scoped: the slice loads and scores; human review promotes rows to `reviewed`.
- Review round 7 (2026-09-05) APPROVED tasks 7.1 and 7.2; REJECTED 8.1 on documentation only (REVIEW.md still described the candidates file; READMEs claimed the tier gate filter before 8.2 existed; TS zeros misattributed). Remediated: REVIEW.md/READMEs rewritten to tier semantics, note corrected, `catalog_gen._review_tier` precedence aligned with the loader (explicit tier wins), `training/manifest.jsonl` rows carry `review_tier`, design §LabelSchema candidates sentence superseded, roadmap agent-vfc line updated. Deferred to the engine specs: a `language_unsupported` loss counter (reviewer suggestion).
- Task 8.2 (2026-09-05, RED first: `test_profile_gate_ignores_title_and_advisory_tiers` failed with `reason='profile_regression:agent'` on five title-tier pairs; then green): `evolve.evaluate_profiles` filters holdout pairs to `GATING_TIERS` via `select_tier` before scoring, so `advisory`/`title` pairs never gate and a regression on `reviewed` pairs still rejects the round.
- Review round 8 (2026-09-05) APPROVED 8.1 and 8.2 (verify-completion: `pytest -q` 473 passed / 4 skipped, extra-free 460 / 17, ruff/mypy clean, three gates PASS; reviewer reproduced RED by removing the tier filter and checked the default holdout gate now covers `human` seeded pairs only, with the 16 title-tier agent rows excluded). Task 5.3 closed with 8.1 as re-scoped. Applied suggestion: the agent-vfc tier test accepts `reviewed` rows so promoting a row does not break it. Follow-up for corpus-seeded-mechanisms: report holdout profiles excluded by tier (`profiles_ungated`) so an operator sees why `agent`/`synthetic` do not gate.
- Task 8.3 (2026-09-05, RED first: 6 failing tests captured — `pointer_recipe`/`select_vendored` missing, loader `KeyError: 'vuln'` on a `vendored = false` row (x2), `pairs --pointers` unknown flag (`SystemExit: 2`), `validate_recipe(require_license=)` unknown, `catalog_gen` skipped pointer recipes as missing excerpts; then green): `PairCase.vendored`/`recipe`, `pair_cache_dir` (`OPENULTRASAST_PAIR_CACHE`, default `~/.cache/openultrasast/pairs`), `network_allowed` (`--pointers` per run or `OPENULTRASAST_PAIRS_NETWORK=1`), `select_vendored`, `_pointer_ready` (cached -> score; network -> `harvest.materialize_pointer` via the shared library; else `pointer_pair_skipped`; a failed fetch is `pointer_pair_fetch_failed`), `evaluate_catalog(pointers=)`; `harvest.validate_recipe(require_license=False)` and `materialize_pointer` (cache only, redaction applies); `catalog_gen` emits `vendored = false` rows with recipe fields and no excerpts, training manifest skips them; `pair_gate` scores vendored local pairs only; `.gitignore` covers the cache path. Smoke with real network on two Real-Vuln LLM-repo recipes into a scratchpad cache: network off -> 0 outcomes, 2 x `pointer_pair_skipped`; network on -> both harvested to `<cache>/vibe-py/<name>/{vuln,fixed}.py` and scored (silent fix on both, vuln side undetected, unresolved 0); nothing written under the repository. Suite 479 passed / 4 skipped, extra-free 466 / 17, ruff/mypy clean, three gates PASS.
- Review round 9 (2026-09-05) REJECTED 8.3 on two findings, both fixed RED-first (2 failing tests captured: warm cache + network off scored the pointer pair; `evaluate_profiles` kept an `agent` pointer pair): `_pointer_ready` consults `network_allowed` before the cache, so a warm cache only spares the fetch under `--pointers`/env and never turns a default run into a pointer run; `evolve.evaluate_profiles` applies `select_vendored` before the tier filter (design amendment: "tests and gates call `select_vendored`"; ProfileGate is the gate the design names, so the one-line filter is in boundary). Suggestions applied: fetch failures carry a `detail`; the harvest module load is memoized; pointer excerpt headers get `function`/`mechanism` from the expected row; `tests/conftest.py` autouse fixture clears `OPENULTRASAST_PAIRS_NETWORK` and points the cache at a temp dir for every test; full-catalog on-disk assertions use `select_vendored`.
- Review round 10 (2026-09-05) APPROVED 8.3 (verify-completion: `pytest -q` 481 passed / 4 skipped; extra-free 468 / 17 inside a no-network namespace; ruff/format/mypy clean; three gates PASS; reviewer reproduced both RED tests by mutation, the warm-cache/network-off skip on the real cache, and that the default run creates no cache and touches no network). Non-blocking: top-level README/docs mention `--pointers` only in benchmarks/pairs/README.md (ride with 8.4); the cwd-relative harvest library path follows the DEFAULT_CATALOG convention.
- Task 8.4 (2026-09-05, RED first: 4 failing tests captured — `build(pointers=)` unknown in the vibe-py builder, `merge_recipes` missing from the harvest library, the agent-vfc writer rendered booleans as strings, no pointer rows in the default catalog; then green): `harvest.merge_recipes` appends new recipes by name and never rewrites existing rows; `vibe-py/build_recipes.py --pointers` keeps the LLM-generated unlicensed repositories as `vendored = false`, `agent`, `review_tier = "seeded"` rows and appends them to recipes.toml (80 pairs over the 40 repositories; the 36 pre-existing recipes are byte-for-byte identical after reload; unlicensed human repositories stay skipped); `agent-vfc/build_recipes.py --from ... --pointers [--cache]` inverts the license rule, harvests each unlicensed candidate into the cache to derive its function label with `catalog_gen.derive_function`, dedupes against known commits/repos, and appends `title` pointer rows (30 added from a fresh 662-candidate search; 2 candidates failed to harvest, 10 had no named function; the 39 pre-existing recipes are identical). Catalogs regenerated: vibe-py 115 rows (35 vendored + 80 pointer), agent-vfc 59 rows (29 vendored + 30 pointer); training manifests unchanged (pointer rows carry no vendored files). Evidence for the observable, cache in the scratchpad: `pairs --slice vibe-py --pointers --json` scored 115 pairs, per_profile human 35 (13 correct, Youden +0.371) and agent 80 (0 correct, Youden 0.000; the LLM-repo baseline), all 80 pointer pairs fetched, no fetch failure; `pairs --slice agent-vfc --pointers --json` 1/59, Youden 0.000, unresolved 2; the default `pairs --slice vibe-py --json` scores 35 pairs and records 80 `pointer_pair_skipped`; `~/.cache/openultrasast` was never created. README/docs name the nightly `--pointers` command. Suite and gates unchanged (see round 11).
- Review round 12 (2026-09-05) verified every closure record, the runtime smoke, gates byte-identical to the pre-spec commit, and Req 1–10 coverage, and REJECTED the feature on one finding: `tests/test_pair_harvest.py` asserted redaction against a contiguous Google API key literal (introduced in the first task commit; the repository's push protection rejects such literals). Decision and fix: the key is now assembled at runtime (`"AIza" + "SyDEMO..."`, the `tests/test_redaction.py` convention) and, because the thirteen-commit series was local and unpushed, it was rewritten in place with a scripted `git rebase -x` so the literal exists in no commit (`git log -p` count 0); the temporary backup branch was deleted after the suite (485 / 472 passed), ruff and mypy were re-run green. Commit ids after 6cd842e changed; messages and trailers are unchanged.
- ESCALATION (task 5.1 observable) — CLOSED 2026-09-05 by the design amendment (Req 10) and task 8.4: the 40 LLM-generated Real-Vuln repositories have no license, so they are `vendored = false` pointer rows (80 pairs, `agent`, `seeded`) scored by `pairs --slice vibe-py --pointers`; `per_profile` reports human 35 and agent 80; Req 5.4 still holds (nothing unlicensed is vendored). The vendored vibe-py rows remain human-only by construction.
- ESCALATION (Req 5.3) — CLOSED 2026-09-05 by Req 9 (review tiers) via task 8.1: the agent-vfc rows load at `review_tier = "title"` (29 vendored + 30 pointer), are scored and reported, and never gate the improve loop; `catalog-candidates.toml` is retired and `REVIEW.md` is the queue a human works through by setting `reviewer` in recipes.toml, which promotes a row to `reviewed`.
- Review round 11 (2026-09-05) APPROVED 8.4 (verify-completion: `pytest -q` 485 passed / 4 skipped, also inside a no-network namespace; extra-free 472 / 17; ruff/format/mypy clean; gate outputs byte-identical to HEAD and to the pre-spec commit; reviewer reproduced RED on a HEAD worktree, 9 mutations, the `--pointers` fetch of evicted cache entries, and byte-identical catalog regeneration offline). Feature verdict was REJECTED on records only (stale escalations, roadmap, spec.json), fixed in the closing commit. Carry-forwards for the follow-on specs: offline unit test for `agent-vfc/build_recipes.py build(pointers=True)`; `sink` not propagated onto pointer catalog rows; the suite writes `.harnessx` under `$HOME` (pre-existing); `merge_recipes` lives in the harvest library because HarvestLibrary already owns recipe-file handling (design dependency SliceCatalogs -> HarvestLibrary).

- 2026-09-04 execution evidence (manual mode, main context): full suite `uv run pytest` 440 passed / 4 skipped; `python -m openultrasast.gate` PASS; `map_gate` PASS; `pair_gate` PASS (local 3/3); `ousast --help` boots. Validation commands come from `.github/workflows/ci.yml`.
- Scorer (2.1–2.3): coverage-with-source counts both ways; function-scoped match; CWE-only rows are `weak_label`; `scorers[slice]` has overlay+inventory for every overlay slice, `hunter` with a client; payload gains `per_profile`, `per_mechanism`, `achievable`, `known_limit`, `loss`, `degradations`. `OverlayRecord.function` is the one additive overlay field; `_flows_for` parses once and keeps function ranges.
- 2.4 baseline after the scorer change is in the roadmap (sast 4/11 → achievable 4/10; vfc 0/176 under function matching). Regex findings get an enclosing function from a parse so function-labeled rows can match the inventory column.
- 2.5 hunter scorer: `pairs --hunter [--hunter-model]`; client resolution prefers HarnessX (`resolve_hunter_client(prefer_harnessx=...)`, best-effort adapter, offline-untested) then any OpenAI-compatible endpoint via `OPENROUTER_API_KEY` + `OPENROUTER_BASE_URL` (DeepSeek documented in `.env.example`). Live run not executed in this session; scripted-client test covers the scorer.
- 3.x harvest: shared `benchmarks/pairs/harvest.py` (comment-blind `name`, `line_range`, `hunk` with next-function and whole-small-file fallbacks, `enclosing` with `fix_path`/`fix_line`), `vfc/harvest.py` is a shim; `catalog_gen.py --slice` regenerates catalogs and derives `function` for hunk-harvested pairs from the excerpt diff. 3.3: curl re-harvested; parse failures fell from 50 files to 36 (remaining are `#if`-split control flow and similar grammar limits, visible in `loss.parse_failed_files`; engine tolerance belongs to `overlay-ir-completeness`).
- 5.1 vibe-py: 35 pairs from the 15 licensed human-authored Real-Vuln repos. The 40 LLM-generated repos (`kolega-ai-dev/vc-*`) have no license file and were NOT vendored (Req 5.4); `build_recipes.py --allow-unlicensed` exists for local inspection only. So the slice currently has `human` provenance only; agent provenance comes from `agent-vfc`. _(dated note; superseded by task 8.4: the LLM repositories are pointer rows now)_
- 5.2 vfc-js: 15 pairs from upstream fix commits after dedupe by fix commit and module/repo attribution check (SecBench.js pointer only; 10 unlicensed upstreams, 3 duplicate fixes, 8 misattributed modules skipped; 2 excerpts without a named function not cataloged). `sink_location` is kept as metadata, not as the expected sink.
- 5.3 agent-vfc: 29 candidate pairs in `catalog-candidates.toml` (not loaded), all `reviewer = "pending"`; `REVIEW.md` is the review sheet. Mechanism/CWE were assigned from commit titles by `build_recipes.py` and must be confirmed by a human. 631 candidates were searched; 202 skipped for missing license; the loaded `catalog.toml` has 0 rows until review. _(dated note; superseded by task 8.1: rows load at tier `title`, the candidates file is retired)_
- 6.1 provenance: `src/openultrasast/provenance.py`, manifest `provenance` block, stage `provenance` in `_run_scan`.
- 6.3 profile gate: `run_round(pair_cases=..., profile_tolerance, min_holdout_pairs)`; CLI `improve --pair-catalog/--no-pair-gate/--profile-tolerance/--min-holdout-pairs`; default on with the full catalog holdout split (slower rounds).
- Measured after round-2 remediation (2026-09-04): sast 4/11 (achievable 4/10), Youden +0.273; vibe-py 13/35 pair-correct, Youden +0.371 (overlay) vs inventory 7/35, 0 weak labels; vfc-js 0/15, Youden −0.200 (2 parse-failed files, 0 weak labels; the earlier 5/32 was inflated by first-function labels and duplicate rows); agent-vfc 0 loaded rows, 29 candidates awaiting review.

- Do not touch `taint.py`, `facts.py`, `cst.py`, or `ir.py`. Parser ERROR-node tolerance belongs to `overlay-ir-completeness`; this spec only makes the loss visible.
- Expect vfc recall to drop when function-scoped matching lands. Record it; do not soften the matcher.
- BaxBench generation is deferred until deep mode can run its exploit harness; provenance and mechanism fields are designed so that slice slots in later.
