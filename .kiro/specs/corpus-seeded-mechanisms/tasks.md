# Implementation Plan

- [x] 1. Foundation: shapes and store fields
- [x] 1.1 Define structural shapes and derive them from a pair
  - `Shape` with language, sink name, arity, source positions and kinds, closed guard kind, mechanism id; `derive_shape` finds the labeled sink call site in the vulnerable `FileIR`, traces source positions through binds to a fact source, parameter, or container read, and classifies the guard from statements present only on the fixed side.
  - Shapes contain no path, line, or literal beyond identifiers.
  - Observable: a Python pair (request input into `os.system`, fix adds an allowlist) yields sink `system`, arity 1, source position 0, guard `allowlist_test`; an unlabeled sink returns None; the shape key is stable across runs.
  - _Requirements: 2.1, 2.2, 2.3, 2.4_
  - _Boundary: Shape_

- [x] 1.2 Add additive mechanism fields and a corpus writer with dedupe
  - `Mechanism` gains origin, review_tier, pairs, shape, guard with defaults; `append_from_pair` dedupes by shape key and extends provenance; old JSONL rows load unchanged.
  - Observable: appending the same shape from two pairs yields one row listing both pairs; a pre-existing sandbox row loads with `origin = "sandbox"`.
  - _Requirements: 1.3, 1.4_
  - _Boundary: Store_
  - _Depends: 1.1_

- [x] 2. Core: export and search
- [x] 2.1 Export mechanisms from trusted pairs as a maintainer command
  - Only `seeded` and `reviewed`, non-known-limit, parse-ok pairs seed; the command runs offline over the vendored catalog and reports skipped pairs with reasons; extra-absent languages are skipped with a degradation.
  - Observable: `ousast mechanisms export --slice sast` writes corpus rows and reports the skipped `title`/`advisory`/known-limit pairs.
  - _Requirements: 1.1, 1.2, 1.5, 2.5_
  - _Boundary: Export_
  - _Depends: 1.2_

- [x] 2.2 Search a tree for variants and merge with overlay flows
  - For each parsed file within the MAP budget, call sites matching a shape's sink name, arity, and source positions (fact source, parameter, container read) produce `variant` findings at `suspicion` with the mechanism id; when the overlay has a flow at the same call site, its record gains `mechanism_id` and no duplicate finding is emitted.
  - Observable: the split-sink Python fixture yields a variant finding merged into the overlay coverage record; a constant-argument call does not match; `quick` emits no variants.
  - _Requirements: 3.1, 3.2, 3.3, 3.6_
  - _Boundary: VariantSearch_
  - _Depends: 2.1_

- [x] 2.3 Make variant findings sandbox-eligible and count them in the manifest
  - Variant findings enter the candidate set after overlay promotions under the existing safety check and caps; the manifest records mechanisms searched, files searched, findings, and merges.
  - Observable: with the fake sandbox a variant finding runs; the manifest `variants` block is present on standard scans and absent on quick.
  - _Requirements: 3.4, 3.5, 6.2_
  - _Depends: 2.2_

- [x] 3. Measurement: leave-one-out
- [x] 3.1 Evaluate the corpus leave-one-out
  - For each trusted pair, seed a temporary store from the others, search both excerpts, and score detection and silence with the pair rules; report per slice, profile, mechanism, and per pair which mechanism found it; write `loo.json`.
  - Observable: `ousast pairs --slice vibe-py --loo --json` reports recall, silence, Youden per slice/profile/mechanism and `found_by` per pair; the run is offline.
  - _Requirements: 4.1, 4.2, 4.3, 4.4_
  - _Boundary: LOO_
  - _Depends: 2.2_

- [x] 3.2 Record the leave-one-out baseline
  - Roadmap gains a leave-one-out table per slice next to the pair baselines; not a gate.
  - Observable: roadmap table present; gates unchanged.
  - _Requirements: 4.4, 7.2_
  - _Depends: 3.1_

- [x] 4. Integration: improve lever
- [x] 4.1 Add the mechanisms lever with a closed validator
  - `MechanismEdit` admit/retract by record id from the exporter's candidate set; validator rejects free-form shapes and unknown guard kinds; journal records pair provenance and metrics.
  - Observable: a free-form edit is rejected; an admit edit of an exported record passes validation and appears in the journal.
  - _Requirements: 5.1, 5.2, 5.5_
  - _Boundary: Lever_
  - _Depends: 2.1_

- [x] 4.2 Propose admissions from leave-one-out misses and retractions from leaks under the existing gate
  - Admit candidates that recover a currently missed holdout pair; retract admitted records that leak on holdout fixed sides; existing accept gate and per-profile clause decide; rejection reverts the store byte for byte.
  - Observable: a scripted candidate that recovers a holdout pair is accepted and persisted; one that leaks on a fixed side is rejected and the store is unchanged.
  - _Requirements: 5.3, 5.4_
  - _Depends: 4.1, 3.1_

- [ ] 5. Integration: reports
- [ ] 5.1 Show mechanism id, known fix guard, and provenance on findings
  - Markdown and SARIF show mechanism summary, guard shape, and pair provenance for findings carrying a mechanism id; variant findings are labeled suspicions unless raised.
  - Observable: a standard scan report on the split-sink fixture names the mechanism and its guard; SARIF properties carry the id.
  - _Requirements: 6.1, 6.3_
  - _Depends: 2.2_

- [ ] 6. Validation
- [ ] 6.1 Prove offline tests and unchanged gates
  - Unit and integration tests run without network, model, or sandbox; semantic-marked tests skip without the extra; detection, map, and local pair gates unchanged; extra-free suite green.
  - Observable: both pytest matrices green; gate entrypoints unchanged.
  - _Requirements: 7.1, 7.2, 7.3_
  - _Depends: 2.3, 3.1, 4.2, 5.1_

## Implementation Notes

- Spec approved by the maintainer in session 2026-09-05 ("continue with corpus-seeded-mechanisms"); approvals recorded in spec.json.
- Task 1.1 (2026-09-05, RED first: 5 failing tests in `tests/test_variants.py`, `ModuleNotFoundError: openultrasast.semantic.variants`; then green): `semantic/variants.py` with `Shape` (language, sink_name, arity, source_positions, source_kinds, guard, mechanism; `key()`/`to_dict()`/`from_dict()` text-free), closed `GUARD_KINDS`/`SOURCE_KINDS`, `derive_shape(vuln_ir, fixed_ir, *, function, sink, line, mechanism, facts, vuln_text, fixed_text)`. Deviation from the design signature: the two excerpt texts are passed in because guard statements (`if x not in ALLOWED`, `if len(x) > n`) are not call sites or binds in `FileIR`; the guard kind is classified from the lines of the labeled function that exist only on the fixed side, closed set, `none` when unknown; nothing of that text enters the shape. Source kinds trace argument identifiers through binds (fact-source pattern -> `fact_source`; subscript/`.get(`/request container -> `container_read`; parameter -> `parameter`), preferring fact_source, then parameter, then container_read. A constant-only sink call or a missing function/call site yields None.
- Task 1.2 (2026-09-05, RED first: 3 failing tests in `tests/test_mechanism_export.py` — `Mechanism` lacked `origin`, `append_from_pair` missing; then green): additive `Mechanism.origin/review_tier/pairs/shape/guard` with defaults so sandbox rows load unchanged; `MechanismStore.load()` folds the append-only log by id (latest row wins) so a re-seeded shape carries the extended `pairs`; `append_from_pair` uses a deterministic id `corpus:<sha1(shape.key())[:16]>` so the improve lever can name records across machines; `corpus_mechanisms()` selects searchable rows. Existing `order_promotions` tests unchanged and green.
- Review round 1 (2026-09-05) APPROVED 1.1 and 1.2 (reviewer re-simulated RED, ran six mutations, verified the import boundary and that sandbox rows load unchanged; isolated suite 493 / 480 green, statics and gates clean). Suggestions carried into group 2: trim `_CONTAINER_READ` to the design's subscript/`.get(` definition so no source vocabulary lives outside facts; intersect line and sink in `_labeled_call`; `append_from_pair` keeps the highest tier and accumulates provenance tags when a shape is re-seeded; sync design §Shape to the implemented signature.
- Task 2.1 (2026-09-05, RED first: 4 failing tests in `tests/test_mechanism_seed.py` — `ModuleNotFoundError: semantic.seed` x3, `argparse` rejected `mechanisms`; then green): `semantic/seed.py` `export_mechanisms(cases, store)` seeds only `seeded|reviewed`, non-known-limit, parsing pairs with cached excerpts, skips with reasons (`tier:<t>`, `known_limit:<why>`, `parse_failed`, `variants_language_unsupported` + degradation, `pointer_pair_not_cached`, `no_labeled_sink_call_site`) and keeps catalog order; CLI `ousast mechanisms export --slice S [--store P] [--json]`, default store `.openultrasast/calibration/mechanisms.jsonl` (the path the scan reads; the store module's `DEFAULT_MECHANISM_LOG` differs and is left alone). Discovery: vibe-py labels carry a function and a mechanism but no sink or line, so `derive_shape` gained a facts-driven fallback (the fact-sink call inside the labeled function, CWE-matching and non-constant first) and now intersects line and sink when both exist (round-1 suggestion); `_CONTAINER_READ` trimmed to subscript/`.get(`; `append_from_pair` keeps the highest tier and accumulates provenance tags. Measured export (offline, scratchpad stores): vibe-py 35 pairs -> 16 seeded, 10 records (7 pairs share `execute/1 parameter`; the 19 skips are absence-class labels — IDOR, open redirect, missing guard — with no sink call to shape); local 3 -> 0 (fixtures label no sink call site); sast 11 and vfc-js 17 -> 0, all `tier:advisory` as Req 1.2 requires. Guards are mostly `none` because Real-Vuln fixed twins are separate trap functions, not patched code.
- Task 2.2 (2026-09-05, RED first: 3 failing tests in `tests/test_variant_search.py`, `ImportError: match_shapes|VariantHit|search_tree`; then green): `variants.match_shapes(ir, shapes, facts, mechanism_ids=)` matches trailing callee name + arity and requires every shape source position to carry a source of any kind (a shape learned from `request.args` fires on a parameter); constants and arity mismatches never match. New module `semantic/variant_search.py` (design deviation: the file plan put `search_tree`/`hits_to_findings` in `variants.py`, but they need the store, the overlay records and `StaticFinding`, which `variants.py` must not import): `search_tree(root, targets, store, facts, max_mechanisms)` -> `SearchResult(hits, mechanisms_searched, files_searched, degradations)`; `hits_to_findings` merges a hit into an overlay promote/coverage record at the same path and line (`mechanism_id` set, no duplicate) and otherwise emits `variant:<id>:<path>:<line>` at `suspicion` with tags `variant`, `mechanism:<id>` and the pair provenance in the rationale. `OverlayRecord.mechanism_id` added (additive).
- Task 2.3 (2026-09-05, RED first: 3 of 4 tests in `tests/test_variant_scan.py` failing — no variant finding, no overlay merge, variant not offered to the sandbox; the quick-mode test passed trivially and guards the invariant; then green): `[variants] enabled=true, max_mechanisms=500` config; MAP runs `_search_variants` after the overlay (standard/deep only; skipped when facts fail to load), appends variant findings, rewrites overlay.json with merged ids, and the manifest carries `variants = {mechanisms_searched, files_searched, findings, merged_into_overlay}`; in REGRESS variant findings join the candidate list after the promotions with a zero-score hotspot each, under the same safety check and cap. Verified with the fake sandbox: a variant of a project-specific sink with no inventory rule is offered. Suite 504 passed / 4 skipped, extra-free 491 / 17, statics clean, three gates PASS.
- Task 3.1 (2026-09-05, RED first: 3 failing tests in `tests/test_loo.py` — `ModuleNotFoundError: semantic.loo` x2, `pairs --loo` unknown flag; the two API tests went green on the first implementation): `semantic/loo.py` `evaluate_loo(cases)` holds every scorable pair out once (known_limit and uncached pointer pairs skipped with a reason), seeds a temporary store from the *other* `seeded|reviewed` pairs (advisory/title pairs are scored as targets, never teach), materializes both sides, runs `search_tree`, and scores: detected when a hit lies inside the labeled function and names the labeled mechanism or sink; silent when the fixed side yields no hit; `found_by` lists the record id and the pairs that taught it; metrics (pairs, detected, silent, recall, silence, Youden, teaching) per slice, profile and mechanism; `to_dict()` is the `loo.json` artifact. Shape derivation is duplicated from `seed.py` (`_lessons`) pending a shared helper once group 2 is accepted. First measurement, vibe-py vendored (35 pairs, 1.0 s): 11 detected (recall 0.314), 21 silent (0.600), Youden -0.086, 16 teaching pairs; per mechanism source_reaches_sink 27 pairs 9 detected / 19 silent, missing_auth_guard 4 / 2 / 2, permissive_default 3 / 0 / 0, path_join_user_input 1 / 0 / 0. The 14 leaks are the coarse `execute/1 parameter` shape firing on Real-Vuln's false-positive trap twins: the honest over-match rate the `mechanisms` lever (group 4) retracts on.
- Review round 2 (2026-09-05) APPROVED 2.1, 2.2, 2.3 (reviewer re-simulated all three REDs, killed 11 of 12 mutants, ran the export offline in a network namespace and reproduced the counts, confirmed gates byte-identical to HEAD; judged the zero-score-hotspot candidate path a closer fit to Req 3.4 than the forced path). Suggestions carried into round 3: a test that a hit on a `demote`/no-flow overlay record is not merged (the surviving mutant); `search_tree` skips a malformed store row with `variants_store_row_invalid` instead of aborting the scan; design §VariantSearch/§Modified Files synced (`SearchResult`, `regress/candidate.py` untouched); `_load_variants` uses `_int_value`; the exporter passes line and sink together; `no_labeled_function` skip reason; one shared `hotspot_from_finding` helper.
- Round-2 suggestions applied (2026-09-05): `hits_to_findings` covered by `test_hits_never_merge_into_demoted_or_flowless_records`; `search_tree` skips a malformed store row with `variants_store_row_invalid` (the store loader keeps the raw shape dict and validation happens where the shape is used); `_load_variants` uses `_int_value`; `seed.pair_lessons(case, facts)` is the one derivation shared by the exporter and leave-one-out and passes line and sink together; `no_labeled_function` skip reason; `regress.candidate.hotspot_from_finding` is the one zero-score hotspot helper (forced sev-5 inventory and variants); design §VariantSearch/§Modified Files synced. Task 3.1 CLI: `pairs --slice S --loo [--loo-out P]` writes `loo.json` (default `reports/loo.json`) and prints per-slice recall/silence/Youden/teaching; task 3.2: roadmap carries the leave-one-out table (vibe-py 11/35 detected, 21 silent, Youden -0.086, 16 teaching; local/sast/github/vfc-js 0 teaching because their tiers never seed or their labels name no sink call).
- Task 4.1 (2026-09-05, RED first: 3 failing tests in `tests/test_mechanism_lever.py`, `ImportError: MechanismEdit`; then green after the store tombstone landed): `MechanismEdit(action, mechanism_id, source, rationale)` with lever `mechanisms` (`VALID_LEVERS` extended); `EvolveValidator.validate_mechanism(edit, candidates)` accepts only admit/retract of a record present in the exporter's candidate set with `origin = corpus`, a shape whose guard and source kinds are closed and whose `sink_name`/`language`/`mechanism` are identifiers (a forged guard `if user not in ALLOWED` or a sink `os.system(cmd + ' ')` is rejected); `apply_mechanism_edits(edits, candidates, scan_store) -> StoreSnapshot` appends the exporter record for admit and a `retracted = true` tombstone for retract (the log stays append-only; `MechanismStore.load()` folds tombstones away), `StoreSnapshot.restore()` is the byte-for-byte revert.
- Task 4.2 (2026-09-05, RED first: 2 failing tests in `tests/test_mechanism_loop.py` — `evaluate_mechanism_profiles` missing, `run_round` rejected `mechanism_candidates`; then green): `evolve.propose_mechanism_edits(holdout, candidates, scan_store)` retracts admitted records that leak on a holdout fixed side and admits a candidate only when a trial store holding it alone recovers a currently missed holdout pair and leaks nowhere; `evaluate_mechanism_profiles` scores the holdout pairs with a given store per provenance profile (pairs, pair_correct = detected and silent, pass rate, Youden); `run_round(..., mechanism_candidates=, mechanism_store=, scripted_mechanism_edits=)` validates mechanism edits with the same validator, applies them after the rule gate passed, re-scores, and rejects with byte-for-byte revert on `mechanism_leak:<id>`, `profile_regression:<profile>` (the existing per-profile clause over the before/after store metrics) or `mechanism_no_gain`; reverted keys are blocked in later rounds like rule edits; the journal records each mechanism edit with its pair provenance and `mechanisms_before`/`mechanisms_after`. This is the closed loop: leave-one-out misses propose, holdout leaks retract, the gate decides, the store is the only thing that changes. Design deviation recorded: the gate for mechanism edits is the per-profile clause computed by variant search (the change they make) rather than by the overlay scorer, which cannot see mechanisms; the rule gate and its clause are unchanged.
- Review round 3 (2026-09-05) APPROVED 3.1, 3.2, 4.1, 4.2 (reviewer re-simulated the three REDs, reproduced the roadmap table offline in a network namespace, confirmed no gate reads loo.json and gates byte-identical to HEAD, ran 16 mutants: 12 killed). Judged the variant-search-based per-profile clause for mechanism edits acceptable and required (design §Error Handling's leak row is only checkable through variant search). Carried into round 4: tests pinning the four surviving mutants (hit outside the labeled function, hit not naming the label, `mechanism_no_gain`, reverted mechanism keys re-proposed); forward `search_tree` degradations into `LooResult`; design §Lever sync (deviation, tombstone, reasons, `score_pair_with_store`); novelty gate keyed on the mechanisms lever regardless of rationale; exporter must not re-admit a standing tombstone (default `--store` to a candidates file); retraction allowed for admitted records absent from the candidate set; the `not a and b or c` precedence in the loop test.
- Seeding reads `PairCase.review_tier` from `pair-corpus-honesty` task 8.1; until it lands, sast and vibe-py rows default to `advisory`/`seeded` per that design and only vibe-py seeds.
- Guard classification is heuristic and closed; `none` is allowed and reported, never used to demote.
