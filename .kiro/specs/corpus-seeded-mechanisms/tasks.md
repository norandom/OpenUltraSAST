# Implementation Plan

- [ ] 1. Foundation: shapes and store fields
- [ ] 1.1 Define structural shapes and derive them from a pair
  - `Shape` with language, sink name, arity, source positions and kinds, closed guard kind, mechanism id; `derive_shape` finds the labeled sink call site in the vulnerable `FileIR`, traces source positions through binds to a fact source, parameter, or container read, and classifies the guard from statements present only on the fixed side.
  - Shapes contain no path, line, or literal beyond identifiers.
  - Observable: a Python pair (request input into `os.system`, fix adds an allowlist) yields sink `system`, arity 1, source position 0, guard `allowlist_test`; an unlabeled sink returns None; the shape key is stable across runs.
  - _Requirements: 2.1, 2.2, 2.3, 2.4_
  - _Boundary: Shape_

- [ ] 1.2 Add additive mechanism fields and a corpus writer with dedupe
  - `Mechanism` gains origin, review_tier, pairs, shape, guard with defaults; `append_from_pair` dedupes by shape key and extends provenance; old JSONL rows load unchanged.
  - Observable: appending the same shape from two pairs yields one row listing both pairs; a pre-existing sandbox row loads with `origin = "sandbox"`.
  - _Requirements: 1.3, 1.4_
  - _Boundary: Store_
  - _Depends: 1.1_

- [ ] 2. Core: export and search
- [ ] 2.1 Export mechanisms from trusted pairs as a maintainer command
  - Only `seeded` and `reviewed`, non-known-limit, parse-ok pairs seed; the command runs offline over the vendored catalog and reports skipped pairs with reasons; extra-absent languages are skipped with a degradation.
  - Observable: `ousast mechanisms export --slice sast` writes corpus rows and reports the skipped `title`/`advisory`/known-limit pairs.
  - _Requirements: 1.1, 1.2, 1.5, 2.5_
  - _Boundary: Export_
  - _Depends: 1.2_

- [ ] 2.2 Search a tree for variants and merge with overlay flows
  - For each parsed file within the MAP budget, call sites matching a shape's sink name, arity, and source positions (fact source, parameter, container read) produce `variant` findings at `suspicion` with the mechanism id; when the overlay has a flow at the same call site, its record gains `mechanism_id` and no duplicate finding is emitted.
  - Observable: the split-sink Python fixture yields a variant finding merged into the overlay coverage record; a constant-argument call does not match; `quick` emits no variants.
  - _Requirements: 3.1, 3.2, 3.3, 3.6_
  - _Boundary: VariantSearch_
  - _Depends: 2.1_

- [ ] 2.3 Make variant findings sandbox-eligible and count them in the manifest
  - Variant findings enter the candidate set after overlay promotions under the existing safety check and caps; the manifest records mechanisms searched, files searched, findings, and merges.
  - Observable: with the fake sandbox a variant finding runs; the manifest `variants` block is present on standard scans and absent on quick.
  - _Requirements: 3.4, 3.5, 6.2_
  - _Depends: 2.2_

- [ ] 3. Measurement: leave-one-out
- [ ] 3.1 Evaluate the corpus leave-one-out
  - For each trusted pair, seed a temporary store from the others, search both excerpts, and score detection and silence with the pair rules; report per slice, profile, mechanism, and per pair which mechanism found it; write `loo.json`.
  - Observable: `ousast pairs --slice vibe-py --loo --json` reports recall, silence, Youden per slice/profile/mechanism and `found_by` per pair; the run is offline.
  - _Requirements: 4.1, 4.2, 4.3, 4.4_
  - _Boundary: LOO_
  - _Depends: 2.2_

- [ ] 3.2 Record the leave-one-out baseline
  - Roadmap gains a leave-one-out table per slice next to the pair baselines; not a gate.
  - Observable: roadmap table present; gates unchanged.
  - _Requirements: 4.4, 7.2_
  - _Depends: 3.1_

- [ ] 4. Integration: improve lever
- [ ] 4.1 Add the mechanisms lever with a closed validator
  - `MechanismEdit` admit/retract by record id from the exporter's candidate set; validator rejects free-form shapes and unknown guard kinds; journal records pair provenance and metrics.
  - Observable: a free-form edit is rejected; an admit edit of an exported record passes validation and appears in the journal.
  - _Requirements: 5.1, 5.2, 5.5_
  - _Boundary: Lever_
  - _Depends: 2.1_

- [ ] 4.2 Propose admissions from leave-one-out misses and retractions from leaks under the existing gate
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

- Seeding reads `PairCase.review_tier` from `pair-corpus-honesty` task 8.1; until it lands, sast and vibe-py rows default to `advisory`/`seeded` per that design and only vibe-py seeds.
- Guard classification is heuristic and closed; `none` is allowed and reported, never used to demote.
