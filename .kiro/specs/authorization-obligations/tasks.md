# Implementation Plan

- [ ] 1. Foundation: closed facts and obligation shapes
- [ ] 1.1 Load obligated operations and dischargers as closed facts
  - `data/facts/obligations.toml` with `[[operation]]` (id, kind, language, calls, resource_arg, requires, sensitivity) and `[[discharger]]` (id, kind, language, calls, decorators, identity_sources, constraint_params) for python, javascript, typescript; `load_obligation_facts(dir)` with `for_language`; `OPERATION_KINDS`, `DISCHARGER_KINDS`, `PROVENANCE_KINDS` closed.
  - Observable: the loader returns Python operation facts for ORM query and raw execute calls and discharger facts for `login_required`, token validators and `user`/`owner_id` constraint params; a file naming kind `"maybe_guard"` or an unknown field raises `ObligationFactsError` naming the entry; no code path detects an obligation without a matching fact.
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_
  - _Boundary: ObligationFacts_

- [ ] 1.2 Derive obligation shapes from trusted pairs
  - `ObligationShape` (language, operation_kind, discharger_kind, provenance, resource_class, mechanism, family="obligation") with text-free `key()`, `to_dict()`, `from_dict()`; `derive_obligation` finds the obligated operation in the labeled function on the vulnerable side and classifies the discharger the fixed side added together with the provenance of the value it binds (authenticated context, request input, constant) via `variants.source_kind_of_name`-style tracing over the identity sources.
  - Observable: the `vampi-books-get-by-title` pair yields `protected_read` / `identity_constraint` / `authenticated_context` / `owned`; a permissive-default pair yields `security_setting` / `non_permissive_value` / `constant`; a pair whose fixed side adds no discharger returns None with reason `no_discharger_added`; `key()` contains no path, line or literal and is identical for renamed identifiers.
  - _Requirements: 2.1, 2.3, 2.5_
  - _Boundary: ObligationShapes_
  - _Depends: 1.1_

- [ ] 1.3 Export obligation shapes through the existing store and exporter
  - `seed.pair_lessons` derives obligation shapes for rows carrying `obligation`; only `seeded|reviewed`, non-known-limit, parsing pairs seed; rows written with `append_from_pair` (family in the shape dict, `guard` = discharger kind), deduped by key with accumulated pairs; `obligation_mechanisms(records)` selector; sink-shape `search_tree` ignores obligation rows.
  - Observable: `ousast mechanisms export --slice vibe-py` reports the absence pairs that seeded and skips advisory/title/known_limit/parse-failed rows with reasons; two pairs with the same shape produce one row listing both; `search_tree` over a store holding only obligation rows searches 0 mechanisms.
  - _Requirements: 2.1, 2.2, 2.4_
  - _Depends: 1.2_

- [ ] 2. Core: operations, dischargers, siblings, policy, dominance, checker
- [ ] 2.1 Find operations and discharge witnesses in a parsed file (P)
  - `find_operations(ir, facts, ranges)` returns operation sites with kind, fact id, enclosing function and resource token; `find_discharges(ir, facts, flow_facts, ranges, entry)` returns witnesses with kind, provenance and scope (decorator, router, statement, hop) using the entry point's decorators and the handler's binds.
  - Observable: a Flask fixture with three handlers yields three `protected_read` operations on resource `book`; the handler with `@login_required` yields a `path_guard` decorator witness; the handler that binds `user` from `request.user` yields an `identity_constraint` witness with `authenticated_context`, and one binding from `request.args` yields `request_input`.
  - _Requirements: 3.1, 5.4_
  - _Boundary: Operations_
  - _Depends: 1.1_

- [ ] 2.2 Group sibling handlers and find consistency anomalies (P)
  - `sibling_sets(entries, operations, discharges)` keyed by (router or module, resource token); `consistency_anomalies(sets, min_siblings)` flags a handler that reaches an operation kind without a discharge its siblings perform; under-populated sets are counted, never reported; a public route among authenticated siblings is a missing `path_guard` with the access classification as evidence.
  - Observable: three `/books` handlers where two constrain by owner produce one anomaly naming the two siblings; with `min_siblings = 4` the same set produces none and is counted under-populated; anomalies never reference or alter existing findings.
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  - _Boundary: Siblings_
  - _Depends: 2.1_

- [ ] 2.3 Load the declared policy with a closed schema (P)
  - `load_declared_policy(path)` reads version, identity_source, `[[resource]]` (name, sensitivity, identity_field), `[[route]]` (path, access, roles); unknown field or value raises `PolicyError` naming it; `version_hash`; absent file returns None.
  - Observable: a valid file loads with its hash; a file with `access = "sometimes"` or an extra key is rejected naming the field; the scan wrapper records `policy_invalid` and continues.
  - _Requirements: 4.1, 4.2_
  - _Boundary: DeclaredPolicy_

- [ ] 2.4 Dominance protocol with an order-based default (P)
  - `Dominance` protocol `dominates(witness, operation, path)`; `OrderDominance`: decorator and router witnesses dominate the handler; a statement witness dominates when it precedes the operation with an early exit between them or is a guard call; along a `PathRecord` a witness on an earlier hop dominates.
  - Observable: a guard call before the operation with a `return` in between dominates; the same call after the operation does not; a witness on hop 1 of a stub `PathRecord` dominates an operation on hop 3; the checker accepts any object implementing the protocol.
  - _Requirements: 5.1, 5.2_
  - _Boundary: Dominance_

- [ ] 2.5 The obligation checker: path-aware and function-local
  - `check_obligations(irs, entries, facts, flow_facts, policy, paths, dominance, store_shapes, min_siblings)` → `ObligationResult`; reached = a path ends at the operation or (no paths) the operation's function is an entry point; label precedence declared > consistency > `function_local`; a declared public route suppresses `path_guard` obligations for that route only; `known_fix` from a matching store shape; identity constraints bound from request input are reported with that provenance; `findings_to_static` emits `obligation:<kind>:<path>:<line>` at `suspicion` with tags `obligation:*`, `discharger:*`, `obligation_evidence:*`.
  - Observable: the three-handler fixture without paths yields one finding labeled `consistency_violation` naming the missing `identity_constraint` and both siblings with a `function_local`-mode degradation recorded once; with a declared protected resource the label becomes `declared_policy_violation` naming the clause; a declared public route removes the guard finding but keeps the identity one; with a stub path whose earlier hop discharges, no finding; evidence level is always `suspicion`.
  - _Requirements: 3.6, 4.3, 4.4, 5.1, 5.2, 5.3, 5.4, 6.1_
  - _Depends: 2.2, 2.3, 2.4_

- [ ] 3. Integration: scan, reports, ranking, intent
- [ ] 3.1 Run the checker in MAP with config and manifest counters
  - `[obligations] enabled=true, min_siblings=3, policy_path`; MAP runs `_check_obligations` after variant search in standard and deep only, with `PathRecord`s when the reachability artifact is present and `OrderDominance` otherwise; findings appended; manifest `obligations = {sibling_sets, under_populated, operations, findings_by_label, policy_version, degradations}`; obligation findings never enter the sandbox candidate set.
  - Observable: a standard scan of the fixture writes one `obligation:` finding and the manifest block with `policy_version: null`; quick has neither; with a policy file the block carries its hash; the deep scan's verdicts contain no obligation finding.
  - _Requirements: 4.1, 5.3, 5.5, 6.5_
  - _Depends: 2.5_

- [ ] 3.2 Reports and ranking name the obligation (P)
  - Markdown lines `Obligation`, `Missing discharger`, `Evidence`, `Known fix`, `Intent` per finding and a `## Obligations` section (sibling sets, policy version); SARIF `obligation_*` properties; `rank` weight = sensitivity x label weight (declared > consistency > function_local), capped strictly below the lowest sandbox-proven finding.
  - Observable: the fixture's report shows the missing `identity_constraint`, the two siblings and the known fix learned from the pairs; SARIF carries the properties with `evidence_level = "suspicion"`; in a run with one sandbox-proven finding the obligation finding ranks below it; reports without obligations are unchanged.
  - _Requirements: 6.1, 6.2, 6.4_
  - _Boundary: reports, rank_
  - _Depends: 2.5_

- [ ] 3.3 Hunter adjudicates intent without raising evidence (P)
  - When the hunter client resolves, ask one closed question per route-bearing finding ("is this route meant to be public?") with redacted handler text and sibling names; record `intent` and the rationale; absent client → `intent_adjudication_unavailable` once; the label and evidence level never change.
  - Observable: with a scripted client answering `public`, the finding's rationale carries the adjudication and its label is unchanged; without a client the degradation appears once and findings are identical.
  - _Requirements: 6.3_
  - _Boundary: IntentAdjudication_
  - _Depends: 2.5_

- [ ] 4. Corpus: absence pairs with context, labels, leave-one-out
- [ ] 4.1 Harvest mode `handler_context` and the `obligation` label (P)
  - Harvest library mode keeping the labeled function with its decorators and the registration statements naming it on both sides; `ExpectedFinding.obligation` additive; the pair scorer counts a finding tagged `obligation:<kind>` inside the labeled function as a detection for obligation-labeled rows; vocabulary gains `unconstrained_protected_read`, `unconstrained_protected_write`, `unguarded_privileged_action`; loader rejects unknown obligation kinds.
  - Observable: harvesting a fixture handler keeps `@app.route` and `@login_required` in the excerpt; a catalog row with `obligation = "protected_read"` loads and is detected by an obligation finding in its function; a row with `obligation = "guess"` is rejected; existing catalogs load unchanged.
  - _Requirements: 7.1, 7.2, 7.3_
  - _Boundary: harvest, pairs_

- [ ] 4.2 Leave-one-out per obligation kind
  - `loo.score_pair_with_store` runs `check_obligations` on both sides for obligation rows with the held-out store's obligation shapes; `per_obligation_kind` metrics; `found_by` names the shape record that supplied `known_fix`; `pairs --loo` payload and roadmap table gain the obligation kinds.
  - Observable: a three-pair toy slice (two teach `protected_read`/`identity_constraint`, one teaches `security_setting`) reports the identity pairs found by each other and the setting pair unfound; the real vibe-py and agent-vfc absence pairs report a baseline per kind; the roadmap table row is present and no gate reads it.
  - _Requirements: 7.4, 7.5_
  - _Depends: 1.3, 2.5, 4.1_

- [ ] 4.3 Relabel and re-harvest the corpus absence pairs
  - vibe-py and agent-vfc rows whose mechanism is an absence kind gain `obligation`; the agent-vfc absence rows are re-harvested in `handler_context` mode (pointer rows through the cache); catalogs regenerated idempotently; nothing unlicensed vendored.
  - Observable: `mechanisms export` seeds at least one obligation shape from vibe-py; the vendored catalogs still load with unchanged vendored counts; gates unchanged.
  - _Requirements: 7.2, 7.5_
  - _Depends: 4.1_

- [ ] 5. Integration: the obligations lever
- [ ] 5.1 Validator dispatch on shape family and pending policy clauses
  - `validate_mechanism` dispatches on `shape["family"]`: obligation rows check operation kind, discharger kind, provenance and resource class against the closed sets; `PolicyClauseEdit(kind, fields, evidence, rationale)` validated against the policy schema and journaled under `pending_policy_clauses`, never applied.
  - Observable: an obligation row with `discharger_kind = "if user"` is rejected; a valid row admits; a clause edit lands in the journal as pending and a following scan reads no policy from it.
  - _Requirements: 4.5, 8.1, 8.2, 8.4, 8.5_
  - _Boundary: Lever_
  - _Depends: 1.3_

- [ ] 5.2 Propose obligation admissions and retractions under the existing gate
  - `propose_mechanism_edits` treats obligation rows like sink rows (a trial store recovers a missed holdout absence pair without leaking → admit; an admitted row firing on a fixed twin → retract); `evaluate_mechanism_profiles` runs the checker for obligation rows; rejection reverts the store byte for byte; journal carries pair or sibling provenance and metrics before and after.
  - Observable: a scripted admission that recovers a holdout absence pair is accepted and persisted; one that fires on a fixed twin is rejected with `mechanism_leak` and the store unchanged; `ousast improve` picks obligation candidates up from the same candidates file.
  - _Requirements: 8.3, 8.5_
  - _Depends: 5.1, 4.2_

- [ ] 6. Validation
- [ ] 6.1 Prove offline tests and unchanged gates
  - Every component unit-tested on local fixtures; semantic-marked tests skip without the extra; detection, map and local pair gates unchanged; extra-free suite green; no test needs network, model or sandbox.
  - Observable: both pytest matrices green; gate stdout byte-identical to the pre-spec commit; a network-blocked run of the obligation tests passes.
  - _Requirements: 9.1, 9.2, 9.3_
  - _Depends: 3.1, 3.2, 3.3, 4.3, 5.2_

## Implementation Notes

- Requirements approved 2026-09-05, design approved 2026-09-05 (maintainer, in session).
- Path-aware evaluation (5.1) is wired through the `Dominance` protocol and an optional `PathRecord` input; until `reachability-flow-model` lands, every run is function-local by construction and tests use a stub `PathRecord`. No task here waits on the upstream specs.
- Sibling grouping keys on (router or module, resource token). If the maintainer prefers data-model-only grouping, only task 2.2 and its tests change.
