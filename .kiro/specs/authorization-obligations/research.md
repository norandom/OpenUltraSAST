# Research & Design Decisions

## Summary

- **Feature**: `authorization-obligations`
- **Discovery Scope**: Extension of the semantic layer (facts, shapes, store, MAP proposers), the entry-point mapper, reports, the pair corpus, leave-one-out and the improve lever; complex integration because it consumes two unimplemented upstream specs.
- **Key Findings**:
  - The absence pairs are real and structured. `vampi-books-get-by-title` has identical code on both sides except a constraint `user=user` bound from `token_validator(request.headers.get('Authorization'))['sub']`; the vulnerable branch queries `Book` by title alone. The difference is the provenance of a constraint, not a flow. 15 of 29 `agent-vfc` rows and 6 of the 19 non-teaching `vibe-py` pairs carry absence labels (`missing_auth_guard`, `permissive_default`, `identity_from_request_body`, `secret_in_client`, `validation_strength`).
  - The entry-point mapper already classifies every route as `public`, `authenticated` or `role-restricted` from its decorators (`mapping._python_route_access`), records the decorators as `access_evidence`, and lists `conditions` (`if` tests that look like checks). That is the sibling detector's upstream for path guards and needs no change.
  - `FileIR` binds carry `value_text`, `names` and `call_name`; `variants.source_kind_of_name` already traces a name through binds to a fact source, a parameter or a container read. Provenance of a constraint's value (authenticated context versus request input versus constant) is the same trace with one more source class.
  - `MechanismStore` rows carry a free `shape` dict and deterministic ids from `Shape.key()`; a second shape family fits without schema change. `MechanismEdit`, `apply_mechanism_edits`, `StoreSnapshot`, the tombstone and `evaluate_mechanism_profiles` are reusable as-is for a second lever family.
  - `reachability-flow-model` (unapproved) defines `PathRecord(entry, hops, sink, sink_line, sink_node, incomplete_at, ...)` and `compose(graph, summaries, entry_nodes, max_depth)`. Obligations need paths from an entry point to an *operation*, which is a sink-shaped target; the same `compose` works when obligated operations are passed as the sink set. `guard-dominance-regime` has no spec directory yet; only the roadmap line exists. Dominance must therefore be consumed through a narrow interface this design defines and the two upstream specs later satisfy.
  - The evidence ladder is closed: `OverlayRecord` allows `static_corroboration` and `suspicion`; proof rungs are forbidden outside the sandbox. Obligation findings are `StaticFinding`s at `suspicion` with the obligation label carried as data, so no ladder change is needed and Req 6.1 holds by construction.
  - The pair scorer counts promote and coverage-with-source records as detections; an obligation finding has no source or sink. Detection for obligation-labeled rows must be an additive rule keyed on the obligation label (allowed by the corpus spec's "one additive label field").

## Research Log

### What the absence pairs actually differ by

- **Context**: Decide whether absence bugs can be a shape family at all.
- **Sources Consulted**: `benchmarks/pairs/vibe-py` excerpts for `missing_auth_guard` and `permissive_default` rows; `benchmarks/pairs/agent-vfc/recipes.toml` mechanisms; `mechanisms.toml` definitions.
- **Findings**: three recurring differences: (a) a constraint added to a data access whose value comes from the authenticated context; (b) a guard call or decorator added before the operation (early return on a failed token check, `login_required`); (c) a literal changed from permissive to restrictive (`CORS(app)` → origins list, `DEBUG=True` → `False`, RLS enabled). A fourth, rarer: identity read from the body replaced by identity from the token (same as (a) seen from the other side).
- **Implications**: discharger kinds `identity_constraint`, `path_guard`, `ownership_check`, `non_permissive_value`, `validated_input`; the value provenance is the discriminating feature for (a) and (d).

### Where the policy comes from

- **Context**: Absence is relative to intent; the tool must not invent intent.
- **Sources Consulted**: `mapping.analyze_entry_points` (routes, access level, evidence), Real-Vuln repositories (many handlers per resource), Clearwing's sibling-comparison practice.
- **Findings**: in every Real-Vuln web app the handlers on one resource share a router and a model; the vulnerable handler is the odd one out. Route access classification already exists. A declared policy is the only way to say "this route is meant to be public"; the hunter can only guess it.
- **Implications**: consistency first (no declaration needed, measurable now), declared policy second (stronger rung), hunter last (records intent, never raises).

### Dominance before guard-dominance-regime exists

- **Context**: Req 5 needs "a discharger dominates the path"; the spec that owns dominance is not written.
- **Findings**: within one handler, the existing `FunctionIR` order of binds and calls gives statement order; a guard call followed by an early return before the operation line is dominance in the common case; decorators dominate the whole handler; middleware attached to the router dominates every route under it. Across calls, `PathRecord.hops` gives the sequence of nodes; a discharger on any hop before the operation node dominates the path when the hop's function returns early on failure.
- **Implications**: define `Dominance` as a narrow protocol (`dominates(witness, operation) -> bool`) with a built-in `OrderDominance` implementation (statement order in the handler, decorators, router middleware, hop order) that `guard-dominance-regime` may replace with nesting-aware dominance. The degraded mode (`function_local`) is `OrderDominance` without path records.

### Store and lever reuse

- **Context**: Avoid a second store and a second lever machinery.
- **Findings**: `Mechanism.shape` is a dict validated where used; `corpus_mechanism_id` hashes `shape.key()`; `validate_mechanism` checks guard and source kinds against `variants` constants. A second family needs its own closed kinds check and a `family` field in the shape dict; the tombstone, snapshot and profile clause need nothing.
- **Implications**: `ObligationShape.to_dict()` carries `family = "obligation"`; the lever validator dispatches on `family`; `search_tree` ignores obligation rows (they are not sink shapes) and the obligation checker ignores sink rows.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| Absence as a taint sink ("sink with a missing sanitizer") | Treat protected access as a sink needing an identity "sanitizer" | Reuses taint | Wrong semantics: the constraint is not a sanitizer of a flow; unconstrained access has no tainted argument | Rejected |
| Model-authored authorization rules | LLM writes per-project rules | Flexible | Violates no-model-authored-patterns; unverifiable | Rejected |
| Obligations with dischargers, policy from consistency plus declaration, path-aware | Closed facts, learned shapes, sibling anomaly, optional declared policy, dominance protocol | Zero-dep, measurable leave-one-out, honest rungs, grows with corpus | Coarse resource grouping; dominance approximated until the guard spec lands | **Selected** |
| Framework-specific authorization linters | Per-framework hard-coded checks | High precision | Regex growth, no learning, no policy | Rejected |

## Design Decisions

### Decision: Obligation findings are `suspicion` with a data label, not new ladder rungs

- **Context**: Req 6.1 names three labels; the ladder is closed and owned elsewhere.
- **Selected Approach**: `StaticFinding.evidence_level = "suspicion"`, tags `obligation:<kind>`, `discharger:<kind>`, `obligation_evidence:<label>`; reports render the label. Dispositions and `ALLOWED_EVIDENCE` unchanged.
- **Trade-offs**: SARIF consumers see `suspicion` plus properties; honest and non-invasive.

### Decision: Dominance is a protocol with an order-based default

- **Context**: `guard-dominance-regime` is unwritten; this spec cannot wait for it to be useful.
- **Selected Approach**: `Dominance` protocol; `OrderDominance` default (decorator, router middleware, statement order before the operation, hop order along a path). The guard spec replaces it without touching callers.
- **Trade-offs**: order-based dominance misses guards inside conditionals; recorded as the known coarseness and measured on the fixed twins.

### Decision: Policy is never written by the tool

- **Selected Approach**: `declared policy` is a hand-maintained file with a closed schema; the lever may only *propose* a clause, journaled as pending until a human accepts; scans never read pending clauses.

### Decision: Resource identity for sibling grouping

- **Selected Approach**: a handler's resource is the trailing segment of its route path with parameters stripped, joined with the operation's target token (model, table, collection name from the operation fact match); router or module is the second key. Coarse but deterministic and text-free.

## Risks & Mitigations

- Sibling grouping over-merges unrelated handlers → minimum sibling count, both keys required, siblings listed in the finding for review.
- Consistency leaks on legitimately public handlers → declared public routes suppress path-guard violations; leak rate on fixed twins reported per slice; the lever's holdout gate rejects shapes that leak.
- Order dominance misses conditional guards → `function_local` and `consistency_violation` labels stay below proof; guard spec replaces the default.
- Corpus excerpts lack registration context → new `handler_context` harvest mode; pointer pairs fetch whole files anyway.
- Two unimplemented upstream specs → this design degrades to function-local mode without path records, so tasks 1–6 are implementable before reachability lands; only path-aware evaluation waits.

## References

- `.kiro/specs/reachability-flow-model/design.md` (PathRecord, compose)
- `.kiro/specs/corpus-seeded-mechanisms/design.md` (store, lever, LOO)
- `src/openultrasast/mapping.py` (`EntryPointRecord`, `_python_route_access`)
- `src/openultrasast/semantic/variants.py` (`source_kind_of_name`, `classify_guard`)
