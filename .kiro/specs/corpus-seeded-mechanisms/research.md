# Research & Design Decisions

## Summary

- **Feature**: `corpus-seeded-mechanisms`
- **Discovery Scope**: Extension of mechanism memory, MAP stage, pair eval, and the improve loop
- **Key Findings**:
  - `semantic/mechanisms.py` already has `Mechanism`, `MechanismStore` (append-only JSONL), `append_mechanism`, embedding cache, hard filters by language/CWE/tags, and `order_promotions`. It is written only by `cli._append_proven_mechanisms` after a sandbox trigger, so it is empty on every real tree.
  - Clearwing's recall lever is the variant loop: a proven mechanism becomes a structural search over the messy tree. OpenUltraSAST copied the store and the retrieval, not the loop.
  - `FileIR` call sites already carry callee name, argument texts, argument identifier lists, and constant flags; binds carry source text and names. That is enough for a shape without new parsing.
  - The pair scorer (`pair-corpus-honesty`) gives labeled function, mechanism id, provenance, and soon a review tier; the fixed excerpt gives the guard the fix added by diffing statement kinds.
  - The improve loop has bounded levers with a validator, journal, byte-for-byte revert, and now a per-profile holdout clause; a `mechanisms` lever fits without changing the gate.
  - Measured 2026-09-05: vibe-py 13/35, vfc-js 1/16, sast 4/10 achievable. Web classes repeat structurally (request-derived string into `exec`/`execute`, identity from the body, `os.path.join` with a parameter, permissive defaults), which is what a shape search catches.

## Research Log

### Mechanism store today

- **Context**: Can the existing store carry corpus-derived records?
- **Sources Consulted**: `semantic/mechanisms.py`, `cli.py` `_append_proven_mechanisms`, `propose-adjudicate-prove` design §Mechanism.
- **Findings**: `Mechanism` fields are summary, cwe, language, tags, keywords, what_made_it_exploitable, source_finding_id, source_repo. Identity is the pattern. JSONL is authoritative; vectors are a rebuildable cache keyed by id and model.
- **Implications**: add `origin` (`sandbox` | `corpus`), `review_tier`, `pairs`, `shape` (structured), `guard` as additive fields with defaults so old rows load. A second writer (`append_from_pair`) beside the sandbox writer.

### Shape derivation from FileIR

- **Context**: Avoid regex and LLM authoring.
- **Sources Consulted**: `semantic/ir.py` (`CallSite.arg_names`, `arg_is_constant`, `Bind.names`, `FunctionIR.params`), `semantic/taint.py` (`_source_in`, parameter seeding).
- **Findings**: for the labeled function, the sink call site is the call whose trailing name equals the label's sink or whose line equals the label's line; source positions are argument indexes whose identifiers trace by binds to a fact source, a parameter, or a container read. Guard kind comes from statements on the fixed side absent on the vulnerable side: `if` with `== NULL`/`is None`/`!x` → `null_test`; comparison with `<`, `>`, `len(` → `bounds_test`; membership in a literal collection or `startswith`/regex → `allowlist_test`; identity read from an auth context (`request.state`, `req.user`, `session`) → `auth_check`; parameterized second argument → `parameterized_call`; changed declared type → `type_change`.
- **Implications**: `semantic/variants.py` implements `derive_shape(pair_ir_vuln, pair_ir_fixed, label)` and `match_shape(file_ir, shape)`. Guard classification is heuristic and closed; unknown → `none`.

### Where variant search sits

- **Context**: Propose, adjudicate, prove roles must stay separate.
- **Sources Consulted**: `three-stage-scan` design (MAP stage, hunter suspicion), `propose-adjudicate-prove` (overlay records, coverage), `regress/candidate.py`.
- **Findings**: MAP already runs overlay and the tool hunter; variant search is a third proposer that reads `FileIR` and the store. Findings at `suspicion`, origin `variant`; when the overlay has a flow at that call site, merge (attach mechanism id to the overlay record). Candidate eligibility follows the hunter-eligibility path being added in `reachability-flow-model` or the sev-5 forced-hotspot path today.
- **Implications**: no disposition change; one new finding origin; manifest counters.

### Leave-one-out

- **Context**: Prove that corpus growth raises recall, honestly.
- **Findings**: pair eval materializes each side into a temp tree already; a leave-one-out runner seeds a temp store from the other trusted pairs and runs variant search on both sides, scoring with the pair scorer's detection and leak rules.
- **Implications**: `pairs.py` gains a read-only consumer path (`evaluate_loo`) or a sibling module `semantic/loo.py` to keep the scorer's boundary; report per slice, profile, mechanism; artifact only.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| Embedding retrieval only | Rank existing promotions by mechanism similarity | Already exists | Cannot propose anything new; store empty | Rejected as recall lever |
| LLM writes Semgrep rules from pairs | Model authors patterns | Flexible | Unbounded pattern text, unverifiable, violates no-model-authored-patterns | Rejected |
| Structural shapes from FileIR plus variant search | Closed shape vocabulary, deterministic match | Zero-dep, bounded, testable leave-one-out | Shapes coarse; guard heuristics | **Selected** |
| Fine-tuned classifier on pairs | ML detector | Learns anything | Opaque, no fix guidance, data too small | Rejected |

## Design Decisions

### Decision: Seed only from seeded and reviewed tiers

- **Context**: `title` pairs are unreviewed guesses; `advisory` pairs have correct fixes but unlabeled mechanisms.
- **Selected Approach**: export reads `review_tier`; `advisory`/`title` may be scored leave-one-out as held-out targets but never seed.
- **Trade-offs**: fewer seeds at first; honest about what the detector was taught.

### Decision: Variant is a proposer at suspicion

- **Context**: Evidence honesty.
- **Selected Approach**: origin `variant`, `suspicion`; merge with overlay flow when present; sandbox may raise.
- **Trade-offs**: variant-only hits do not fail CI; correct.

### Decision: Lever admits records, not shapes

- **Context**: Keep the validator closed.
- **Selected Approach**: `mechanisms` lever edits reference record ids produced by the exporter; free-form shapes are rejected.

## Risks & Mitigations

- Coarse shapes over-match (`exec(x)` everywhere) — source-position requirement plus fact/parameter/container check; report leak rate on fixed sides leave-one-out; the per-profile gate rejects admissions that leak.
- Guard heuristics misclassify — closed set with `none`; reported, not used for demotion.
- Store growth — dedupe by shape; one record per shape with pair provenance list.
- Leave-one-out cost — one temp store per pair over tens of pairs; fine; cache parsed IR per excerpt.

## References

- `semantic/mechanisms.py`, `semantic/ir.py`, `semantic/taint.py`
- `.kiro/specs/propose-adjudicate-prove/design.md` §Mechanism (Clearwing reference architecture)
- `.kiro/specs/pair-corpus-honesty/` (review tiers, pointer slices, scorer rules)
- `.kiro/specs/harnessx-self-improving-rulesets/design.md` (bounded levers, accept gate)
- Clearwing sourcehunt mechanism memory and variant loop (reference, not a dependency)
