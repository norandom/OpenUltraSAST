# Brief: corpus-seeded-mechanisms

## Problem

The pair corpus is only a ruler. `pair-corpus-honesty` made it honest and is growing it past the license and review walls, but nothing in the tool learns from a labeled pair: the detector on an operator's tree is the same regex inventory plus intra-file taint whether the corpus holds 11 pairs or 1,100. The mechanism store that Clearwing uses as a library (`semantic/mechanisms.py`, JSONL plus an embedding cache) exists here but is filled only from sandbox-proven findings, so it is empty in practice and only reorders prove candidates.

Measured 2026-09-05: vibe-py 13/35 pair-correct, vfc-js 1/16, sast 4/10 achievable, vfc 0/176. Recall on real web code is where the tool is weakest, and web bug classes repeat structurally across projects (identity from the request body, `exec` of a request-derived string, path joined from a parameter, RLS or CORS left open).

## Desired Outcome

Every `seeded` or `reviewed` pair becomes a mechanism record: the source shape, the sink statement shape, and the guard the fix added. A structural variant search runs those shapes over any scanned tree and proposes matches, which the overlay and the sandbox then verify. Leave-one-out recall on the corpus is the corpus's own detection rate and rises as the corpus grows. The improve loop gains a lever that admits mechanisms, so it can raise recall instead of only defending it.

Principle written into the roadmap: **recall first under a false-positive ceiling, per provenance profile, and every reviewed pair becomes a searchable mechanism.**

## Approach

Derive a mechanism record from a pair by parsing the vulnerable excerpt with the existing `FileIR`, taking the sink call site the label names, the identifiers that carry the source, and the guard statements that appear only on the fixed side. Normalize into a language-scoped shape: sink callee name, argument arity, which argument positions carry source-derived identifiers, and the guard kind. Variant search walks a scanned tree's `FileIR`, finds call sites with the same shape whose arguments carry a fact source or a parameter, and emits `variant` findings at `suspicion` carrying the mechanism id; when the overlay already has a flow to that sink, the record is `coverage` with the mechanism id attached. Leave-one-out evaluation seeds from all pairs but one and scores the held-out pair. The improve loop proposes admitting a candidate mechanism when it recovers a missed holdout pair; the existing accept gate and the per-profile holdout clause decide.

## Scope

- **In**: mechanism export from pairs; shape normalization; variant search as a proposer in MAP; leave-one-out measurement command and payload; `mechanisms` improve lever with validator rules; store hygiene (tier, provenance, dedupe, version); offline tests.
- **Out**: LLM-authored shapes; changing dispositions or evidence rungs; embedding retrieval changes (existing prove-order reuse stays); inter-file flow (reachability spec); any merge gate; vendoring more pairs (corpus spec).

## Boundary Candidates

- Shape extraction (reads FileIR) vs overlay dispositions (unchanged)
- Mechanism store schema (additive fields) vs prove-order retrieval (unchanged consumer)
- Improve lever (admit/retract mechanisms) vs rule/policy levers (unchanged)

## Out of Boundary

- Taint semantics, facts, CST walker (`overlay-ir-completeness`, `guard-dominance-regime`)
- Call graph, summaries, hunter (`reachability-flow-model`)
- Pair scorer and catalogs (`pair-corpus-honesty`), except one read-only consumer of `PairCase`

## Upstream / Downstream

- **Upstream**: `PairCase`/`load_pair_catalog` with `review_tier`; `FileIR`; `MechanismStore`; `adjudicate`; `run_improvement` gate with per-profile holdout.
- **Downstream**: `reachability-flow-model` attaches paths to variant findings; `guard-dominance-regime` consumes the guard shapes as sanitizer candidates; reports show mechanism ids on findings.

## Existing Spec Touchpoints

- **Extends**: `propose-adjudicate-prove` mechanism memory (additive fields, second write path), `three-stage-scan` MAP stage (one more proposer), `harnessx-self-improving-rulesets` improve loop (one more bounded lever).
- **Depends**: `pair-corpus-honesty` Req 9 (tiers) for which pairs may seed.

## Constraints

Core `dependencies = []`. Variant findings never exceed `suspicion` without overlay or sandbox agreement. Mechanisms seed only from `seeded` or `reviewed` pairs. JSONL stays authoritative; caches are rebuildable. Leave-one-out is reported, never gated. No target code executes outside the sandbox.
