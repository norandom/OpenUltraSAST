# Brief: authorization-obligations

## Problem

The detector, the overlay and the new variant search all model one thing: attacker data flowing from a source to a sink. The pair corpus shows that the bugs concentrated in vibe-coded and agent-written web code are not flows. They are absences: a handler that queries a user-owned record by id without constraining it to the caller (`vampi-books-get-by-title`: the safe branch adds `user=user` bound from the validated token; nothing else differs), a privileged route with no guard on its path, an identity taken from the request body instead of the authenticated context, a security control left at its permissive default. In `agent-vfc`, 15 of 29 rows carry such labels (`permissive_default`, `missing_auth_guard`, `identity_from_request_body`, `secret_in_client`); in `vibe-py`, 6 of the 19 pairs that could not teach a mechanism are absence pairs, and the overlay scores 0 on all of them.

Nothing in the pipeline can represent "this operation should have been guarded" or "this query should have been constrained by the caller's identity". A flow bug is wrong in any program. An absence bug is wrong only relative to the application's own policy: which resources are protected, which routes are meant to be public, who may act on what. That policy is never written down in the code, so the tool has to recover it, and vulnerability hunting alone cannot.

## Desired Outcome

Absence bugs become first-class, measured, and honest. An obligated operation (protected data access, privileged action, security configuration) reached from an entry point without a discharger (a dominating auth guard, an identity constraint bound from the authenticated context, a non-permissive value) is reported as an obligation violation, with the missing discharger kind, the evidence for why the obligation exists (sibling handlers that discharge it, or a declared policy clause), and the known fix shape the corpus taught. Leave-one-out on the absence pairs is the objective, per obligation kind and per provenance profile, so the number rises as the corpus grows. `agent-vfc` and `vibe-py` absence pairs move from 0 detected to a measured baseline that the engine specs can raise.

Principle written into the roadmap: **an operation carries obligations, not only data; the application's own consistency and its declared policy say which, and the tool reports the missing discharger rather than a phantom flow.**

## Approach

Obligated operations and discharger kinds are closed facts data, like sinks and sanitizers today: operation kinds (protected read or write on an owned resource, privileged action, security-relevant setting) and discharger kinds (path guard, identity constraint from authenticated context, ownership check, non-permissive literal, validated input). An obligation shape is learned from a trusted pair the way a mechanism shape is: the fixed side's added discharger and the provenance of the value it binds (authenticated context, not request input) are the lesson; the shape carries no text. Policy comes from two sources that need no model authoring: consistency (siblings on the same resource or router that discharge the obligation make the one that does not the anomaly) and an optional declared, versioned policy file per project (protected resources, public routes, identity source, roles). A violation is only real when an entry point reaches the operation with no discharger dominating the path, which is the reachability model plus the guard-dominance regime already drafted for memory bugs applied to web obligations; without the path model the check degrades to function-local at a lower rung with a recorded degradation. Reports name the obligation, the missing discharger, the siblings or the policy clause, and the known fix; the hunter may adjudicate intent ("is this route meant to be public?") because that is a question of meaning, not pattern. The improve loop gains a lever that admits obligation shapes and proposes policy clauses only from consistency evidence, under the existing per-profile holdout gate.

## Scope

- **In**: obligated-operation and discharger facts; obligation shapes derived from pairs; consistency detection across sibling handlers; optional declared policy file with a closed schema; path-aware violation evaluation with a function-local degraded mode; new evidence rungs and report wording for obligations; worth-fixing weighting by resource sensitivity; corpus recipe shape for absence pairs (handler plus registration context); leave-one-out per obligation kind; `obligations` improve lever; offline tests.
- **Out**: taint or facts changes for flow bugs; the call graph and path records themselves (reachability spec); guard-dominance IR (guard-dominance-regime); LLM-authored policy or shapes; any merge gate; vendoring unlicensed code; sandbox proof of absence bugs (they do not crash).

## Boundary Candidates

- Obligation facts and shapes (new, data plus derivation) vs sink/source facts and taint (unchanged)
- Consistency detector over sibling handlers (new) vs entry-point mapper (read: routes, access level, decorators)
- Declared policy file and loader (new, closed schema) vs rule ledger and CWE policy (unchanged)
- Path-aware obligation check (new consumer) vs path records and dominance (owned upstream)
- Obligation rungs and report wording (new) vs the flow ladder and dispositions (unchanged)
- `obligations` lever (new) vs rule, policy and mechanisms levers (unchanged)

## Out of Boundary

- Taint semantics, walker, facts for flows (`overlay-ir-completeness`)
- Call graph, summaries, path records, hunter client (`reachability-flow-model`)
- Guard and Use IR records, dominance computation (`guard-dominance-regime`)
- Pair scorer rules and catalog schema (`pair-corpus-honesty`), except one additive label field for the obligation kind and the registration-context excerpt mode in the harvest library
- Mechanism store and variant search for sink shapes (`corpus-seeded-mechanisms`), reused as-is for the obligation shapes' storage and lever machinery

## Upstream / Downstream

- **Upstream**: `EntryPointRecord` (route, access level, decorators, conditions); `FileIR`; path records and dominance from the two engine specs; `PairCase` with `review_tier`; `MechanismStore` and the lever machinery; facts loader.
- **Downstream**: reports and SARIF; worth-fixing ranking; the roadmap's leave-one-out table gains obligation kinds; `guard-dominance-regime` consumes obligation discharger kinds as guard candidates for web code.

## Existing Spec Touchpoints

- **Extends**: `corpus-seeded-mechanisms` (second shape family, same store, same lever contract), `pair-corpus-honesty` (registration-context excerpt mode, obligation label), `three-stage-scan` (one more proposer in MAP, new rungs below proof).
- **Depends**: `reachability-flow-model` (entry point to operation paths); `guard-dominance-regime` (a guard dominates the path). Reachability is now on the critical path for two consumers.

## Constraints

Core `dependencies = []`. Obligation findings never claim a proof rung; they carry `consistency_violation` or `declared_policy_violation` and stay below sandbox-proven evidence. No policy clause or shape is authored by a model; the hunter may only adjudicate intent on an existing finding. Facts and policy schemas are closed; extension is data, never regex growth. Consistency needs a minimum sibling count and is reported with the siblings. Leave-one-out and consistency precision on fixed twins are reported, never gated; `local` stays the only CI-failing slice.
