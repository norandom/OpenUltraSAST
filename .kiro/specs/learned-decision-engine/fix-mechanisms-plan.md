# Plan: learn fix mechanisms into the engine (draft for review, 2026-10-04)

Status: proposed. Not approved. Amends the learned-decision-engine spec once the maintainer approves it.

## Why

The Joern trace run over exp-005's 501 units shows the engine cannot tell a vulnerable function from its
fix. In the 105 pairs where both sides were analysed, a taint path appears on both sides in 12, on the
vulnerable side only in 2, on the fixed side only in 0, and on neither in 91
(`benchmarks/measurements/2026-10-04-joern-slice-leak-audit/record.json`).

So the fix is invisible to the engine. Either the flow survives and the engine does not know the fix's
mechanism (an `allowed_classes` argument, a path normalisation check, an escaping call), or the engine's
sources and sinks miss the function on both sides. A classifier fed this evidence cannot improve on it.

The corpus now holds 710 complete fix pairs (`2026-10-04-decision-engine-harvest-3/record.json`). Each fix
diff shows what was added. That is the material the engine lacks.

## Goal

Grow the engine's discharge knowledge (sanitizers, guards, safe-argument forms) and, second, its source and
sink coverage, from the fix diffs. Admit a fact only when it improves held-out separation. Spend no model
money.

## Requirements (proposed)

1. **Mining.** From each fix pair, extract what the fixed function adds on the vulnerable flow: new calls,
   new conditions guarding the sink, new or changed sink arguments. Record each as a candidate fact with its
   language, family, form (sanitizer call, guard predicate, safe argument, sink restriction) and the pairs
   that propose it. Mining is deterministic (tree-sitter diff of the two function bodies). No model calls.
2. **Generalisation is explicit.** A candidate is a pattern, not a repository name: a callee name, an
   argument key, a predicate shape. Candidates naming project-specific identifiers are rejected (Req 8: no
   application-specific trees).
3. **Admission by held-out separation.** Folds are by repository, as in the decision engine. A candidate is
   admitted for a fold only if, on that fold's held-out pairs, adding it to the fact tables:
   - increases pairs where the vulnerable side keeps a path and the fixed side loses it or becomes
     sanitized;
   - and does not remove any held-out vulnerable-side path (no recall loss).
   A candidate proposed by fewer than 2 distinct repositories in the training folds is not tried.
4. **No train-on-test.** Mining and admission never read held-out pairs; the closed-loop leak recorded in
   memory (`closed-loop-train-on-test-leak`) is the failure this rule exists to prevent. Population v3 is
   never read.
5. **Measurement by the trace runner.** Each admission round re-runs the engine on the affected pins only
   (the runner's resume and selection already support this; on k3s the worker Deployment runs them in
   parallel). The outcome is the pair-asymmetry table per family, before and after, on held-out folds.
6. **Gate before production.** An admitted fact enters `src/openultrasast/ruleset/semantic/*.toml` only after
   the detection gates (`gate`, `map_gate`, `pair_gate`) show no regression, and only as a registered
   experiment whose decision rule was fixed before the run.
7. **Coverage second.** After discharge facts, the same loop proposes source and sink additions from pairs
   where neither side has a path (91 of 105 today), admitted under the same held-out rule.

## How it relates to what exists

- `corpus-seeded-mechanisms` already has a closed loop that admits and retracts mechanisms by leave-one-out.
  This plan reuses its lever and store, and points it at discharge facts mined from real fix diffs instead
  of variant search.
- `benchmarks/pairs/mechanisms.toml` (23 mechanisms) labels what kind of bug a pair is. The new candidates
  describe what a fix does. They live in the fact tables, not in the mechanism vocabulary.

## Measures of success

- Pair asymmetry on held-out folds: vulnerable-only paths rise from 2 of 105 toward a substantial share,
  with zero fixed-only paths.
- No held-out recall loss on vulnerable sides.
- Then the decision engine is re-run with the new engine evidence (exp-005 design), and the pooled block gate
  (exp-004 design) is re-measured.

## Cost and time

- Model cost: $0 (mining and admission are deterministic; the classifier re-run afterwards is a separate,
  approved spend).
- Engine time: one pass over affected pins per admission round; about 2 hours per full pass on k3s plus the
  VM, about 6 hours on the VM alone.

## Open questions for the maintainer

1. Should coverage additions (Req 7) be in the same increment or a later one?
2. Minimum proposing repositories: 2 is the proposal. Higher is safer, lower finds more.
3. Admission per family and language, or pooled across languages for the same callee name?
