# Brief: closed-loop-integrity

## Problem

The closed loop cannot tell a better detector from a corpus artifact. Measured 2026-09-05 while wiring the obligation checker to the real pair corpus:

- **The lever trains on the test set.** `ousast mechanisms export` seeds candidate shapes from every vendored pair of a slice, and `improve.propose_mechanism_edits` admits a candidate because it recovers a missed holdout pair. A shape taught by a holdout pair can recover itself. On vibe-py (35 vendored, 18 train, 17 holdout) 5 of 11 candidates were taught by a holdout pair; holdout Youden is +0.059 when every pair teaches and **−0.059 when only the train split teaches**. The reported +0.353 holdout gain from `corpus-seeded-mechanisms` is inflated by an unknown amount. `evaluate_loo` is honest; only the lever leaks.
- **Five vibe-py twins are byte-identical** once the provenance header is stripped (`dsvw-dsvw-do-get`, `python-insecure-app-main-try-hack-me`, `pythonssti-main-read-root`, `vampi-books-get-by-title`, `vulnpy-deserialization-do-pickle-load`). No detector can be loud on one side and silent on the other; the slice ceiling is 30/35 and every published vibe-py number carries those five as permanent losses.
- **TypeScript has no grammar.** The semantic extra declares python, javascript, c, cpp and java. Every `.ts`/`.tsx` row parses as `language_unsupported`: 18 agent-vfc rows plus most of the absence rows. The row count is scored as failure, not as unscorable.
- **Excerpts carry no registration context.** Vendored absence excerpts are the handler function alone, so no entry point is named and anything gated on reachability reports nothing. The `handler_context` harvest mode exists (2026-09-05) but no row has been re-harvested with it.
- **Unit fixtures are easier than the corpus.** Fixtures bind identity in one hop; the real vampi fix binds it in two. Green suites therefore do not evidence corpus behaviour, and nothing in CI compares a fixture's difficulty against the rows it stands in for.

The consequence is that three specs (`corpus-seeded-mechanisms`, `authorization-obligations`, and the unwritten `guard-dominance-regime`) each added a detector and a measurement, and none of the measurements is trustworthy. Detection logic is ~16% of the source; the other 84% is harness that currently cannot say whether the 16% works.

## Desired Outcome

One number per slice that a maintainer can believe, before any detector is tuned against it. Concretely: the improve lever never sees a holdout excerpt while it learns; unscorable rows are excluded from the denominator and listed by reason; every language the corpus carries either parses or is counted as unsupported rather than as a miss; every absence excerpt carries the context its label needs; and a fixture-difficulty check fails CI when a unit fixture is strictly easier than the corpus rows its test claims to cover.

Then, and only then, the evolutionary loop (HarnessX `MetaAgent.evolve` or the existing bounded levers) is given more search freedom, because a fitness function that rewards memorizing the holdout will be optimized for exactly that.

Principle for the roadmap: **the ruler is repaired before the thing it measures is tuned; no published number without its unscorable denominator.**

## Approach

1. **Split enforcement.** The exporter takes a split and defaults to `train`; the lever refuses a candidate whose `record.pairs` intersect the holdout set and records the refusal. Re-measure `corpus-seeded-mechanisms` and rewrite its roadmap row with the honest number.
2. **Unscorable rows.** The pair loader flags `identical_twin` (excerpt bodies equal after header strip) and `language_unsupported` rows; scorer and LOO report them under a `unscorable` counter with the reason and drop them from recall, silence and Youden denominators. Nothing is deleted; the catalog row gains a `known_limit` reason instead, which the existing achievable-metric machinery already honors.
3. **TypeScript grammar.** `tree-sitter-typescript` joins the semantic extra; the walker maps `typescript`/`tsx` to it. Existing grammars unchanged.
4. **Context re-harvest.** The absence rows of vibe-py and agent-vfc are re-harvested in `handler_context` mode (maintainer, network, license already on the recipe); pointer rows through the cache. Task 4.3 of `authorization-obligations` moves here.
5. **Fixture-difficulty gate.** A test-only check derives a small difficulty vector from a fixture (bind depth to the identity source, registration present, cross-file registration) and compares it against the corpus rows named in the test's docstring; strictly easier fails.
6. **Evolution under the repaired ruler.** Only after 1–5: expose the HarnessX evolve loop over the existing levers (rules, policy, mechanisms) with the per-profile holdout clause as the fitness function and the split enforced by construction. This step gets its own requirements once 1–5 are measured.

## Scope

- **In**: exporter split filter and lever refusal; unscorable classification in the loader, scorer and LOO; TypeScript grammar in the semantic extra; re-harvest of absence rows; fixture-difficulty check; re-measurement and roadmap rewrite; a closure decision on `authorization-obligations` tasks 4.3, 5 and 6 (they measure against this repaired ruler or not at all).
- **Out**: new detectors; new shape families; changing dispositions or evidence rungs; any merge gate on non-local slices; vendoring new pairs beyond re-harvesting existing recipes.

## Boundary Candidates

- Corpus honesty (loader, scorer, LOO, catalogs) vs detectors (unchanged)
- Lever admission rule (split-aware) vs lever validator and store schema (unchanged)
- Semantic extra dependency set (one grammar added) vs walker semantics (unchanged)

## Out of Boundary

- Taint semantics, facts, dominance (`guard-dominance-regime`)
- Call graph, path records (`reachability-flow-model`)
- Obligation checker internals (`authorization-obligations`), except that its corpus tasks are re-homed here

## Upstream / Downstream

- **Upstream**: `pair-corpus-honesty` (labels, tiers, splits, `known_limit`), `corpus-seeded-mechanisms` (exporter, lever, LOO), `tree-sitter-overlay-extra` (grammar set), `authorization-obligations` (`handler_context`, obligation label).
- **Downstream**: every roadmap number; `harnessx-self-improving-rulesets` (evolve loop gets a trustworthy fitness); `authorization-obligations` 4.3/5/6.

## Existing Spec Touchpoints

- **Extends**: `pair-corpus-honesty` Req 9/10 (one more row classification), `corpus-seeded-mechanisms` Req 4/5 (split-aware seeding and admission), `tree-sitter-overlay-extra` (grammar list).
- **Re-homes**: `authorization-obligations` task 4.3 and the corpus half of 6.1.
- **Blocks**: `harnessx-self-improving-rulesets` evolve step until 1–5 are measured.

## Constraints

Core `dependencies = []`; the grammar lands in the optional extra only. No row is deleted; unscorable rows stay in the catalog with a reason. No LLM-authored labels, shapes or policy. Gates (`gate`, `map_gate`, `pair_gate`) stay byte-identical: the local slice has no identical twins, no TypeScript and no lever. Every re-harvested excerpt is re-redacted and keeps its license line. All numbers in the roadmap are rewritten in one commit with the measurement command that produced them.

## Viability of `authorization-obligations` under this brief

The detector is sound where it can see: with a registration line present it fires on the real vampi vulnerable excerpt and stays silent on a constrained twin. It cannot be evaluated today because its inputs (named entry points, registration context, TypeScript parse) are exactly the defects above. Recommendation: keep tasks 1–3 and 4.1/4.2 (implemented, reviewed, pushed), re-home 4.3 and 6.1's corpus half here, and hold 5 (the lever) until the split is enforced, because a lever admitted under the leaking rule would be admitted for the wrong reason.

## Open Questions for the maintainer

1. Treat the five identical twins as `known_limit` (excluded from achievable, kept for silence) or drop them from the vibe-py catalog?
2. Is `tree-sitter-typescript` acceptable in the semantic extra, or does TypeScript wait for a broader overlay-ir-completeness spec?
3. Should the fixture-difficulty gate be CI-failing from day one or reported first?
4. Does the HarnessX evolve step (approach 6) get its own spec, or stays as the final task group here once 1–5 are measured?
