# Brief: learning-harness

## Problem

The tool is a hand-authored static analyzer with a learning loop bolted on the side, and the loop cannot learn. Three deliberate choices cap it: closed vocabularies (sinks, sources, obligation kinds) that grow only by writing a new spec; a corpus that is the only teacher and a shape that is the only lesson; and a ban on retaining anything the model discovers. Results have ceilings by construction, the loop trains on its own test set, and there is no failure analysis feeding the next round. Detection logic is ~16% of the source and the other 84% cannot say whether the 16% works.

Measured 2026-09-06 on the vibe-py holdout (17 vendored pairs), the existing tool hunter (Sonnet 5 through OpenRouter, 4 steps, tools `read_file`, `grep_repo`, `find_refs`, prompted from file-level hotspots, no learning of any kind) against the overlay:

| scorer | published number | class-aware, identical twins excluded (n = 14) |
|---|---|---|
| tool hunter | 0/17 correct, Youden −0.588 | **12/14 correct, Youden +0.857, 0 leaks** |
| overlay (facts + shapes) | 5/17 correct, Youden +0.294 | 5/14 correct, Youden +0.357 |

The published hunter number is a scoring artifact: the pair scorer counts a hunter finding only when the finding text contains the literal CWE id and the prompt never asks for one, so 24 of 25 vulnerable-side findings that sit inside the labeled function and name the labeled bug (SQL injection in `resolve_pastes`, BOLA in `get_by_title`, SSTI in `read_root`, missing authorization on the profile lookup) were thrown away. The 24 "leaks" split into 3 findings on byte-identical twins (unscorable by construction) and 21 findings outside the labeled function on the trap twin, most of them real defects in a deliberately vulnerable repository. The two remaining misses are `before_request` (`loads(b64decode(cookie))` with no import in the excerpt) and `bad_mvc.do_GET` (labeled CWE-79, the hunter reported the SQL concatenation on the same lines; the label may be wrong).

Three consequences follow.

1. **The model with tools is already the best detector we own, by a wide margin, without any learning.** The roadmap thesis ("recall from the model with tools plus proof; precision and silence from static checks") is confirmed, and the harness has been optimizing the wrong component.
2. **Detection, silence and leak are meaningless without a class.** The same finding is a detection in one class, a leak in another, and noise in a third. Every scorer, lever and gate in the tool currently uses text tokens (CWE strings, sink names) as a proxy for class, and the corpus's own class labels are 32 free-text strings across 7 slices, with 130 of 176 vfc rows labeled `other`.
3. **Improvements without a class dimension oscillate.** A change that helps SQL injection and hurts access control reads as "no change" on an aggregate Youden. The loop then reverts it, or keeps it, for the wrong reason, and the system degrades in ways nobody predicted. This is the maintainer's observation and it is exactly what the corpus-seeded lever does today.

Repairs already measured and required regardless (from the folded `closed-loop-integrity` brief): the mechanism lever seeds candidates from holdout pairs (holdout Youden +0.059 with every pair teaching, −0.059 with the train split only); five vibe-py twins are byte-identical; TypeScript has no grammar; absence excerpts carry no registration context; unit fixtures are easier than the corpus rows they stand in for.

## Desired Outcome

A harness that improves a **set of classified detectors** round by round, where every change is attributed to the class it was meant to move, every unpredicted regression in another class counts against it, and nothing is published without its unscorable denominator.

- **Auto-classifier.** Every unit of work (a labeled pair, a finding, a scan target region) is assigned to a class from a closed, versioned taxonomy by a classifier that is itself measured: agreement with maintainer labels on the reviewed pairs, confusion matrix per round. The classifier is the routing key for everything downstream: which detector runs, which skills load, which holdout the change is validated on, which journal row records it.
- **Per-class detectors.** One hunter configuration per class: system prompt, skills, tool set, step budget, evidence checklist, known counterexamples. A round evolves one class's configuration and is validated on that class's holdout plus a regression sweep over every other class. The static machinery (facts, overlay, obligations, dominance, sandbox) becomes tools the detector calls and verifiers that check its claims; it stops being the detector.
- **Class-aware scorer.** Detection = a finding in the labeled function whose class matches the label. Silence = no finding of the labeled class in the labeled function on the fixed side. Unscorable rows (identical twin, unsupported language, unresolved label) are listed by reason and removed from the denominator, never deleted. The text-token proxy goes away.
- **Learning unit = skill, not regex.** A round's output is a natural-language skill, a tool recipe, a checklist or a counterexample, drafted from a failure analysis, tested on the class's train split, validated on its holdout, journaled with a hypothesis, the predicted affected class, and the measured attribution. HarnessX's `MetaAgent.evolve` with its journal (`hypothesis_id`, `levers`, `predicted_affected`, precision discounted by `regressed_unpredicted`) is the loop primitive; the tool supplies tasks, trajectories, the evaluator and the class routing.
- **Honest fitness.** Split enforced by construction (a candidate touching a holdout pair is refused, not scored); per-class Youden on scorable rows; sandbox proof as the tiebreaker where a class has recipes; the roadmap rewritten from one command with the unscorable denominator next to every number.

Principle for the roadmap: **classify first, then detect, then improve one class at a time under a fitness that punishes what it did not predict.**

## Approach

1. **Class-aware scorer and unscorable rows** (repairs the ruler; smallest change, biggest number). Detection and silence keyed on class and labeled function; identical-twin and unsupported-language rows flagged with a reason and excluded from denominators; the hunter's findings carry a class field the scorer reads. Re-publish every slice number from one command.
2. **Taxonomy and auto-classifier.** A closed, versioned class taxonomy (seeded from the 32 free-text labels, the mechanism vocabulary and the obligation kinds; CWE families as the spine). A classifier with two tiers: a deterministic tier from static signals (rule id, sink family, obligation kind, mechanism) and a model tier for what static signals cannot place, each answer carrying which tier decided. Measured against maintainer labels on the reviewed pairs; disagreements are the review queue. The vfc slice's 130 `other` rows are its first job.
3. **Per-class hunter configurations.** Split the single hunter into one configuration per class: prompt, skills directory, tools, budget, evidence checklist. Start by cloning the current hunter into every class so round zero is a controlled baseline, then let rounds diverge them. The classifier routes a target region to its detector; a region can route to several.
4. **Split enforcement and lever refusal.** The exporter and every future lever take the train split by construction and refuse candidates that touch a holdout pair. Re-measure `corpus-seeded-mechanisms` and rewrite its roadmap row.
5. **Evolve loop on HarnessX.** Tasks = classified pairs (`RLTask.task_type` = class); trajectories = the hunter's journaled runs; evaluator = the class-aware scorer; `MetaAgent.evolve` proposes one configuration change per round for one class with `predicted_affected` set to that class; the round is accepted only if the class's holdout improves and no other class regresses beyond tolerance; the journal's attribution table is the round report. Budget-capped per round.
6. **Corpus repairs that the loop needs.** TypeScript grammar in the semantic extra; absence rows re-harvested with `handler_context`; identical twins marked `known_limit` with reason `identical_twin`; a fixture-difficulty check that fails when a unit fixture is strictly easier than the corpus rows its test claims to cover.
7. **Static machinery as tools and verifiers.** Facts, overlay dispositions, obligations, entry points and the sandbox are exposed to the hunter as tools (`entry_points`, `flows`, `obligations`, `prove`) and to the scorer as verifiers that can raise a hunter suspicion to `static_corroboration` or a proof rung. No detector logic is deleted; it changes role.

## Scope

- **In**: class-aware scorer; taxonomy and classifier with its own measurement; per-class hunter configurations; split enforcement; HarnessX evolve loop wiring with tasks, trajectories, evaluator and journal; the corpus repairs listed in 6; static machinery exposed as hunter tools; roadmap rewrite from one command.
- **Out**: new static shape families; new hand-written facts beyond what a round proposes and validates; changing the evidence ladder or dispositions; any merge gate on non-local slices; vendoring new pairs beyond re-harvesting existing recipes; fine-tuning model weights (skills and configurations only).

## Boundary Candidates

- Taxonomy and classifier (new, owns class assignment) vs pair labels (unchanged, the reference the classifier is measured against)
- Per-class detector configurations (new, evolved) vs static analyzers (unchanged internally, exposed as tools)
- Evolve loop (new, HarnessX) vs existing bounded levers (rules, policy, mechanisms; kept, subordinated to the split and the class attribution)
- Class-aware scorer (replaces the text-token rule) vs catalog schema (one additive `unscorable` reason)

## Out of Boundary

- Taint semantics, walker, dominance internals (`guard-dominance-regime`, `overlay-ir-completeness`)
- Call graph and path records (`reachability-flow-model`), except as a future hunter tool
- Obligation checker internals (`authorization-obligations`); its corpus tasks 4.3 and 6.1 move here, its lever task 5 waits for the split

## Upstream / Downstream

- **Upstream**: `pair-corpus-honesty` (labels, tiers, splits, `known_limit`), `corpus-seeded-mechanisms` (exporter, LOO, lever), `tool_hunter` and `provider/openrouter`, `harness_ext` seam, HarnessX 0.1.0 (`meta_harness`, `rl`, `tracing.journal`), `tree-sitter-overlay-extra`.
- **Downstream**: every roadmap number; `harnessx-self-improving-rulesets` (its evolve step is this spec); `authorization-obligations` 4.3/5/6; scan reports (findings carry a class and the detector that produced them).

## Existing Spec Touchpoints

- **Extends**: `pair-corpus-honesty` Req 1 (scorer rule) and Req 9/10 (row classification); `corpus-seeded-mechanisms` Req 4/5 (split by construction); `three-stage-scan` MAP (per-class hunters as proposers); `harnessx-self-improving-rulesets` (the evolve loop lands here).
- **Folds in**: the `closed-loop-integrity` brief (its five repairs are approach items 1, 4 and 6).
- **Re-homes**: `authorization-obligations` 4.3 and the corpus half of 6.1; holds 5.

## Constraints

Core `dependencies = []`; HarnessX and grammars stay optional extras; every loop step degrades to a recorded reason without them. No row deleted; unscorable rows keep a reason. Labels stay maintainer-owned: the classifier proposes, disagreements queue for review, and a class change on a reviewed pair is a reviewed edit. Model-authored skills are retained only after held-out validation and are journaled with their attribution; nothing a round proposes reaches a scan without passing its class holdout and the cross-class regression sweep. Split enforced by construction, never by convention. Gates (`gate`, `map_gate`, `pair_gate`) stay byte-identical: the local slice is not touched by any of this. Redaction applies to every prompt and every journaled trajectory. Per-round cost cap; a round that exceeds it is recorded and reverted.

## Open Questions for the maintainer

1. Taxonomy spine: CWE families, the mechanism vocabulary, or a new closed list with both as attributes?
2. Round zero: clone the current hunter into every class (controlled baseline) or start each class from a hand-written seed prompt?
3. Cross-class regression tolerance: zero, or a per-class floor proportional to class size?
4. Does `authorization-obligations` task 5 (the lever) stay a spec task or become one class's evolve round?
5. Model for the detectors and for the meta-agent: same model, or a cheaper detector with a stronger meta-agent?

## Evidence

- `benchmarks/measurements/2026-09-06-vibe-py-holdout-hunter-sonnet5.json`: `ousast pairs --slice vibe-py --split holdout --hunter --hunter-model anthropic/claude-sonnet-5 --json` (2026-09-06).
- `benchmarks/measurements/2026-09-06-vibe-py-holdout-hunter-findings.json`: every hunter finding per side for the 17 holdout pairs with `in_labeled_function` and the scorer's verdict; the class-aware re-score uses a keyword classifier written for this measurement only and is the reason approach item 2 exists.
