# Brief: learning-harness

## Problem

The tool is a hand-authored static analyzer with a learning loop bolted on the side, and the loop cannot learn. Three deliberate choices cap it: closed vocabularies (sinks, sources, obligation kinds) that grow only by writing a new spec; a corpus that is the only teacher and a shape that is the only lesson; and a ban on retaining anything the model discovers. Results have ceilings by construction, the loop trains on its own test set, and there is no failure analysis feeding the next round. Detection logic is ~16% of the source and the other 84% cannot say whether the 16% works.

Measured 2026-09-06 on the vibe-py holdout (17 vendored pairs), the existing tool hunter (Sonnet 5 through OpenRouter, 4 steps, tools `read_file`, `grep_repo`, `find_refs`, prompted from file-level hotspots, no learning of any kind) against the overlay:

| scorer | published number | class-aware, identical twins excluded (n = 14) |
|---|---|---|
| tool hunter | 0/17 correct, Youden −0.588 | **12/14 correct, Youden +0.857, 0 leaks** |
| overlay (facts + shapes) | 5/17 correct, Youden +0.294 | 5/14 correct, Youden +0.357 |

The published hunter number is a scoring artifact: the pair scorer counts a hunter finding only when the finding text contains the literal CWE id and the prompt never asks for one, so 24 of 25 vulnerable-side findings that sit inside the labeled function and name the labeled bug were thrown away. The 24 "leaks" split into 3 findings on byte-identical twins and 21 findings outside the labeled function on the trap twin, most of them real defects in a deliberately vulnerable repository. Raw runs: `benchmarks/measurements/2026-09-06-vibe-py-holdout-hunter-*.json`.

Three consequences follow.

1. **The model with tools is already the best detector we own, without any learning.** The roadmap thesis ("recall from the model with tools plus proof; precision and silence from static checks") is confirmed, and the harness has been optimizing the wrong component.
2. **Detection, silence and leak are meaningless without a class.** Every scorer, lever and gate uses text tokens (CWE strings, sink names) as a proxy for class; the corpus's own labels are 32 free-text strings across 7 slices, and 130 of 176 vfc rows say `other`.
3. **Improvements without a class dimension oscillate.** A change that helps one class and hurts another reads as no change on an aggregate Youden; the loop keeps or reverts it for the wrong reason and the system degrades in ways nobody predicted. This is the maintainer's observation and it is what the corpus-seeded lever does today.

Repairs already measured and required regardless: the mechanism lever seeds candidates from holdout pairs (holdout Youden +0.059 with every pair teaching, −0.059 with the train split only); five vibe-py twins are byte-identical; TypeScript has no grammar; absence excerpts carry no registration context; unit fixtures are easier than the corpus rows they stand in for.

## What others learned

Full sourced notes in `research.md` (four threads, 2026-09-06). The findings that change this design:

**Cyber reasoning systems (AIxCC finals, Big Sleep, XBOW, Glasswing).** The routing key that worked in every finalist was mode × language × sanitizer or CWE family, aligned to what the oracle can confirm; nobody routed on fine CWE. Only proof survives: every top system gates a report on an executed oracle, the accuracy multiplier decided the ranking (Atlantis 0.9999 versus 0.9044), and XBOW keys a non-AI validator per vulnerability class that alone decides success. RoboDuck's cheap logprob classifier (~$0.001) sending the top 20% to a $0.50 agent is the closest public analogue of an auto-classifier front end. Ensembles beat selection when the winner is unpredictable, with attribution done per agent after the fact. Validated is not correct: 38–46% of automatically accepted patches were semantically wrong. Hallucination controls are structural (forced tool calls, curated tools instead of bash, symbol resolution). Cross-run learning is nearly absent in the field, and the one trained component reported catastrophic forgetting across projects. Stability and cost decided more than cleverness.

**Self-improving harnesses (GEPA, DSPy, AlphaEvolve, DGM, Self-Harness, SkillOpt, AHE, Meta-Harness).** Track wins per instance or class, never the aggregate: GEPA's per-instance Pareto archive doubled the gain of greedy selection. Accept a change only when train and holdout are both non-negative and one is strictly positive; reject ties. Meta-agents predict the class they help at 33.7% precision and the class they hurt at 11.8% ("regression blindness"), so a cross-class sweep cannot be optional. Two-stage evaluation is where sample efficiency comes from. Prompt bloat is the overfit signature; cap length. Structural edits (tools, checklists, memory) transfer across model families, prose edits regress. Self-diagnosis confabulates (0 of 121 reflections named the real cause; structured trajectory facts reached 86%). Hide the checker and the gold labels from the editable surface. One change, one class per round. Harness-edit quality is flat across model tiers while detector quality is not: a cheap meta-agent, spend on the detector.

**Datasets and taxonomies.** Deduplicate by normalized hash before splitting and split by repository, chronologically. Report pair-wise outcomes (pair-correct, both-vulnerable, both-benign, reversed) and a directional-bias index, not F1; models that flag both sides win F1 while losing pair accuracy. Match on location and class with hierarchical partial credit and the maximum penalty for a hallucinated class. Fine CWE classification from code is unsolved (top-1 ≤ 14.7%, most errors lateral siblings); coarse families are workable (88 CWEs collapsed to 12 gave per-class experts +12.8% F1, with a router right 63.8% of the time and F1 0.18 when wrong). Specialists collapse without hard negatives. Verdicts flip on renames and whitespace; single-shot evaluation missed 42% of real changes, so evaluate with K ≥ 3 runs and a reliable-change test. Function-level pairs lose context, the same defect as our context-free absence excerpts.

**Routing and regression control.** Learned routers plateau 10–20 points below an oracle and can lose to random; measure router accuracy on its own against random and oracle. Route to several experts with an explicit `unknown`, never argmax. Slice everything; aggregate gains of +2 points have masked 28–39% of items getting worse. Freeze per-class configurations to prevent interference; skill loops driven by self-feedback alone drift, external feedback does not. Production gates are conjunctive per slice with relative thresholds against the last blessed baseline; no public numeric negative-flip budget exists, so the defensible budget is the measured seed-noise floor per class.

## Desired Outcome

A harness that improves a **set of classified detectors** round by round, where every change is attributed to the class it was meant to move, every unpredicted regression in another class counts against it, only what a verifier can confirm is reported above suspicion, and nothing is published without its unscorable denominator and its noise floor.

- **Auto-classifier as routing key.** A closed, versioned taxonomy of roughly 8–12 families derived from the CWE hierarchy and aligned to what our verifiers can confirm (sandbox recipe, static corroboration, entry-point and flow tools). Multi-label with an explicit `unknown`. Three tiers: deterministic static signals first, a cheap model second with logprob averaging, `unknown` third, each answer recording its tier. Measured on its own: agreement with maintainer labels on reviewed pairs with hierarchical partial credit, accuracy against a random router and an oracle, confusion matrix per round. Disagreements are the review queue.
- **Per-class detectors, frozen between rounds.** One hunter configuration per family: length-capped prompt, skills, curated tools with symbol resolution (never bash), step and cost budget, evidence checklist, hard negatives, known counterexamples. A region routes to every family the classifier admits plus a generalist. Round zero clones the current hunter into every family so the baseline is controlled; K ≥ 3 runs per class establish the seed-noise floor that becomes that class's regression budget.
- **Class-aware, pair-wise scorer.** Detection = a finding in the labeled function whose class matches the label, with hierarchical credit and the maximum penalty for a hallucinated class. Silence = no finding of the labeled class in the labeled function on the fixed side. Outcomes as pair-correct, both-vulnerable, both-benign, reversed, plus a directional-bias index, negative flips per item against the last blessed round, and a fixed-FPR view. Unscorable rows (identical twin, unsupported language, unresolved label, missing context) listed by reason and removed from the denominator, never deleted. Dedup by normalized hash before splitting; split by repository, chronologically.
- **Only proof is reported above suspicion.** Class-keyed verifiers decide: sandbox recipes, static corroboration, entry-point, flow and obligation tools. A hunter claim without a verifier stays `suspicion` and is scored as such. Verifier code and gold labels sit outside every editable surface, and anything reported as proven gets a second independent judge.
- **Learning unit = structural change, journaled.** A round's output is a tool, a checklist, a counterexample, a memory entry or a bounded prompt edit for one class, drafted from structured failure facts (which sink, which line, which check fired), never from free-form self-critique. Accepted only when train and holdout are both non-negative with one strictly positive and no other class falls below its budget; ties rejected; rejected edits kept in a buffer the proposer sees; the proposer never sees the holdout. HarnessX's `MetaAgent.evolve` and journal (`hypothesis_id`, `levers`, `predicted_affected`, precision discounted by `regressed_unpredicted`) is the round primitive; the tool supplies tasks keyed by class, trajectories, the evaluator and the routing.
- **Honest fitness.** Split enforced by construction; two-stage evaluation (minibatch gate, the class's full holdout, the cross-class sweep); a per-class archive of which candidate wins which instance rather than one champion; the roadmap rewritten from one command with the unscorable denominator and the noise floor beside every number; a per-round cost cap where an over-budget round is reverted and recorded.

Principle for the roadmap: **classify first, verify before reporting, improve one class at a time under a fitness that punishes what it did not predict.**

## Approach

1. **Class-aware pair scorer and unscorable rows.** Pair-wise outcome vocabulary, location-and-class matching with hierarchical credit, directional-bias index, per-item negative flips, K-run reliable-change test, unscorable reasons out of the denominator, normalized-hash dedup, repository-level split. Re-publish every slice from one command. Smallest change, biggest number.
2. **Taxonomy and auto-classifier.** Family taxonomy versioned in one file with its CWE mapping and its verifier per family; three-tier classifier; its own measurement report; the vfc slice's 130 `other` rows and the 32 free-text classes are its first job, disagreements queued for review.
3. **Per-class hunter configurations.** Clone the current hunter into every family; curated tools with symbol resolution; length-capped prompts; per-family evidence checklist and hard negatives; the classifier routes a region to every admitted family plus the generalist; findings carry their class, detector and verifier.
4. **Verifiers keyed by class.** Sandbox recipes, static corroboration, entry-point, flow and obligation tools exposed to the hunter and to the scorer; a claim rises above `suspicion` only through a verifier; a second independent judge for anything proven.
5. **Split enforcement and lever refusal.** Every exporter and lever takes the train split by construction and refuses candidates touching a holdout pair; re-measure `corpus-seeded-mechanisms` and rewrite its roadmap row.
6. **Evolve loop on HarnessX.** Tasks = classified pairs (`RLTask.task_type` = family); trajectories from journaled hunter runs; evaluator = the class-aware scorer; one structural change for one class per round with `predicted_affected` set; the acceptance rule and cross-class sweep above; per-class Pareto archive; rejected-edit buffer; reflector blind to the holdout; per-round cost cap; the journal's attribution table is the round report and the daily benchmark.
7. **Corpus repairs the loop needs.** TypeScript grammar in the semantic extra; absence rows re-harvested with `handler_context`; identical twins marked `known_limit:identical_twin`; a fixture-difficulty check that fails when a unit fixture is strictly easier than the corpus rows its test claims to cover; a post-cutoff slice for contamination.
8. **Operational floor.** Persisted logs and trajectories, budget caps tested on the failure path, redaction on every prompt and journaled trajectory, cost per point published per round.

## Scope

- **In**: items 1–8; roadmap rewrite from one command; a closure decision on `authorization-obligations` 4.3, 5 and 6.
- **Out**: new static shape families; hand-written facts beyond what a round proposes and validates; changing the evidence ladder or dispositions; any merge gate on non-local slices; vendoring new pairs beyond re-harvesting existing recipes; fine-tuning model weights.

## Boundary Candidates

- Taxonomy and classifier (new, owns class assignment and its measurement) vs pair labels (maintainer-owned reference)
- Per-class detector configurations (new, evolved, frozen between rounds) vs static analyzers (unchanged internally, exposed as tools and verifiers)
- Class-aware scorer (replaces the text-token rule) vs catalog schema (one additive `unscorable` reason, one `class` field)
- Evolve loop (new, HarnessX) vs existing bounded levers (rules, policy, mechanisms; kept, subordinated to split, class and budget)

## Out of Boundary

- Taint semantics, walker, dominance internals (`guard-dominance-regime`, `overlay-ir-completeness`)
- Call graph and path records (`reachability-flow-model`), except as a future hunter tool
- Obligation checker internals (`authorization-obligations`); its corpus tasks move here, its lever waits for the split

## Upstream / Downstream

- **Upstream**: `pair-corpus-honesty` (labels, tiers, splits, `known_limit`), `corpus-seeded-mechanisms` (exporter, LOO, lever), `tool_hunter` and `provider/openrouter`, `harness_ext`, HarnessX 0.1.0 (`meta_harness`, `rl`, `tracing.journal`), `tree-sitter-overlay-extra`, the sandbox and regress recipes.
- **Downstream**: every roadmap number; `harnessx-self-improving-rulesets` (its evolve step is this spec); `authorization-obligations` 4.3/5/6; scan reports (findings carry class, detector and verifier).

## Existing Spec Touchpoints

- **Extends**: `pair-corpus-honesty` Req 1 (scorer) and Req 9/10 (row classification); `corpus-seeded-mechanisms` Req 4/5 (split by construction); `three-stage-scan` MAP (per-class hunters as proposers); `propose-adjudicate-prove` (verifiers keyed by class); `harnessx-self-improving-rulesets` (the evolve loop lands here).
- **Folds in**: the retired `closed-loop-integrity` brief.
- **Re-homes**: `authorization-obligations` 4.3 and the corpus half of 6.1; holds 5.

## Constraints

Core `dependencies = []`; HarnessX and grammars stay optional extras; every loop step degrades to a recorded reason without them. No row deleted; unscorable rows keep a reason. Labels stay maintainer-owned: the classifier proposes, disagreements queue for review, and a class change on a reviewed pair is a reviewed edit. Model-authored skills, tools and prompt edits are retained only after held-out validation under the acceptance rule and are journaled with attribution; nothing a round proposes reaches a scan without its class holdout and the cross-class sweep. Split enforced by construction. Verifier code and gold labels outside every editable surface. Prompt length capped per class. Gates (`gate`, `map_gate`, `pair_gate`) stay byte-identical. Redaction on every prompt and trajectory. Per-round cost cap with revert.

## What this project is for (maintainer, 2026-09-06)

The target is to catch the taxonomy families below **reliably** on real-world application code, including absence bugs in vibe-coded services (an authorization check that was never written), with an emphasis on dangerous, low-hanging fruit. It is not a bug-finder for JavaScript interpreters, WebGL renderers or browser engines, and it is not a memory-safety fuzzer: memory bugs in C and C++ are a different game played by specialized systems (AIxCC-class CRSs, Big Sleep) that this project learns from and does not replicate or compete with. The balance to hold is between two failure modes, being useless on actual code and being blind to forgotten checks in generated code; both are in scope, engine and renderer bugs are not. The vfc C slice therefore stays a measured, non-gating slice with one coarse memory-safety family and no crash oracle of our own.

## Decisions (maintainer, 2026-09-06)

1. **Taxonomy spine.** Ten families keyed to danger and to a verifier we can run, with CWE and the mechanism vocabulary as attributes, never the routing key: injection into a query or command (SQL, command, code, template); file path from user input; deserialization of untrusted data; access control (IDOR, missing guard, identity from request body; the obligations checker is its verifier); output encoding (XSS, template to HTML); untrusted destination (server-side request forgery and open redirect, which share the shape of untrusted input choosing where a request goes and account for 34 corpus rows); prototype pollution and unsafe object merge; permissive configuration and secrets (CORS, debug, cookie flags, weak crypto, hardcoded credentials); memory safety as one coarse family for the vfc slice only; unknown. Multi-label routing.
2. **Regression budget.** Measured, not chosen: round zero runs the cloned hunter K = 5 times per family at temperature 0 over the vendored corpus; the per-family negative-flip rate between seeds is the budget. A round that exceeds it in any family is rejected regardless of its target gain.
3. **Models.** Detectors and meta-agent on `deepseek-v4-flash` through DeepSeek's own OpenAI-compatible endpoint (`https://api.deepseek.com`); `deepseek-v4-pro` only as the second independent judge above suspicion and for classifier disagreements queued for review; embeddings stay on OpenRouter. The chat endpoint and the embedding endpoint are configured separately (today one base-URL variable serves both). The 1M context lets the detector read whole files instead of hotspot excerpts.
4. **Round-zero verifiers.** Snippet templates with an oracle per family, on the existing per-language sandbox recipes: canary row in an in-memory database for injection, canary file for command execution and traversal, canary object for deserialization. Access control gets the obligations checker as static corroboration. Output encoding, SSRF, prototype pollution and configuration report at `suspicion` only until they have an oracle. A family without a verifier never reports above suspicion in a scan but is still scored class-aware on the corpus: the corpus is the verifier for learning, the sandbox is the verifier for reporting.
5. **Obligations lever.** `authorization-obligations` task 5 is retired as a spec task and becomes the access-control family's first evolve round; obligation shapes are that family's memory entries under the split rule.
6. **Order.** Round zero on the web families over vibe-py and agent-vfc, where real-world code, dangerous fruit and a working hunter coincide; the vfc C slice later, as a measured slice only.

## Evidence

- `benchmarks/measurements/2026-09-06-vibe-py-holdout-hunter-sonnet5.json`: `ousast pairs --slice vibe-py --split holdout --hunter --hunter-model anthropic/claude-sonnet-5 --json`.
- `benchmarks/measurements/2026-09-06-vibe-py-holdout-hunter-findings.json`: every hunter finding per side with `in_labeled_function` and the scorer's verdict; the class-aware re-score used a keyword classifier written for the measurement only, which is why approach item 2 exists.
- `research.md`: the four research threads with sources.
