# Brief: the detector optimizer

## Problem

`learning-harness` built the measurement layer honestly — a closed family taxonomy, a class-aware pair
scorer, per-family detector configurations, a split enforced by construction, verifier-gated reporting,
and a journal with attribution. What it did **not** build is a search. `run_learning_round` is a
hand-rolled hill-climber: one proposal, one minibatch, one holdout check, a threshold rule, accept or
revert. Every defect four review rounds found in it was a defect of that improvised loop rather than of
the measurement underneath it.

The maintainer's judgement, and the reason for this spec: the remaining work is not a sequence of
patches to that loop. It is adopting an interface and an algorithm that already exist, are published,
and are better than what we would arrive at by fixing ours one finding at a time.

## What the current loop gets wrong, measured

Round zero on vibe-py, `deepseek-v4-flash`, K = 5, $0.69, 23/30 pair-correct:

| family | scorable | recall | silence | Youden | noise floor |
|---|---|---|---|---|---|
| injection | 20 | 0.75 | 0.90 | +0.65 | **11** |
| access_control | 3 | 1.00 | 1.00 | +1.00 | 3 |
| config_secrets | 3 | 1.00 | 1.00 | +1.00 | 1 |
| deserialization | 2 | 1.00 | 1.00 | +1.00 | 0 |
| output_encoding | 1 | 1.00 | 1.00 | +1.00 | 1 |
| path | 1 | 1.00 | 1.00 | +1.00 | 1 |

Four defects follow from the loop's shape, not from its bugs:

1. **The acceptance rule cannot discriminate.** `decide` compares raw deltas: any regression on train or
   holdout rejects, a tie rejects. The measured floor says 11 of 20 injection pairs disagree with
   *themselves* across five runs, so a delta over a minibatch of 8 is mostly noise. The spec built
   `sign_test` and `reliable_change` for exactly this and the rule calls neither.
2. **The holdout is an input to the decision.** `decide` reads `holdout_delta`. Req 5.4 keeps the
   *proposer* blind to the holdout, and then the *selector* reads it every round. Repeated rounds
   selecting on holdout performance is search-time overfitting of the test set — the same leak class
   this project has already measured once, one level up.
3. **Noise is fought with repetition instead of diversity.** K = 5 spends five rollouts per pair per
   side estimating variance. The published alternative spends that budget on more candidates and lets a
   frontier keep whatever wins somewhere.
4. **The proposer is told a score, not what went wrong.** `FailureFacts` carries outcomes, run strings
   and counts. The single largest lever in the published work is textual feedback from the *evaluation
   trace* — and our evaluator produces exactly the right material (which finding landed on which line,
   whether it fell inside the labeled span, whether the fixed side leaked, which family was claimed)
   and then throws all of it away.

## What others built

**GEPA — Reflective Prompt Evolution (Agrawal et al., arXiv:2507.19457, ICLR 2026 oral).** Algorithm 1,
read from the paper rather than from a summary:

- Split `D_train` into `D_feedback` and `D_pareto`. Initialise the candidate pool `P = [Φ]` and score
  the seed on every instance of `D_pareto`, giving a score **matrix** `S[candidate][instance]`.
- Each iteration: select a candidate from the Pareto frontier; select a module round-robin; run it on a
  minibatch drawn from `D_feedback`; collect scores, traces and **textual feedback** via a feedback
  function `μ_f`; have a reflection LM rewrite that module's prompt; re-run the mutated system on the
  *same* minibatch.
- **Accept if and only if the minibatch average improved.** Only then is the candidate scored on all of
  `D_pareto` and added to the pool with its parent recorded.
- Return the candidate with the best average on `D_pareto`.

Algorithm 2, the selection: for each instance take the best score any candidate achieved; keep the
candidates that achieve it; drop strictly dominated ones; sample a survivor with probability
proportional to the number of instances it leads on.

Three things about that are directly relevant to us. The acceptance gate is **cheap and noisy on
purpose** — a single minibatch comparison — because the frontier, not the gate, is what protects
against a bad accept: anything that wins on one instance is retained. Selection is **stochastic and
diversity-preserving**, which is what stops the search collapsing onto one lineage. And the expensive
full evaluation is spent only on candidates that already passed the cheap gate.

Reported: 93% on MATH with a DSPy `ChainOfThought` program against 67% unoptimised, +10% over MIPROv2
and +20% over GRPO with **35× fewer rollouts**; on IFBench, optimal prompts after 678 rollouts against
GRPO's 24,000. Sample efficiency is the claim that matters for us, because our rollouts cost money.

**DSPy's optimizer interface.** `MIPROv2` proposes instruction and demonstration candidates and searches
them with Bayesian optimisation (Optuna TPE), scoring on minibatches and running a full validation pass
on the incumbent every `minibatch_full_eval_steps` — an explicit two-fidelity design for a noisy metric.
`dspy.GEPA` takes `metric`, `reflection_lm`, a budget (`auto` / `max_full_evals` / `max_metric_calls`),
`reflection_minibatch_size`, `candidate_selection_strategy` (`pareto` | `current_best`) and
`track_stats`, and its metric returns `Prediction(score, feedback)` rather than a float.

**The standalone `gepa` library** (MIT) exposes `gepa.optimize(seed_candidate, trainset, valset,
task_lm, reflection_lm, max_metric_calls)` over a `GEPAAdapter` protocol of three methods —
`evaluate`, `make_reflective_dataset`, `propose_new_texts` — with a seed candidate that is just a dict
of component name to text. That adapter shape is the interface we want whether or not we take the
dependency: it is the smallest surface that separates *what a detector is* from *how it is searched*.

## What this spec proposes

Restate the detector as an optimisable program and put a published optimiser behind it.

- **A detector is a candidate**: a dict of named text components (`prompt`, `checklist`,
  `hard_negatives`, `counterexamples`) plus its frozen non-text settings (tools, budgets). That is
  already what `FamilyConfig` holds; it becomes the seed candidate.
- **The metric returns a score and a reason.** `score_pair_family` gains a feedback string built from
  what the evaluation already knows. This is the highest-value change in the spec and it is independent
  of which optimiser sits on top.
- **`D_pareto` is carved out of the train split.** The holdout leaves the acceptance rule entirely and
  is scored once, for reporting, when the search is over. This is a requirements change to Req 9.5 and
  the most important honesty consequence of the redesign.
- **An adapter protocol** (`evaluate`, `make_reflective_dataset`, `propose_new_texts`) with two backends:
  our own implementation of Algorithms 1 and 2 by default, so the core install keeps
  `dependencies = []`, and `gepa` behind an optional extra so its improvements arrive for free.
- **The Pareto pool replaces the accept/revert tree.** `Archive` already records per-pair winners; it
  becomes the frontier, and the journal's parent records become the ancestry GEPA needs.

## Scope

In: the search over a family's text components, the feedback function, the candidate pool and its
selection, the budget accounting, and the artifacts that make a run reproducible.

Out, and deliberately: the taxonomy, the classifier, the pair scorer's *outcome* rules, the verifier
boundary, the write roots, redaction, the three gates. Those are the measurement, and a search whose
objective is not trustworthy is worse than no search. Nothing here relaxes them — in particular the
proposer stays blind to the holdout, verifier code and gold labels stay outside every write root, and
no pattern or policy is written by a model.

## Decisions for the maintainer

1. **Reimplement Algorithms 1 and 2, take `gepa` as an extra, or both?** Both is proposed: ours by
   default (zero-dependency, and the security properties are ours to own), `gepa` behind an extra for
   comparison. The cost is one adapter and one conformance test that both backends must pass.
2. **Drop the holdout from the acceptance rule?** Proposed yes, and it amends approved Req 9.5. The
   holdout becomes what its name says.
3. **K = 1 inside the search, K ≥ 3 only for published numbers?** Proposed yes. That is roughly a 5×
   budget reclaim spent on more candidates, which is where the sample efficiency comes from.
4. **Does the reflection model differ from the detector model?** The published work uses a stronger
   reflector than the task model. We have `deepseek-v4-pro` configured as the judge; proposed to reuse it.
5. **Is `access_control` still the family we care most about?** It has one train teacher. Until agent-vfc
   rows are reviewed above tier `title`, the optimiser cannot work on it, whatever its algorithm.

## Open questions

- Does `gepa` run against an OpenAI-shaped base URL that is not OpenAI (our DeepSeek endpoint), and what
  does it pull in? Both must be checked before the extra is offered, under the no-undeclared-dependency rule.
- Our "module" granularity: is a module a family, or a lever within a family? Round-robin over levers is
  the closer analogue, but the levers are not independent — a checklist edit and a prompt edit interact.
- The feedback function's failure mode is a reflection model that writes plausible prose about a trace it
  misread. What check makes a feedback string answerable rather than persuasive?
- GEPA's acceptance is a single noisy comparison. Our floor says a single comparison is close to a coin
  flip on this corpus. Does the frontier really absorb that at n ≈ 20 instances, or is our corpus simply
  too small for the algorithm's assumptions?

Sources: [GEPA (arXiv:2507.19457)](https://arxiv.org/abs/2507.19457) ·
[DSPy GEPA overview](https://dspy.ai/api/optimizers/GEPA/overview/) ·
[DSPy MIPROv2](https://dspy.ai/api/optimizers/MIPROv2/) ·
[gepa-ai/gepa](https://github.com/gepa-ai/gepa)
