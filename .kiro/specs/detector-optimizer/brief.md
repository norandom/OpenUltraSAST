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

**SIMBA — Stochastic Introspective Mini-Batch Ascent (`dspy.SIMBA`).** Two of its ideas fit our corpus
better than GEPA's do. It runs `num_candidates` (6 by default) program variants per example, buckets the
trajectories, and ranks examples by **max-to-min score gap** — deliberately spending the budget on the
instances where variants disagree most. On our corpus that is not a nuisance, it is the training signal:
the 11 injection pairs that disagree with themselves are precisely the pairs where a rule change can flip
an outcome, and uniform minibatch sampling would spend most of its budget on the 9 that never move. It
also alternates two strategies rather than round-robining blindly — `append_a_demo` (a successful
trajectory becomes a demonstration) and `append_a_rule` (the model introspects on the bucket and writes a
rule) — which is exactly the split our levers already have between `counterexamples`/`hard_negatives` and
`checklist`/`prompt`. Candidates are sampled by softmax over historical scores at temperature 0.2, a
cheaper third option beside GEPA's `pareto` and `current_best`.

**The reflection meta-prompt** (GEPA Appendix C) is short and tells us what the feedback function must
produce. It shows the reflector the current instruction, then "inputs, outputs and feedback" for the
minibatch, and asks it to infer the task, extract "all niche and domain specific factual information ...
as a lot of it may not be available to the assistant in the future", and name any generalizable strategy.
That is a specification for `μ_f`, not just a prompt: feedback has to carry the domain facts a detector
cannot re-derive — which sink, which span, which side leaked — rather than a verdict.

**GEPA's merge** is gated strictly: two candidates are crossed only when they share a common ancestor,
optimised *disjoint* sets of prompts, are both Pareto-optimal, and both beat the ancestor's aggregate.
Worth having once we have per-lever candidates, and worth not having before then.

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

## Where the noise actually is, and why the architecture may be wrong

The maintainer's objection, and I think it is correct: the harness treats the detector as a black box
emitting a noisy scalar, and everything follows from that — K runs, majority vote, a measured floor, a
regression budget, a sign test. That is the stance you take when you cannot see inside the thing you are
measuring. We can see inside it.

The variance is not in the judgement. `temperature: 0` is sent and thinking is disabled, and 11 of 20
injection pairs still disagree with themselves. A traced run shows why: over four steps the model chose
different files to read and different grep patterns, and reached its conclusion from different context
each time. The freedom is in the **trajectory**, and we built statistics to average over it instead of
removing it.

This is exactly what DSPy exists to argue about, and three of its constructs attack the source rather
than the symptom.

**Constraints as predicates, enforced at generation time** (`dspy.Assert`/`Suggest`, arXiv:2312.13382).
A constraint is a boolean function of the output; on failure the past output *and the error* are injected
into a retry. We already have the predicates — is the reported line inside a parsed function, does the
named sink occur at that line, is the claimed family in the taxonomy, did the run cite a tool result —
and we apply every one of them **after the fact, at scoring time, to decide whether to count a finding**.
Applying them at generation time to decide whether to *accept* one is free, needs no dependency, and is
the single highest-value change available. The paper reports near-total intrinsic constraint satisfaction
and 5–15% downstream gains.

**Typed decomposition instead of one free-running loop.** Our detector is a single ReAct loop that decides
which files to read, what to grep, when to stop and what to report; every one of those is a variance
source. DSPy's thesis is that each step gets a signature — a typed input/output contract — and a little
control flow composes them. Ours would be roughly: locate candidate sink sites; trace whether an untrusted
value reaches each; check for a guard between source and sink; judge. **Several of those steps need no
model at all** — the CST, the entry-point mapper, `flows` and `obligations` already answer them
deterministically, and we are currently paying a model to re-derive facts we hold.

**Best-of-N against a checkable reward, instead of a majority vote** (`dspy.Refine`, `BestOfN`). Both
spend K samples. A majority vote assumes the modal answer is right and discards the disagreement; Refine
ranks the N attempts by an explicit reward and feeds a hint from the failures into the next attempt. We
have checkable rewards for free. The same budget, used as evidence rather than as averaging.

**Why this matters more for our models, not less.** GEPA and SIMBA are demonstrated with a strong
reflection model over a weaker task model, and their gains come from evolving instructions. A cheap model
fails on an under-specified task and does well on a narrow typed one. So the cheaper the detector model,
the more of the return sits in decomposition and constraints and the less in prompt evolution — which is
the opposite of the order this spec originally proposed.

**The experiment that settles it, before any of this is built.** We already run K = 5. Record the tool-call
sequence for every run, and measure how often a pair's runs took different trajectories, and whether
outcome flips coincide with trajectory divergence. If they do, the noise architecture is treating a
structural problem as a statistical one and most of it can be deleted rather than repaired. Cost: nothing
beyond logging what we already generate.

## The constraint that outranks the algorithm

Both algorithms assume a dataset. GEPA splits `D_train` into `D_feedback` and `D_pareto`; SIMBA's default
batch size is 32. **Our injection family has 12 train teachers** — fewer than one SIMBA batch, and after a
GEPA split roughly six instances on each side. Every other family has one to three.

So the honest statement of what this spec can and cannot buy: GEPA and SIMBA are sample-efficient in
*rollouts*, not in *instances*. They will not shortcut a corpus of twelve. The optimiser is worth building
because the current loop is the wrong shape and will stay wrong at any corpus size, but the binding
constraint on results is the train split, and it will remain so after this spec ships. Two things move it,
neither of which is an algorithm: reviewing agent-vfc rows above tier `title` (29 rows, currently unable to
teach anything), and harvesting more pairs per family.

## Scope

In: the search over a family's text components, the feedback function, the candidate pool and its
selection, the budget accounting, and the artifacts that make a run reproducible.

Out, and deliberately: the taxonomy, the classifier, the pair scorer's *outcome* rules, the verifier
boundary, the write roots, redaction, the three gates. Those are the measurement, and a search whose
objective is not trustworthy is worse than no search. Nothing here relaxes them — in particular the
proposer stays blind to the holdout, verifier code and gold labels stay outside every write root, and
no pattern or policy is written by a model.

## Decisions for the maintainer

0. **Is the optimiser even the next thing to build?** Proposed no, and this reverses the order above.
   Constraints at generation time, typed decomposition and best-of-N attack the variance at its source; an
   optimiser only tunes text around a program whose freedom is the problem. Proposed sequence: measure where
   the variance is, constrain generation, decompose the loop, then optimise — and at a trainset of twelve the
   optimiser that fits is `BootstrapFewShot` (collect traces that scored well, install them as demonstrations
   in a lever we already have) rather than an evolutionary search with nothing to search over.

0b. **Adopt DSPy itself?** Proposed no. Our detector is not a DSPy program — it is an agentic tool loop over
   a repository with curated tools, redaction on every prompt, path clamping, a "no findings unless a tool
   was called" rule and a final-answer turn, several of which are security properties rather than
   conveniences. Handing that loop to `dspy.ReAct` and the calls to litellm would put them behind someone
   else's abstraction, and DSPy could only ever be an optional extra under `dependencies = []`, which means
   two code paths for the thing that *is* the product. What DSPy would genuinely buy — signatures, adapters,
   multi-module composition — we barely need at one module per family. The optimisers are available without
   the framework: `gepa` ships standalone under MIT, and SIMBA's two ideas are a hundred lines of logic.
   Proposed instead: take the interface shape and the algorithms, not the framework.

1. **Reimplement Algorithms 1 and 2, take `gepa` as an extra, or both?** Both is proposed: ours by
   default (zero-dependency, and the security properties are ours to own), `gepa` behind an extra for
   comparison. The cost is one adapter and one conformance test that both backends must pass.
2. **Drop the holdout from the acceptance rule?** Proposed yes, and it amends approved Req 9.5. The
   holdout becomes what its name says.
3. **Sample instances by disagreement (SIMBA) or uniformly (GEPA)?** Proposed SIMBA's ranking. Our measured
   floor makes it the better fit, and it turns the noise floor from an obstacle into an instance sampler.

4. **K = 1 inside the search, K ≥ 3 only for published numbers?** Proposed yes. That is roughly a 5×
   budget reclaim spent on more candidates, which is where the sample efficiency comes from.
5. **Does the reflection model differ from the detector model?** The published work uses a stronger
   reflector than the task model. We have `deepseek-v4-pro` configured as the judge; proposed to reuse it.
6. **Is `access_control` still the family we care most about?** It has one train teacher. Until agent-vfc
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
[gepa-ai/gepa](https://github.com/gepa-ai/gepa) ·
[DSPy SIMBA](https://dspy.ai/api/optimizers/SIMBA/) ·
[dspy/teleprompt/simba.py](https://github.com/stanfordnlp/dspy/blob/main/dspy/teleprompt/simba.py) ·
[DSPy Assertions (arXiv:2312.13382)](https://arxiv.org/pdf/2312.13382) ·
[dspy.Refine](https://dspy.ai/api/modules/Refine/) ·
[DSPy (arXiv:2310.03714)](https://arxiv.org/pdf/2310.03714)
