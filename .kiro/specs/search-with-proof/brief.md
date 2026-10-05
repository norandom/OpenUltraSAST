# Brief: search with proof

Maintainer, 2026-10-05, after reviewing Cairn (github.com/oritera/Cairn): "we are still not progressing through the
state space search / not finding what we need and the progress is sort of slow ... i think something is missing."
And: "I'd move to primarily executing in the cluster."

## What was missing

Every detection step so far classifies: it scores one function excerpt and then tries to make the score precise
enough to block. Calibration, Wilson bounds, pooled block gates, prompt variants and trained models all hit the same
wall: ranking is decent (within-pair AUC about 0.76), but precision at the top cannot be proven to 95% on our data.

Cairn treats a security problem as a directed search with an objectively checkable goal. A shared board holds
confirmed facts, open intents and human hints. A reasoner proposes independent intents; explorers with real tools
each confirm one fact; the loop ends when the goal is demonstrably met.

Three things follow for OpenUltraSAST:

1. **An objective success condition.** A finding is demonstrated when a test or proof of concept fails on the
   vulnerable code and passes on the fixed code (or, for a push, fails on head and passes on base where applicable).
   A demonstrated finding is right by construction; it needs no calibration and no training data, so it generalises
   to unseen repositories by construction.
2. **Exploration with tools.** Agents that read other files, follow callers, build and run the code, instead of a
   single-shot judgement of one excerpt.
3. **Search state per repository and push.** Facts and intents accumulate on a board instead of every question
   starting from zero.

## Shape

- The cheap layers (quick rules, engine, classifier) become triage: they rank candidates.
- Agentic search runs only on the top-ranked candidates of a push, under a per-push budget.
- BLOCK only on a demonstrated finding. Advisory for plausible, unproven ones. "Could not demonstrate" is recorded as
  such, never as "not vulnerable".
- Execution is primarily in the kube-ax cluster: reason and explore steps are AX Tasks; the VM coordinates.
- Model access: a scoped, budget-limited key in the cluster, managed by the operator.

## Not in scope

Copying Cairn code (AGPL-3.0; this repository is Apache-2.0). Offensive use against systems we do not own: all
execution is against code under analysis, inside gVisor sandboxes.
