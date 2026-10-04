# Brief: does the safety net work on repositories it has never seen?

Maintainer, 2026-10-04: "we want to spread the safety net across repos in general, unseen code. that was the purpose
of the AB tests to see if our approach is generalizeable." And: "we should run our tests / runs in kube. now we can
speed it up and design the workloads for ax directly. kind is only a fallback."

## Why this spec exists

The A/B experiments so far (exp-003, exp-004, exp-005) score the decision engine on repository-held-out folds of known
fix pairs. That measures whether the vulnerable side of a pair scores above its fixed side. It does not measure what a
safety net on an arbitrary repository lives on:

- on an ordinary push, does it stay quiet? (false-alarm rate)
- on a push that introduces a real vulnerability, does it say so? (catch rate)

Populations v1 and v2 measured the engine scan on fresh cases once (1 of 11, 0 of 17) and are spent. Nothing since has
measured push-level behaviour on unseen repositories.

## What this spec delivers

1. A frozen pool of repositories never used anywhere in development, with two kinds of change each: real
   vulnerability-introducing commits and ordinary commits.
2. A push-level metric: each change replayed through the hook exactly as a user would run it, and through other
   arms (decision engine, engine evidence) where an experiment asks.
3. Execution designed for the kube-ax cluster from the start: one push replay is one AX Task; kind and the VM are
   fallbacks.
4. A baseline for today's hook, then a table of arms scored on the same pool.

## Not in scope

Changing detection. This spec only builds the measurement. Improvements are separate, registered experiments judged
by it.
