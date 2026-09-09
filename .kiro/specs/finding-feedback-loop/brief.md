# Brief: finding-feedback-loop — what happens after a finding is judged wrong

**Status:** brief only, unapproved. Successor scope lifted out of `contributor-scan`, which is mid-implementation
and does not cover this.

## Why this is its own spec

Two task groups were drafted into `contributor-scan/tasks.md` on 2026-09-09 without passing through
requirements or design. That was a workflow error: they are not refinements of scan integration, they are a
different feature — a loop that learns from findings a human rejected — and writing them as tasks skipped the
two phases that decide whether the feature is shaped right. They are lifted here to be specified properly.

## The gap this exists to close

Nine engine defects were found in one session against two repositories. **Three of them were the same bug in
three different matchers**: a spec token matched as a substring rather than as a word — `resolve` inside
`resolveUrl` in the sanitizer matcher, `user` inside `users` in the discharger matcher, `gets` inside `fgets`
in the sink matcher. Each was found by a measurement, fixed locally, and left no trace. The third survived
until a 89k-line C library made it visible as 26 identical false positives.

Nothing in the system remembers that a finding was wrong. There is no artifact recording *this site, at this
rung, is not a defect, and here is why*, so the same class recurs and each recurrence costs another
measurement to find.

Two audiences want that artifact for different reasons:

* **A maintainer** wants the propagation automated. Two of the three matcher bugs needed no judgement at all,
  only the fix carried across.
* **A developer** wants to dismiss a finding in their own repository, have it stay dismissed, and have the
  reason reviewable beside the code. Today they have no way to say so, and a tool that cannot be told it is
  wrong is one they stop running.

## What the maintainer asked for

> "is there a way for an evolution (gepa, simba) style prompting with a declarative and persistent approach
> when evaluating findings per target repo? so that devs can commit state and evolve the harness / dismiss
> findings"

And, as the standing test for all of it:

> "it must find the bugs, otherwise it's SAST noise. most devs know codeql / semgrep have dataflow
> capabilities but never use it"

## The boundary that shapes the design

This project has refused LLM-authored patterns and policy from the start, and a closed-loop leak measured on
2026-09-05 is why that is not negotiable: the improve lever admitted candidate shapes because they "recover a
currently missed holdout pair", five of eleven were taught by the holdout pairs they then recovered, and a
holdout Youden of **−0.059 was reported as +0.059**.

So a reflective optimiser has exactly one legitimate target here:

| may be evolved | may not be evolved |
| --- | --- |
| the judge and residual **questions** — how we ask | fact tables, rulesets, the declared policy file — what we claim |

A prompt is how a question is put; a fact table is an assertion about the world. GEPA/SIMBA-style evolution
over `CANDIDATE_QUESTION` and `residual_question`, scored against a repository's own labelled dismissals, is
sound. The same machinery writing sink tables is the thing that produced the leak.

## What the shape looks like

* **Per-repository, declarative, committed by the developer.** A dismissal file in the *target* repository —
  site, rung, reason, author — read by the tool and never written by it, the same rule the declared policy
  file already follows. Reviewed like code, diffable, and a dismissal without a reason is how a suppression
  list becomes a graveyard nobody can audit.
* **Dismissals are labels, not suppressions.** With the known vulnerabilities a `benchmarks/repos/` recipe
  already declares, a dismissal file gives a per-repository evaluation set with *both* classes in it — which
  is what an optimiser needs and what a suppression list normally throws away.
* **A ledger for the maintainer.** Counter-examples grouped by what they share (same token, same matcher
  clause, same witness shape), so a recurring cause is visible as a cause rather than as five separate bugs.
* **Split-respecting adoption.** Train split only, holdout never read, the three gates byte-identical, and
  precision *and* recall reported on both sides — an adoption that quietly trades recall is worse than none.

## The acceptance test for the model's role

Revert the three matcher fixes and run the grouping: does it rediscover the known causes? A model that cannot
recover a cause we already know should not be trusted to propose one we do not.

## Known limits to carry forward

* The pair corpus could not see any of the nine defects; whole-repository measurement is what found them, and
  this loop inherits that. Its evaluation set has to include repositories, not only pairs.
* Only two repositories exist today (one Python, one C), and the C one has never produced a true positive.
  An optimiser tuned on that evidence base would be tuned on very little.
* `contributor-scan` Req 8 already warns about the +16% overfitting gap between the slice a change was
  developed against and one nobody tuned against. Per-repository evolution makes that risk structural rather
  than incidental.
