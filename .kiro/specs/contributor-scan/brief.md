# Brief: contributor-scan — make the model layer a tool someone runs

**Status:** brief only, unapproved. Successor to `model-grounded-detection`, which is complete (16/16 tasks)
and is not reopened by this.

## The gap this exists to close

`model-grounded-detection` built and measured an arbiter. It works: 41.3% of the corpus reaches
`model_entailed` against the flat IR's 2.2%, and the wired pipeline scores 86.7% pair-correct at 6.7% leak
against the LLM hunter's 76.7% / 12.3%, at a fifth of the model calls and ~100× cheaper.

**And none of it is reachable by a user.** `ousast scan` still runs
`preprocess → map → overlay → obligations → regress → report` and touches the model layer nowhere;
`model/pipeline`, `judge`, `config_value`, `report`, `calibrate` and `execution` have zero production callers
outside `model/`. Every number quoted above came from a measurement harness in a scratch directory.

That is a scope gap in the predecessor spec, not an oversight in its execution: it had no task saying *make
this reachable*, and its Req 11.2 (the gates stay byte-identical) is satisfied precisely **because** nothing
is wired. The spec is complete and the feature is unshipped, both at once.

## What the goal actually is

> "a real world tool that helps developers when they want to contribute"

That reframes the work. A contributor does not have a labelled function and a known weakness class — they
have a repository they are about to touch and a question about what is risky in it. Everything measured so
far is function-level pairs: a labelled function, a declared family, a known target. None of it exercises the
questions a whole repository asks.

## What is missing, in the order it bites

1. **Scan integration.** Wire `model/pipeline` into `ousast scan` so a finding with a rung reaches a report.
   Without this nothing else matters.
2. **Whole-repo scanning.** Region selection from entry points instead of a labelled function; ranking across
   thousands of candidates rather than one; a budget policy (the enumerator caps at 8 candidates per region,
   which is meaningless at repo scale); and the performance envelope — a CPG build on a 100k-line tree, not a
   40-line excerpt. **This has never been run.**
3. **A known-vulnerable repository as the target.** The 176 real-world CVE pairs already in the corpus are
   single-function excerpts and do not exercise any of the above. Running against a real checkout — curl,
   libpng, a WordPress plugin — is the only way to find what breaks at scale.
4. **The memory decision.** 173 of those 176 pairs are `memory` family, routed to a deferred execution tier
   that is a stub. Either adopt Clearwing for them or scope C memory-safety out explicitly. Right now it is
   neither, and a sixth of the corpus sits idle.
5. **Retire `evidence_level`.** It duplicates `rung` in intent; noted as a follow-up in group 3 and never
   tracked.

## Already built and unrecorded

These were delivered during `model-grounded-detection` without being in any spec. They belong here so the
record is not scattered:

- **The pipeline itself** (`model/pipeline.py`) — Req 8 existed, task 3.2 built `judge()`, and nothing ever
  said to connect an enumerator to it. Built, tested, measured, unspecified.
- **Ops** — a single image carrying tool and engine, a compose file with read-only target and tmpfs scratch,
  bash/zsh/PowerShell wrappers that make the container invisible, and a pyinfra deploy for host installs.
  The Docker path is written and syntax-validated but **the image has never been built**.
- **Corpus** — the `owasp` slice (40 validated xss pairs; `output_encoding` went from 1 pair to 41) and
  authored sink/sanitizer facts for Java and JavaScript.

## Known limits to carry forward

- `permissive_values` is a flat literal list with no keyword association, so it holds both `True` and `False`.
  `debug=True` is dangerous where `httponly=True` is safe and the model cannot tell them apart.
- Interprocedural resolution is the most repeated miss cause across every experiment: OWASP's helper classes,
  `angular-http-server`'s `resolveUrl`. Joern supports it; our queries may not be configured for it.
- Five bugs in `model-grounded-detection` shared one shape — a taint-specific assumption applied to every
  family, each found by a measurement rather than a check. Any new family-specific path should be audited for
  siblings before it is measured, not after.
