# Brief: an AI service plane for OpenUltraSAST (Kubernetes-style, at the model level)

Status: brief for maintainer decision (2026-09-29). Not a spec yet; no approvals reset.

## Why now

Two measurements say the current pipeline cannot be developed further at its token cost:

- Development: 90% of the tokens of the last session were tool I/O (inline scripts and their output), because
  every stage lives in ad-hoc scripts run from one long conversation (`dev-tokens-are-tool-io` memory).
- Pipeline: verification costs $0.009-0.022 per candidate for two passes because every hunt re-derives the same
  per-repository facts and every pass re-sends its whole conversation; resume, budgets and pass agreement are
  hand-rolled per script (`results-v2-model-pipeline.json`).

Google's `ax` (open-sourced 2026-09; Apache-2, Go, early) frames agent work as a Kubernetes-style service:
declarative `Task` / `Workspace` / `Model` manifests, a reconciler, sandboxed isolated execution, suspend and
resume, and a runner contract any binary can honour. Its software needs Kubernetes and Agent Substrate, lists
only Google and Anthropic providers, and has no pipelines, artifacts or budgets yet. Its *design* is what we
adopt; its software is a later deployment target.

## The model

| ax primitive | OpenUltraSAST meaning |
|---|---|
| `Workspace` | one pinned checkout: repository, commit, product-file filter; materialised once, bound by many tasks |
| `Model` | provider, model id, credentials, prices, per-task budget (usd, calls); DeepSeek via an adapter |
| `Task` | one concern, isolated: declared inputs (artifacts), declared outputs, resource limits, idempotent per unit, resumable |
| runner contract | our Python entrypoint reads the task and workspace YAML from the environment and writes artifacts |
| reconciler | a local loop over manifests today (one engine container at a time on the 7 GB host); `ax` later, unchanged manifests |

What ax lacks and we add as a thin layer: a `Run` manifest that lists tasks with dependencies (a DAG), artifact
locations, and budgets. This layer is what the reconciler executes; the tasks themselves are ax-shaped.

## The concerns as tasks

1. `classify-sinks` -- workspace -> `candidates.json` (model-read, no tools). Exists: `model_sinks.py`.
2. `triage` -- candidates -> `kept.json` with `data_origin` per function (no tools). Exists inside `verify_batched.py`.
3. `repo-facts` -- workspace -> `facts.json`: per-file callers and entry points, computed once, no model. New;
   this is the memory layer, and it is an artifact, not a cache.
4. `verify` -- kept + facts, `pass=n` -> `verdicts.jsonl`, one hunt per file, budgeted. Exists as a script.
5. `judge` -- verdicts -> `agreed.json`: agreement across passes, then a no-tools judgement over each agreed
   finding's rationale and code. Agreement exists; the judge does not.
6. `recheck-fixed` -- fixed workspace + agreed -> `fixed_alerts.json`. Exists (`--fixed`).
7. `score` -- all of the above + the population record -> `score.json`. Exists (`score_batched.py`).

Each task: one manifest, one entrypoint, one fixture test, one budget. A task that fails leaves no partial
truth: it is unfinished, never "clean" (the 402 lesson).

## What it buys, measured or estimated

- Tokens per task bounded by declared inputs; `repo-facts` replaces the 1-2 tool turns per hunt that today
  re-grep callers (each turn re-sends the whole context); estimated 20-40% per hunt, to be measured on the
  46-candidate validation set.
- Two passes and the judge become tasks with their own budgets instead of loops inside a script.
- Development in small contexts: one task type at a time, against a fixture; the transcript measure is the
  check.
- Portability: the same manifests run on the laptop reconciler now and on `ax` on a cluster later.

## What it does not buy

Recall and precision come from the model and the questions asked, not from orchestration. The open problems
recorded in the strategy review (judge quality, the config-family question, pass stability) remain the
detection work; this design makes them affordable to attack.

## Risks

- `ax` is early ("heavy development", "major breaking changes"); we depend on its shape, not its releases.
- Its provider list excludes DeepSeek; an adapter task image is ours to keep.
- A local reconciler is new code; it must stay thin (manifests, DAG, artifacts, budgets, resume) or it becomes
  the next thing that eats tokens.

## Decisions needed

1. Adopt this as a spec (`/kiro-spec-init` on this brief) and pause further script-level pipeline changes.
2. Manifest format: ax's `ax.io/v1alpha1` kinds verbatim plus our `Run` kind, so the later move is a rename of
   the reconciler, not of the manifests.
3. First increment: `repo-facts` + `verify` as tasks under the local reconciler, measured against the
   46-candidate set for cost and recall before the other concerns move.
