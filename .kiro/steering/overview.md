# Overview — what this is, and what is actually true of it

**Written 2026-09-09.** Fourteen specs have accumulated and the roadmap still described a pre-Joern world, so
this is the synthesis above them: what the system does, what has been measured, and what is not true yet.
Every number here comes from a committed artifact in `benchmarks/measurements/`.

## What the tool is

A static analyser that separates **what it can prove from what it merely suspects**, and says which is which.

The thesis is not the dataflow engine — CodeQL and Semgrep have one and developers do not turn it on. It is
the **rung**: a claim you can act on without writing a query, and an explicit admission when the engine could
not decide.

```
execution_confirmed   a test or sandbox reproduced it                (built, no production caller)
model_entailed        the graph decided: a flow with no discharge,
                      an obligation with no guard, a permissive value  ← the product
model_corroborated    the graph found the shape; a judge with
                      coverage agreed on the residual question
suspicion             an enumerator or a pattern proposed it and
                      nothing corroborated it                          ← everything below the line is noise
                                                                          until proven otherwise
```

Silence is not a clean bill of health. If no fact table covers a site, the model is **silent, not negative** —
23 of the 39 misses in the original entailment ceiling were sinks simply absent from the tables.

## How it works, in one pass

```
preprocess ─▶ entry-point map ─▶ MAP stage ─┬─ static patterns
                                            ├─ semantic overlay
                                            ├─ obligations (absence bugs)
                                            ├─ tool hunter (LLM)
                                            └─ MODEL LAYER ──▶ one CPG per repository (Joern, subprocess)
                                                               ├─ taint      reachability + sanitizer lattice
                                                               ├─ dominance  guard governs obligated operation
                                                               └─ config     constant abstraction over a value
```

Three abstractions, one arbiter each, dispatched on spec type so a family without an arbiter cannot be
silently routed to the wrong one. The CPG is built **once per scan** and every question is batched into one
invocation per query kind.

## What has been measured

| | measured | source |
|---|---|---|
| entailment, flat IR → CPG | 2.2% → **41.3%** of the corpus | `2026-09-08-model-entailment-ceiling*.json` |
| vibe-py pairs (30) | **90.0% pair-correct**, 6.7% leak, $0.0068 | `2026-09-08-pipeline-vibe-py.json` |
| — against the LLM hunter | 76.7% / 12.3% at 5× the calls, ~100× the cost | same |
| vampi (python, 520 lines) | **3 of 3** known vulnerabilities at `model_entailed` | `2026-09-09-repo-vampi-authz-precision.json` |
| vampi access-control precision | 28.6% → **50.0%** | same |
| access-control leak, pairs nobody tuned against | 42.9% → **0.0%**, pair-correct unchanged | same |
| libpng envelope (89k lines of C) | build 16s, query 250s, scan 446s, **911 MB** | `2026-09-09-repo-libpng-envelope.json` |
| libpng valid findings | **zero** | same |
| report proportionality | libpng 198 sections → **39** | `2026-09-09-report-proportionality.json` |

## What is not true yet

- **The C story does not work.** `c/memory` has produced zero true positives and three distinct classes of
  false one. It models string functions; libpng overflows through arithmetic, and its library code never
  calls a sink we model. This is structural, not tuning.
- **One language is demonstrated.** Python. JavaScript has fact tables and pair coverage but no repository.
  PHP, Ruby and Go have **zero families** — Joern would parse them and the engine would say nothing.
- **The suspicion band is still too loud.** vampi emits 61 report sections for a 520-line application, 38 of
  them a candidate the graph could not decide with a judge's opinion attached.
- **The evidence base is two repositories.** One has never produced a true positive.
- **Control dependence is unavailable.** 0 of 13,184 calls in the libpng CPG and 0 of 1,152 in vampi's have a
  controlling control structure, so every guard question runs on CFG dominance instead.
- **`execution_confirmed` has no production caller.** The rung exists and nothing reaches it.

## Why a corpus of benchmarks is not enough on its own

This is the finding worth teaching, and it is not an opinion — it is what the gates say.

**Twelve engine defects were found in one session by pointing the tool at three real repositories. The three
gates stayed byte-identical through every single fix.** A gate that does not move is a corpus that could not
see the bug.

| defect | what the corpus saw |
|---|---|
| `resolve` matched inside `resolveUrl` (sanitizers) | nothing |
| `user` matched inside `users` (dischargers) | nothing |
| `gets` matched inside `fgets` (sinks) — 26 identical false positives | nothing |
| the model layer had zero production callers | nothing |
| `query_batch` implemented, tested, unreachable | nothing |
| a paid budget halting unpaid arbitration | nothing |
| a region with no function claiming the whole repository's answer | nothing |
| a guard discharging an obligation it is not a guard of | nothing |
| `joern-parse` failing where the frontend succeeds | nothing |
| a 1.49MB batch over Linux's 128KB argv cap | nothing |
| an array callable not recognised as a handler | nothing |
| one defect reported as twenty-six findings | nothing |

The reason is structural rather than a gap in the corpus's coverage. **A pair is a labelled function with a
declared family and a known answer.** It cannot exercise: which region to look at, what to spend, whether the
capability is even reachable, whether two entry points share a sink, whether the question fits in an argv
slot, or whether a flow crosses a module boundary. Every one of those is a property of a *repository*, and
none of them is a property of a function.

Three of the twelve are worse than invisible — they are **quiet failures**, where the tool produced a clean
report and every honesty counter agreed with it. The rung ladder labels a *verdict*; when no verdict is
produced there is nothing to label. That is the failure mode a benchmark score cannot express at all, because
the score is computed from the verdicts that exist.

So the corpus is necessary and not sufficient: it is the **holdout** that stops per-repository tuning, and it
is the wrong instrument for finding out whether the tool works. Both instruments, or neither number means
anything.

## The lesson that shaped the current specs

Nine engine defects were found in one session by pointing the tool at two real repositories. **Three were the
same bug in three matchers** — a spec token matched as a substring: `resolve` in `resolveUrl`, `user` in
`users`, `gets` in `fgets`. Two were a capability built and unreachable: the model layer itself, then the
query batcher. One was a paid budget stopping unpaid work.

The three gates stayed **byte-identical through every one of those fixes**. That is the finding: a corpus of
function-level pairs could not see any of them, and a repository showed all nine within minutes.

## Where the specs stand

| spec | phase | state |
|---|---|---|
| `contributor-scan` | implementation | 14 done, 15 open — **the active one** |
| `finding-feedback-loop` | design | requirements approved, design awaiting approval |
| `model-grounded-detection` | complete | 16/16; built the arbiter this all rests on |
| `authorization-obligations` | tasks approved | 24 open — superseded in practice by the dominance arbiter |
| `constrained-detector` | tasks | 4 of 20, tasks unapproved |
| `reachability-flow-model` | tasks generated | 23 open, nothing approved — largely delivered by adopting Joern |
| `learning-harness` | implementation | 30 done, 3 open |
| six others | complete | `pair-corpus-honesty`, `corpus-seeded-mechanisms`, `propose-adjudicate-prove`, `three-stage-scan`, `real-world-vfc-slice`, `harnessx-self-improving-rulesets`, `tree-sitter-overlay-extra` |

97 source modules, 90 load-bearing and 7 standalone capabilities; 814 tests.
