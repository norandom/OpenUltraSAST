# Brief: three-stage-scan

## Problem

AppSec engineers and DevOps teams running OpenUltraSAST in CI get a regex static scan scored against cheat-sheet fixtures. They cannot tell what actually exists in a real repository, where complexity concentrates, how to aim tests, or whether a finding is worth a CI failure. The previous HarnessX spec added governance around those regexes (CWE policy, score, shadow status) without making the hunter evolutionary or the evaluation realistic.

## Current State

- `ousast scan --mode quick` is a deterministic regex inventory. It works.
- `--mode standard` is labeled a hunter pool but reuses the same regex path unless the optional HarnessX extra *and* a hunter model are both set. That hunter dumps a file into a prompt and scrapes JSON; it has no tools.
- `--mode deep` exits with "not implemented." Sandbox config exists on paper (`network=false`, read-only workspace, memory/pids/timeout). No container is ever started.
- Benchmarks are one-line sinks written to match the regexes. The fixtures themselves comment the misses (`regex blind spot`). The ≥90% recall gate is circular.
- CWE policy, project score, shadow status, traces, and SARIF already exist and should not be redesigned.

## Desired Outcome

A scan answers three operator questions, in order:

1. **What exists?** A static inventory of files, surfaces, and pattern/SARIF hits — honest about being inventory, not verified bugs.
2. **Where are problems most likely, and how do I tune tests?** A complexity map of hotspots plus test-gap hints a DevOps team can act on.
3. **Is this worth fixing?** Isolated regression against the top hotspots. Triggerable and reachable → worth a CI fail. Not triggerable → do not fail the build.

Stages 2–3 use a tool-calling hunter (read / grep / callers) and a Docker-isolated runner. Evaluation uses split-sink and mutation corpora, not cheat sheets. Missing Docker or a model degrades visibly; stage 1 still runs.

## Approach

**Map-then-prove on the existing modes.** Keep `--mode quick|standard|deep`:

- `quick` → stage 1 only
- `standard` → stages 1 + 2
- `deep` → stages 1 + 2 + 3

Do not require the HarnessX extra for the LLM path. Use the existing stdlib OpenRouter client when a hunter model is configured. HarnessX remains an optional alternative runtime.

Do not add a Python Docker SDK. Drive the Docker CLI via subprocess with the threat-model flags (no network, read-only source, tmpfs scratch, memory/pids/timeout, cap-drop). Core `dependencies = []` stays.

Complexity map is a new artifact built from existing ranking, entry points, finding density, nesting/size, and test-file presence — not a rewrite of `RankingScore`. Stage 3 writes a worth-fixing verdict that feeds back into a complexity ledger (evolutionary), without editing detection pattern text.

## Scope

- **In**: three-stage scan contract; complexity map + test-tuning hints; Docker-isolated regression and worth-fixing verdicts; tool-calling hunter on hotspots; split-sink/mutation evaluation; CI mapping (PR = stage 1, nightly = stage 2/3); visible degradation; evolutionary feedback from regress → map.
- **Out**: rewriting CWE policy or project-score formula; auto-authoring regex patterns; full fuzzing campaigns; patch generation/application; network pentest; importing Clearwing.

## Boundary Candidates

- Stage orchestrator (which stages a mode runs, artifacts, degradation)
- Complexity map (hotspots, signals, test-gap hints)
- Sandbox runner (Docker CLI, capability probe)
- Regression / worth-fixing (candidate tests, verdicts, ledger feedback)
- Tool-calling hunter (repo-bound tools + model loop for stages 2–3)

## Out of Boundary

- PolicyStore / ScoreModel / RulesetStore internals (consume, do not own)
- MetaAgent.evolve regex-status loop (adjacent, do not replace)
- Deep fuzzing, exploit development, auto-patching
- HarnessX packaging / optional extra (may be used, not required)

## Upstream / Downstream

- **Upstream**: existing preprocess, rank, mapping, findings, verification, config, CLI modes, OpenRouter client, threat-model sandbox limits.
- **Downstream**: CI fail-on `worth-fixing`; later fuzz/patch specs; MCP scan status.

## Existing Spec Touchpoints

- **Extends**: `openrouter-sast-harness` gates `standard_security_harness` and `sandboxed_dynamic_harness` (still unsatisfied).
- **Adjacent**: `harnessx-self-improving-rulesets` owns CWE policy, score, shadow, optional HarnessX extra. This spec must not reopen those.

## Constraints

- Core install stays zero-dependency. Docker CLI and an LLM key are operator-provided runtimes, not Python dependencies.
- Scanned code is untrusted. Stage 3 is the first mode allowed to execute target-derived code, and only inside the sandbox.
- LLM output starts at evidence `suspicion`. It must not be stamped `static_corroboration`.
- Cheat-sheet one-liners may remain as unit fixtures; they must not be the merge gate for stages 2–3.
