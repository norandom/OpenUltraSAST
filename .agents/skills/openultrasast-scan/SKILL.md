---
name: openultrasast-scan
description: OpenUltraSAST scan workflows - `ousast scan` in quick, standard or deep mode, the evidence ladder, `--fail-on` exit codes, recorded degradations, the run directory and `ousast mcp`. Use when running or planning a scan, reading a run directory, or wiring OpenUltraSAST into an agent.
---

# OpenUltraSAST Scan

Use this skill to run `ousast scan PATH --mode quick|standard|deep` from an agent and to read what
it wrote.

## Workflow

1. Confirm the target is a local checkout (a path, not a URL).
2. Run through the project entry point: `uv run ousast ...` inside the repository, or `ousast` from an
   environment where it is installed. Never activate a virtualenv by hand.
3. Start with `--mode quick` unless the task needs the Joern model layer (`standard`) or sandboxed
   regression snippets (`deep`). Check the prerequisites below first; a mode whose engine is missing
   still exits 0 and records a degradation.
4. Read the printed `scan_id=` and `run_dir=` lines; the run directory is `.openultrasast/runs/<scan-id>/`.
5. Report the finding count, how many the verifier accepted, and **every** recorded degradation
   (`manifest.json`, key `degradations`). No findings plus a degradation is not a clean scan: the scan
   answered a smaller question than it was asked.
6. Never call a finding verified from its title or severity. `verification.json` holds the status.

## Commands

```bash
uv run ousast scan <repo> --mode quick
uv run ousast scan <repo> --mode standard --fail-on verified
uv run ousast scan <repo> --mode deep --fail-on worth-fixing
uv run ousast scan <repo> --mode quick --config openultrasast.toml
uv run ousast mcp                 # the MCP server over stdio, for agent hosts
```

## Modes and prerequisites

| Mode | Adds | Needs | Without it |
| --- | --- | --- | --- |
| `quick` | language-scoped pattern rules, entry-point hints, ranking, verification, score; deterministic | nothing | - |
| `standard` | the MAP stage: complexity map, semantic overlay, authorization obligations, the Joern model layer (one code property graph per repository; taint, guard-dominance and configuration questions), deterministic fusion | Joern (shipped in the Docker image, with `php-cli` for PHP); a provider key for the residual LLM question | `cpg_unavailable`; without a key the LLM question is not asked and only the graph's entailed findings are reported |
| `deep` | REGRESS: promoted candidates run as snippets in a Docker sandbox (no network, read-only source, non-root) and get a `triggerable` / `not_triggerable` / ... verdict in `verdicts.json` | a working `docker` | `sandbox_unavailable` |

Model stages read `DEEPSEEK_API_KEY` (every LLM call); with only `OPENROUTER_API_KEY` set, chat
calls fall back to OpenRouter. An exported shell variable wins over `.env` silently. `[models]
hunter` in the config enables the tool hunter in `standard`; it is off by default.

## Exit code: `--fail-on`

| Policy | Exit 1 when |
| --- | --- |
| `never` (default) | never |
| `findings` | any finding was reported |
| `verified` | any verification result is `verified` (accepted at `static_corroboration` or above) |
| `worth-fixing` | a deep-mode sandbox verdict is marked `worth_fixing` |

A degradation never changes the exit code. Read `manifest.json` for it.

## Recorded degradations

Each entry in `manifest.json` `degradations` is `{"stage": ..., "reason": ...}`. The ones to expect:

- `cpg_unavailable` (stage `model`): no Joern on the host; the model layer ran nothing.
- `sandbox_unavailable` (stage `regress`): no working `docker`; deep mode fell back to standard.
- `learning_endpoint_unavailable` (stage `model`): no provider key resolved. The graph's entailed
  findings are still reported; the residual question is skipped. This is recorded in `manifest.json`
  but has no line in `report.md`'s "What could not be analysed" section.
- `hunter_model_unavailable` (stage `map`): `[models] hunter` is unset, so the tool hunter did not run.
  Recorded on every standard scan without that setting; it is expected, not an error.
- coverage facts from the graph, rendered in `report.md` under "What could not be analysed":
  `cpg_empty`, `cpg_build_failed`, `cpg_sharded`, `files_unparsed`, `query_failed`,
  `query_budget_reserved`, `query_too_expensive`, `budget_exhausted`, `regions_truncated`,
  `region_failed`; plus `max_findings_exceeded` and `facts_unavailable` (overlay, obligations).

Prove the instrument read its input before believing a zero: `manifest.json` names the stages that
ran and the files the preprocess step kept (`preprocess/file_targets.json`).

## Evidence ladder

`src/openultrasast/verification.py` defines the levels in this order. A level moves one rung at a
time and never backward.

| Level | Meaning | Produced today by |
| --- | --- | --- |
| `suspicion` | a rule, model or weak signal raised a hypothesis | the Joern model layer (its rung, `model_entailed` or `suspicion`, travels in the finding's tags), the tool hunter, authorization-obligation checks |
| `static_corroboration` | deterministic code evidence at the line | quick rules, the semantic overlay |
| `crash_reproduced` | an artifact-backed reproducer | nothing: there is no crash reproducer. Deep-mode sandbox verdicts (`verdicts.json`, `worth_fixing`) do not raise the level |
| `root_cause_explained` | independent verifier reasoning | nothing: the LLM judge was retired in v2.0.0 |
| `exploit_demonstrated` | a demonstrated exploit | nothing |
| `patch_validated` | relevant checks re-run after a patch | nothing: there is no patch stage |

The verifier's status per finding (`verification.json`): below `static_corroboration` is
`needs_evidence`; `static_corroboration` with reachability `unknown` is `rejected` (the tie-breaker
asks for call-graph, route, CLI, parser or dynamic evidence); `static_corroboration` with
function-level reachability is `accepted`. `verified` means accepted at `static_corroboration` or
above, and that is what `--fail-on verified` counts. There is no configurable report threshold: the
`[evidence]` config section was retired in v2.0.0 and is ignored.

## Run artifacts

Under `.openultrasast/runs/<scan-id>/`:

- `report.md`, `report.sarif` (SARIF 2.1.0 for code hosts and IDEs), `manifest.json` (stages, degradations, model payload)
- `findings.json`, `verification.json`, `score.json`, `shadow_findings.json` (rules shipped as `shadow`)
- `harness.json`: the resolved harness configuration the run used
- standard: `fusion.json`, `complexity_map.json`, `overlay.json`; deep: `verdicts.json`
- `calibration/false_positive_learnings.json`, `rank/ranking.json`, `mapping/`, `preprocess/`, `trace/events.jsonl`

## Changed code only

`ousast pre-push --base <rev> --head <rev> --artifact <file> <repo>` replays a revision pair and
reports only new or worsened defects (experimental; `--mode advisory` is the default and never
blocks). The capability registry is empty, so every candidate is diagnostic.

## MCP

`ousast mcp` serves a narrow MCP server over stdio (newline-delimited JSON-RPC) with ten tools:
`openultrasast.scan`, `status`, `findings`, `get_finding`, `evidence`, `artifacts`, `benchmark`,
`explain`, `propose_patch` (degrades visibly) and `export_report`. No tool runs a shell, Docker or a
free-form command.

```jsonc
{ "command": "uv", "args": ["run", "ousast", "mcp"] }
```
