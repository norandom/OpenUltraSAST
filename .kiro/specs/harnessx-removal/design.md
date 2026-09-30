# Design Document

## Overview

HarnessX leaves the product in one reviewable sequence, and the plane's memory layer takes over what HarnessX was
meant to drive. Three facts from the code shape the design:

- **No HarnessX capability is measured, and one of them never existed.** The LLM paths are reached only through
  config keys, not CLI flags (`scan` has `path`, `--mode`, `--config`, `--fail-on`; `cli.py:163-167`), and
  `benchmarks/` holds no run of any of them (no `hx-hunter:` finding, no `llm-panels` decision). The
  `MetaAgent.evolve` proposer is only a docstring (`improve/evolve.py:8-9`, `harness_ext.py:7-8`). No code calls it.
- **The plane already does the LLM work better, and outside `ousast scan`.** `verify` (two passes, known callers
  from `repo-facts`) plus `agree` (2-of-3 with the tie-break) met the ai-service-plane gate
  (`benchmarks/independent/plane-increment-2.json`: 16/20 declared sites agreed, $0.0205 per candidate). The
  standard-mode LLM hunter that users actually reach, the tool hunter at the MAP stage (`cli.py:631-640`,
  `tool_hunter.resolve_hunter_client`), is not HarnessX and stays.
- **Everything deterministic already runs without the extra.** Every guarded branch falls back to a deterministic
  function (`run_hunter_pool`, `verify_findings`, `fuse_finding`). Removal therefore makes the fallback the only
  path. Quick mode, `benchmark`, `pairs`, `improve` and the gates never enter a guarded branch.

So every HarnessX capability in `ousast scan` is **retired** with its deterministic path kept. The plane's `verify`
and `agree` tasks are the documented agentic path (`ousast plane run <Run>`). The proposer is **carried by the
memory layer**: a persistent store, keyed by repository and pin, that plane Runs write through a model-free
`remember` task. From that store a deterministic generator emits `RuleStatusEdit` proposals into the unchanged
`EvolveValidator` and gate. The improvement loop becomes a plane Run whose only Model-bound tasks are the verify
passes.

## Architecture

```
Before                                              After
ousast scan --mode standard                         ousast scan --mode standard
  hunter_pool: HxScanOrchestrator | run_hunter_pool   hunter_pool: run_hunter_pool (only path)
  verify: verify_judge (llm-judge) | verify_findings  verify: verification.verify_findings
  fusion: llm panels | deterministic panels           fusion: deterministic panels (fuse_findings)
  MAP: tool hunter ([models] hunter, DeepSeek)        MAP: tool hunter (unchanged)
harness_ext.py, hunter_harness.py, verify_judge.py  deleted
stage_processors.host_under_harnessx                deleted; deterministic pipeline kept
[harnessx] config, extra, mypy override, lock       one load warning; extra/override/lock gone
improve: benchmark per-rule proposer (+ MetaAgent   improve: benchmark proposer + memory proposer (--memory)
         "plugs in" -- never implemented)
                                                    plane Run (per case)
                                                      facts -> va, vb -> agree -> vc -> final   (existing)
                                                      alerts (new, no model) ------------------+
                                                      remember (new, no model) <- facts, final, alerts, va/vb/vc
                                                    plane Run (loop tail, once)
                                                      measure -> propose -> improve(validate+gate)   (no model)
~/ousast-results/plane/memory/                      the store: facts by content, rows by repo + pin
```

New code: `src/openultrasast/plane/memory.py` (store, ingest, seed; host side),
`src/openultrasast/plane/tasks/{alerts,remember,measure,propose,improve}.py`,
`src/openultrasast/improve/memory.py` (deterministic proposal rules). None of it is in the reconciler. The
reconciler gains only `mark_done` (below). It is 465 lines today, and `tests/test_plane_reconciler.py:759-761`
keeps it under 500.

## Components and Interfaces

### 1. Fate of each HarnessX capability (Requirement 1)

| Capability | Where today | Fate | What the user loses |
| --- | --- | --- | --- |
| LLM hunter pool (`HxScanOrchestrator`) | `hunter_harness.py:49-185`; gated in `cli.py:400-456` (`hx_hunter` at :405, orchestrator at :438-448, degradation at :452-455) | **Retired.** `run_hunter_pool` becomes the only standard-mode hunter pool. LLM hunting of a repository stays available in two places: the MAP-stage tool hunter in `ousast scan --mode standard/deep` with `[models] hunter` (`cli.py:631-640`, not HarnessX), and plane `verify` via `ousast plane run plane/runs/validation-46.yaml` | `hx-hunter:<path>:<line>` findings from an anthropic/openai/litellm agent (`hunter_harness.py:155`). No run of this path is recorded under `benchmarks/`, so no measured TP is lost. |
| LLM judge | `verify_judge.py:22-63`; gated in `cli.py:406, 499-511` | **Retired.** `verification.verify_findings` is called directly and `verify_judge.py` is deleted (it is only the dispatcher and the judge). The plane's LLM verification is `verify` + `agree` (+ `vc`/`final` tie-break) | Per-finding `plausible/unsupported` verdicts that set `ACCEPTED/REJECTED` (`verify_judge.py:83-88`). Unmeasured. `[models] judge` (model-grounded-detection, `model/endpoint.py:195`) is a different capability and stays. |
| LLM fusion panels | `fusion.py:194-326` (`_fuse_with_llm_panels`, `_run_llm_panels`); gated in `cli.py:519-541` | **Retired.** The deterministic panels (`_panel_a`, `_panel_b`, `_reconcile`, `fusion.py:101-167`) become the only path. `fuse_findings_dispatch` is renamed `fuse_findings(findings, verifications, *, high_assurance, mitigated_ids)`. The plane counterpart of independent cross-examination is `agree` across independent passes with the 2-of-3 tie-break | Steel-man LLM panels (`decision_source: "llm-panels"`). Unmeasured. `fusion.json` for deterministic decisions is unchanged. |
| Deterministic stages hosted under HarnessX | `stage_processors.py:129-156` (`host_under_harnessx`); only caller is the skipped test `test_slot_contract.py:119-133` | **Retired, no replacement.** ax runs whole tasks, so a model-disabled in-loop host has nothing to host. `stage_processors`/`slot_contract` stay as the standalone deterministic pipeline that `test_gate.py:147-148` pins | Nothing. The function has no production caller. |
| LLM evolution proposer (`MetaAgent.evolve`) | docstring only: `improve/evolve.py:8-9`, `harness_ext.py:7-8` | **Carried by the memory layer** (Requirement 6): `improve/memory.py` rules over the store, fed into `run_round` as extra proposals | Nothing implemented is lost. |

No CLI flag is HarnessX-specific, so Requirement 1.3 applies to config keys. A key that asked for a retired
capability makes `load_config` raise `RetiredConfigError(ValueError)`, and the CLI prints the message and exits 2.
A silent downgrade is not allowed:

| Key | Message (abridged) |
| --- | --- |
| `[models] verifier` | "`[models] verifier` was retired with HarnessX on <date>: LLM verification runs on the plane (`verify` + `agree`, `ousast plane run`, see ops/ax/README.md). Remove the key." |
| `[fusion] panel_model`, `[fusion] decider_model` | "... LLM fusion panels were retired; fusion is deterministic; independent LLM agreement is the plane's `agree` task ..." |

`[harnessx]` is different (Requirement 3.3). It only tuned budgets and never requested a capability, so it loads
with **one** `logging.warning` on logger `openultrasast.config` that names the plane ("`[harnessx]` is ignored:
HarnessX was removed; agentic work runs on the ax plane with per-task budgets, see ops/ax/README.md"). The section
is otherwise ignored. `[models] hunter` keeps its meaning (tool hunter, obligations intent adjudication at
`cli.py:1237`), so it gets no message. With the extra installed it no longer starts a second, HarnessX hunter. The
release notes say so.

Requirement 1.2 (moved capabilities have a CLI path, a Model per task and a fixture test) is met by the existing
`verify`/`agree` tasks (`ousast plane run`; Model `deepseek-flash` bound per Task; `tests/test_plane_verify.py`,
`tests/test_plane_scoring_parity.py`, `tests/test_plane_tiebreak.py`), and by the new memory and loop tasks below, each with its own fixture test. No
capability is moved into a new Model-bound task.

### 2. Removal mechanics (Requirement 2)

**Source.**

- Delete `harness_ext.py` (97 lines), `hunter_harness.py` (197) and `verify_judge.py` (130).
- `cli.py`: drop the imports at :44, :46 and :94. Drop `harnessx_present`, `hx_hunter` and `hx_verify` (:400-406),
  the orchestrator branch and its degradation (:438-456), and the verify degradation (:499-502). Call
  `verify_findings(findings)` at :503-511. Drop `hx_fusion` and its degradation (:521-527). Call
  `fuse_findings(findings, verifications, high_assurance=config.fusion.high_assurance)`. The `verifier_model`
  local goes away.
- `fusion.py`: drop the import at :24, the `panel_model`/`decider_model`/`provider`/`use_harnessx` parameters, and
  `_with_degradation`, `_fuse_with_llm_panels`, `_run_llm_panels` and `_text` (:229-338). Rewrite the module
  docstring (:10-14) and update `__all__`.
- `stage_processors.py`: drop `host_under_harnessx` (:129-156) and its `__all__` entry, and rewrite the module
  docstring (:10-11). `slot_contract.py:7-14` becomes "the zero-dependency substrate for the deterministic
  pipeline".
- `config.py`: drop `HarnessxConfig` (:99-107), `ResolvedConfig.harnessx` (:201), `_load_harnessx` (:345-351) and
  its call (:230). Drop `ModelConfig.verifier` (:37), `FusionConfig.panel_model/decider_model` (:123-124) and
  their loaders (:266, :366-367). Add `RETIRED_KEYS` and the one-warning rule above. `harness.py:183` keeps the
  `"verifier": None` literal in `model_roles`, so `harness.json` keeps its schema byte for byte (the key has always
  been `null` in the baseline config).
- Comment-only mentions: `gate.py:174` ("a model-backed stage"), and `improve/evolve.py:8-9`, which now names the
  memory proposer.
- `plane/Dockerfile.runner:23` loses "no HarnessX".

**Packaging.**

- Delete the `harnessx` extra and its comment (`pyproject.toml:14-22`) and the `harnessx.*` mypy override and its
  comment (:67-71).
- `uv lock` regenerates `uv.lock`. The `harnessx` package (:1062), the extra (:2145-2146), the requirement
  (:2169) and `provides-extras` (:2178) go.
- Extras that remain: `semantic`. There is no `all` extra. `pip install .` and `pip install '.[semantic]'` in a
  fresh venv are the Requirement 2.2 check.
- No source or test imports a HarnessX transitive dependency. The only third-party imports are `yaml`,
  `tree_sitter` and `pytest` (checked with an import scan), so dropping the lock entry cannot break an import.

**Tests** (14 files plus `conftest.py`):

| File | Action |
| --- | --- |
| `test_harness_ext.py`, `test_hunter_harness.py`, `test_verify_judge.py`, `test_cli_hx_dispatch.py` | **Delete.** Each exercises only HarnessX or its dispatcher. |
| `conftest.py` | Rename fixture `assert_cold_of_harnessx` to `assert_cold_import(code)`: a fresh interpreter runs `code`, with no module-name guard. `test_semantic_extra.py:28-35` is its remaining user (the tree-sitter check brings its own assertion). |
| `test_gate.py` | Delete `test_harnessx_stage_stays_within_tolerance_of_baseline` (:124-150) and the `has_harnessx` import (:23). Replace the two "never import" tests (:155-175) with `test_governance_planes_import_only_stdlib_and_declared_dependencies`, an allow-list (stdlib, `openultrasast`, `yaml`) over module-level imports of `GOVERNANCE_SCORING_BENCHMARK_PLANES`. It covers any extra without naming one. Update the docstring at :5-6. |
| `test_scan_pipeline_integrity.py` | Rename `test_standard_scan_extra_absent_matches_deterministic_baseline` to `test_standard_scan_with_a_hunter_model_keeps_deterministic_findings` (config `hunter` only). Rename `test_quick_scan_is_unaffected_by_the_extra` to `test_quick_scan_records_no_degradation`. Drop the `has_harnessx` monkeypatch and the `harnessx` parameter. Recompute the expected degradation set from the post-removal run, since `hunter_pool`/`verify` entries no longer exist. |
| `test_slot_contract.py` | Delete `test_host_under_harnessx_disables_the_model` and the imports at :16 and :22. Keep the rest. |
| `test_config.py` | Replace `test_harnessx_defaults_when_section_absent` and `test_load_config_reads_harnessx_section` with `test_retired_agentic_section_loads_with_one_warning` (caplog: exactly one record naming the plane) and `test_retired_llm_keys_fail_naming_the_replacement` (verifier, panel_model, decider_model). |
| `test_fusion.py` | Delete `test_dispatch_records_degradation_when_llm_requested_but_extra_absent` (:142-146) and the import at :16. Rename the dispatch calls to `fuse_findings`. |
| `test_tool_hunter.py` (:229, :266), `test_scan_deep.py` (:144) | Drop the `has_harnessx` monkeypatch line. |
| `test_semantic_extra.py` | Use `assert_cold_import`. |
| `test_module_audit.py` | The subsystem tuple at :31 becomes `("fusion", "mcp", "skills")`. A new assertion checks that the three deleted modules are absent from the audit. |

**Module audit.** `model/audit.py:76-77` (`harness_ext`, `hunter_harness`) are deleted, and `:78`
(`stage_processors`) is reworded to "deterministic slot-contracted scan stages; pinned by the zero-dependency
guard in test_gate". Regenerate `benchmarks/measurements/2026-09-08-module-audit.json` in place with `to_dict(audit(SRC))`.
`test_the_manifest_matches_the_tree` pins that path. The diff shows three rows removed and no orphan.

**Search (Requirement 2.4).** `grep -rni harnessx src tests pyproject.toml README.md` may match only lines tagged
`retired 2026-..`:

- the `RETIRED_KEYS` entry and warning text in `config.py`
- the two retirement tests in `test_config.py`
- the one README line in the plane section

Requirement 3.3 cannot be implemented or tested without naming the section, so these lines count as retirement
notes. The check is a test (`test_no_harnessx_outside_retirement_notes`) that fails on any untagged match. It
builds its pattern at runtime, so it does not match itself.

### 3. Equality proof (Requirement 3)

The spec's "`ousast regress`" is not a subcommand (`cli.py:133-251`). Regress exists only as the deep-mode
sandbox stage. On this project the regression command over the development pins is `ousast pairs`
(README.md:38): the vuln-vs-fixed replay over local fixtures and vendored pinned VFC pairs, offline by default.
The benchmark replay is README.md:35's manifest. The baseline also covers the two paths the removal touches
directly: one standard-mode scan (verify and fusion) and one `improve --dry-run` (evolve). Everything is
quick or standard mode with no Joern on the host, so each command takes minutes, not hours, on this 7 GB host.

**Environment (instrument first).**

- Run from a `git archive HEAD` export in the scratchpad (the source is frozen, per the long-runs rule).
- `uv sync --frozen --extra semantic`, which drops the installed `harnessx`. It is installed in `.venv` today.
- `OPENULTRASAST_SKIP_DOTENV=1` and `env -u DEEPSEEK_API_KEY -u OPENROUTER_API_KEY -u ANTHROPIC_API_KEY -u OPENAI_API_KEY`,
  plus an empty `--config`, so no command can reach a model.

The harness asserts `find_spec("harnessx") is None`, `find_spec("tree_sitter") is not None`, and a
`uv pip freeze` hash. It also prints the byte size of each input manifest, and fails on any non-zero exit code.

**Commands** (one script, `benchmarks/harnessx_removal_equality.py record|compare <dir>`):

1. `pytest -q -p no:cacheprovider --junitxml=suite.xml`, which gives outcome per test id.
2. `ousast pairs --json > pairs.json`. Instrument check: pair count > 0 and at least one TP.
3. `ousast benchmark benchmarks/manifests/python-vulnerable.toml --mode quick`. Keep
   `benchmark_result.json`, `calibration_records.json` and `external_baseline_deltas.json`. Instrument check:
   `expected > 0`.
4. `ousast scan benchmarks/fixtures/python-vulnerable --mode standard --config empty.toml`. Keep
   `findings.json`, `verification.json`, `fusion.json`, `report.sarif`, `harness.json` and `manifest.json`.
5. `ousast improve benchmarks/manifests/java-spring-boot-vulnerable.toml --dry-run --no-pair-gate`, stdout plus
   the dry-run journal.

**Stored.** `benchmarks/measurements/<date>-harnessx-removal-baseline/`: the normalized outputs, and `env.json`
(commit, freeze hash, instrument checks). The script's exclusion list is written into that directory's
`README` line.

**Comparison.** JSON is parsed, normalized and re-serialized with sorted keys. Everything else is compared as
raw bytes. Excluded:

- keys `runtime_seconds`, `scan_id`, `timestamp`, `started`, `finished`, `created_at`, `generated_at`, and any
  key ending `_seconds` or `_ms`
- run directory names (timestamped, `benchmark.py:186`)
- `trace/events.jsonl` as a whole (timings)
- the export's absolute root path, replaced by `<ROOT>`

For the suite, every test id that survives must keep its outcome. Deleted and renamed ids are compared through
the map in the Tests table above, and any other difference is a failure. Any difference in 2-5 blocks the merge.

### 4. Memory layer (Requirement 6.1, 6.4)

**Store** (`plane/memory.py`). The store lives at `results_root()/memory/` (`~/ousast-results/plane/memory/`,
honouring `OUSAST_RESULTS`, `reconciler.py:58-59`). It is JSON files, not SQLite: the rest of the plane is JSON,
diffable and greppable, and one run at a time holds the run lock, so SQLite's concurrency buys nothing.

```
memory/
  index.jsonl                       one row per ingested (run, task): sha256 of its memory.jsonl, row count
  facts/<sha256>.json               facts.json by content (identical facts stored once)
  repos/<host>__<owner>__<name>/<pin>.jsonl   the rows of one repository + 40-hex pin
```

Ingest is idempotent: an `index.jsonl` hit skips the delivery, and rows carry a deterministic `id`. Ingest also
refuses to write when `shutil.disk_usage` reports less than 1 GiB free. The disk is at 98% today, so it names
the store path in the error.

**Storage backends (maintainer, 2026-09-30: "think of using minio features, including its json support. i have a
server").** The store is written against one interface, `MemoryStore` (`put_row`, `put_facts`, `get_facts`,
`rows(repo=..., pin=..., kind=..., where=...)`, `index`), with two backends of identical behaviour:

- `FileStore`: the layout above, for this laptop and the unit tests.
- `MinioStore`: the maintainer's MinIO server, and the store of record once the plane runs on a separate
  Kubernetes cluster. The layout maps onto one bucket with the same key paths:
  - **Object metadata and tags** on every row object: `repo`, `pin`, `kind`, `family`, `run`, `population`,
    `split`. Rules list by prefix (`repos/<repo>/`) and filter by tag instead of scanning the bucket.
  - **Server-side JSON queries**: `rows(where=...)` pushes the filter down with S3 Select
    (`SelectObjectContent`, JSON Lines input, JSON output), so a proposal rule reads matching rows, not whole
    files. Support is probed once per process against the server (a small Select on a known object); when the
    server lacks it (some MinIO releases removed S3 Select), the backend fetches and filters locally, logs the
    fallback once, and returns the same rows. A query never silently returns nothing because a feature is
    missing.
  - **Versioning** on the bucket: each proposal's provenance records the object key and version id of every
    memory row it cites, so its evidence cannot change underneath it (Req 6.4). Object lock (governance mode) is
    optional for the `proposals/` prefix.
  - **Lifecycle rules**: raw run outputs under `runs/` expire after a configurable number of days; `repos/`,
    `facts/` and `proposals/` are kept. The near-full laptop disk stops being the store's limit.
  - **Presigned URLs** (the step that removes the host receiver for the Kubernetes move, not built in this
    spec): the reconciler can hand a task presigned PUT URLs for its outputs and GET URLs for its inputs in the
    start request, so tasks write to MinIO directly and never hold credentials. The interface keeps
    `presign_put`/`presign_get` so that follow-on changes the reconciler, not the store.
  - **Bucket notifications** (follow-on): an event on new `repos/` rows can trigger the loop Run
    (event-driven loop engineering).
- **Configuration**: `OUSAST_MEMORY` selects the backend (`file:///path` or `minio://<bucket>`); the MinIO
  endpoint and credentials come from `.env` (`MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`,
  `MINIO_SECURE`), never from a manifest, never printed. Client: the `minio` Python SDK as an optional extra
  (`openultrasast[minio]`); the core install stays PyYAML-only.
- **Tests**: the same contract tests run against `FileStore` and against `MinioStore` pointed at a MinIO
  endpoint (skipped unless `OUSAST_MEMORY_TEST_MINIO` is set), including the Select probe with its fallback
  forced, versioned provenance, and metadata filters. The disk-space refusal applies to `FileStore` only.

**`remember` task** (`plane/tasks/remember.py`, no Model, budget `{usd: 0, calls: 0}`, one per case). It reads the
case's delivered artifacts as inputs: `facts.json`, the `units.jsonl` of `va`/`vb`/`vc`, `final/agreed.json` and
`final/disputed.json` with the per-candidate rows, and `alerts.jsonl`. It takes the repository URL and pin from
the bound Workspace (`AX_WORKSPACES_YAML`, `OUSAST_GIT_PINS`) and the population from the Run annotation
`openultrasast.io/population`. It writes `memory.jsonl` and passes `facts.json` through. Task code interprets
the artifacts, so the reconciler and runner stay content-blind (ai-service-plane Req 3.4). After `reconciler.run`
returns, `cli._plane` calls `memory.ingest(run_dir)`. `ousast plane remember <run>` does the same by hand.

**Row kinds** (every row has `id`, `kind`, `repo`, `pin`, `run`, `task`, `population`, `split`, `image`):

- `facts`: `sha256`, `candidates_digest` (`repo_facts._digest`, `repo_facts.py:188`), `files`.
- `verdict`: `candidate` (`path::function`), `family`, `site`, `passes {a, b, c}` (true/false/null), `final`
  (`agreed | rejected | disputed`), `tiebreak` (bool), `site_match` (bool/null), `usd`, `turns`.
- `unit_cost`: `pass`, `path`, `usd`, `calls`, `usage`, `turns`, `model`.
- `alert`: `rule_id`, `rule_status` (`enabled | shadow`), `path`, `line`, `function`, `pin_role`
  (`vulnerable | fixed`).
- `proposal_outcome`: `edit_key`, `evidence_digest`, `outcome` (`accepted | reverted | rejected`), `gate_run`.

**Fact reuse.** A facts entry is valid for the key (repo, pin, candidates digest, runner image digest). The image
is in the key because the host's source and the image's source can differ, and facts computed by other code are
not the same facts. `ousast plane workspaces --validation-set` writes the key as the Task annotation
`openultrasast.io/memory-key`. Annotations are already stripped before ax (`manifests.py:4-6`). Before
`reconciler.run`, `cli._plane` calls `memory.seed(run_manifest)`. For each Run entry whose Task carries a key with
stored facts and no state yet, seed writes `<run>/<task>/facts.json` and a `summary.json`
(`status: done, units_done == units_total == 1, reused: {"sha256", "from_run"}`). It then calls
`reconciler.mark_done(run, task, reused=...)`, a public helper of about 10 lines that takes the run lock, sets
the state and releases it. The reconciler already skips `done` tasks (`reconciler.py:342`). The receiver already
serves any regular file under the run directory as a declared input (`egress.py:242-246`). A changed pin, a
changed candidate set or a rebuilt image recomputes.

### 5. Proposals from memory (Requirement 6.2, 6.4)

**Interface.** The proposal surface HarnessX would have used is `run_round` (`improve/evolve.py:149-247`). It
builds `RuleStatusEdit`s (`improve/validator.py:36-47`), filters them through the journal's novelty gate
(`journal.reverted_edit_keys`, `journal.py:26-38`), validates each with `EvolveValidator.validate`
(`validator.py:75-81`, which accepts only `RuleStatusEdit` and `PolicyConstantEdit`), smoke-replays and gates.

`improve/memory.py` exposes:

```
propose_from_memory(rows, ruleset_by_id, current_ledger, journal_rounds, *, excluded) -> list[MemoryProposal]
MemoryProposal = (edit: RuleStatusEdit, provenance: dict)
```

`run_round` gains `proposals: Sequence[MemoryProposal] = ()`. It appends their edits after the benchmark's edits
and keeps the first edit per `key()`. The validator and the gate are untouched. `ousast improve` gains
`--memory [DIR]` (off by default, so the deterministic `improve` output is byte-identical) and
`--qualify-population NAME` (repeatable).

**Rules** (the thresholds are module constants and part of the provenance record). Join key: an `alert` and a
`verdict` match when repo, pin and `path::function` are equal. A `disputed` final counts as no evidence in
either direction.

- **M1, repeated false alerts** (`enabled -> shadow`). Rule R qualifies when both hold:
  - at least 3 R alerts sit at candidates whose final is `rejected`, or on a `fixed` pin inside the case's declared
    fix range, across at least 2 distinct repositories;
  - no R alert sits at an `agreed` candidate or a `site_match` site.
- **M2, missed declared sites** (`shadow -> enabled`). Shadow rule R qualifies when all three hold:
  - its shadow alerts hit at least 2 `agreed` candidates with `site_match == true`, across at least 2
    repositories;
  - no enabled rule alerts at those candidates;
  - R has no alert on a `fixed` pin at the same function and at most 1 alert at a `rejected` candidate.
- **M3, frequently disputed families.** Families with at least 5 candidates and a dispute rate of at least 0.3 go
  to `signals.json` as advisory input for plane routing (for example, scheduling pass `c` up front). They are not
  an edit and never reach the validator.

**Provenance.** Each proposal's `rationale` is `memory:<proposal_id>`, where `proposal_id` = sha256 of
(rule, edit key, sorted evidence row ids, thresholds). The sidecar `memory_proposals.jsonl`, next to the journal,
holds:

- `proposal_id`, `edit_key`, `rule_id`
- `evidence` (the row ids plus their repo, pin, run and task)
- the counts that met each threshold
- `excluded` (populations and pins removed by the guard, with counts)
- the store's `index.jsonl` digest at proposal time

`evolve._record` (`evolve.py:366-396`) adds `"evidence": proposal_id` to an edit's journal entry only when the
edit came from memory. Otherwise the journal is unchanged byte for byte. A reader follows journal, then sidecar,
then store rows, then the run directory.

**Novelty.** `journal.reverted_edit_keys` does not block a rule edit that carries a rationale (`journal.py:36`), so
a memory proposal would otherwise come back every round. The proposer itself skips any key whose reverted journal
entry has the same evidence digest. New evidence is the "new rationale" that allows a retry.

**Train-on-test guard.** A row is excluded from proposals when any of these holds:

- (a) its `population` is one of `--qualify-population`, which is also where the proposal will be gated or
  qualified;
- (b) its (repo, pin) is a case of the benchmark manifest being gated;
- (c) its (repo, pin) is a `split = "holdout"` pair of the pair catalog, which the per-profile holdout clause
  (`evolve.py:204-214`) measures.

This is the rule the closed-loop leak broke, where a holdout pair taught the shape that "recovered" it. Here the
filter runs before any rule sees a row. Concretely, rows from `validation-46` (population
`independent-v2/validation`) never propose edits that are then qualified on `independent-v2/validation`. The
tie-break was designed on that set, so it is development evidence only.

### 6. The loop as a plane Run (Requirement 6.3)

`ousast plane workspaces --validation-set ... --loop` extends the generated Run. It also emits a Workspace for each
case's fixed pin (the population's `fixed` sha, already read by `generate.fix_ranges`, `generate.py:89`):

| Task (per case unless noted) | Model | Budget | Inputs -> outputs |
| --- | --- | --- | --- |
| `<case>-facts`, `-va`, `-vb`, `-agree`, `-vc`, `-final` | verify passes: `deepseek-flash`; others none | as generated today (`generate.verify_budget`) | unchanged |
| `<case>-alerts` (new) | none | `{0, 0}`, `serialize: engine` | vulnerable + fixed Workspaces -> `alerts.jsonl` (quick-mode `quick_scan_findings` with enabled and shadow rules, function-attributed) |
| `<case>-remember` (new) | none | `{0, 0}` | facts, va, vb, vc, final, alerts -> `memory.jsonl`, `facts.json` |
| `loop-measure` (once) | none | `{0, 0}` | every `remember` + `memory-snapshot/rows.jsonl` -> `measure.json` (the increment metrics: declared sites agreed, cost per candidate, dispute rates) |
| `loop-propose` (once) | none | `{0, 0}` | measure, snapshot, journal -> `proposals.jsonl`, `memory_proposals.jsonl`, `signals.json` |
| `loop-improve` (once) | none | `{0, 0}`, `serialize: engine` | proposals; Workspace = this repository at the commit under test -> `gate.json` (the `RoundOutcome`), `journal.json`, `rule_policy.json` (only when accepted) |

Before the Run starts, `memory-snapshot` is seeded into the run directory like reused facts. It holds the store
rows after the guard, since a sandboxed task cannot read the host store. A `{usd: 0, calls: 0}` budget makes
`budget.py` refuse any call, so a model-free task that tries one fails loudly rather than spending. Attribution
per task is the existing `ousast plane status` table.

**The gate's verdict** lands in `~/ousast-results/plane/<run>/loop-improve/gate.json` and is ingested as
`proposal_outcome` rows. An accepted `rule_policy.json` is adopted into the repository only by a maintainer
commit, as any ledger change is today (README "Rule-level loop").

### 7. Documentation and specs (Requirement 4)

- **README.** Replace "Configuring the HarnessX agentic plane" (README.md:293-329) with "The agentic plane (ax)":
  what runs there (repo-facts, verify, agree, memory), `ousast plane run|status|remember`, a pointer to
  `ops/ax/README.md`, and one tagged line saying HarnessX was retired. Rename "The HarnessX self-improving cycle"
  (:330) to "The self-improving cycle". Its calibration ledger and `ousast improve` content is not HarnessX and
  stays. The MetaAgent paragraph (:393-400) is replaced by the memory proposer (`--memory`, provenance, guard).
  Drop the `panel_model`/`decider_model` lines at :227-228.
- **`docs/examples.md` section 6** becomes "Running the agentic plane", with the plane doctor, run and status
  commands.
- **`docs/threat-model.md:17-20, 32-34`**: egress is the per-task EgressPolicy (receiver, Git hosts, Model
  `egress-hosts`, passthrough only). Credentials travel only in the start request. Spend is the per-task
  `usd`/`calls` budget in the Run.
- **Retirement notes.** A dated note ("Retired 2026-..: HarnessX was removed by `harnessx-removal`; the agentic
  plane is ax (`ai-service-plane`), proposals come from the plane memory. History below is unchanged.") goes at
  the top of the requirements (and design, where present) of `harnessx-self-improving-rulesets`,
  `learning-harness`, `three-stage-scan` and `openrouter-sast-harness`, and in `.kiro/steering/overview.md` near
  :175. The other specs that mention HarnessX in passing keep their history untouched.
- `RELEASE_NOTES.md` gets one entry listing the retired keys. Kiro tooling stays out of user docs.

## Data Models

- `memory.jsonl` (remember output) and `repos/<repo>/<pin>.jsonl`: the rows above, one JSON object per line,
  sorted keys, stable `id` = sha256(kind, run, task, candidate|path|rule_id+line).
- `index.jsonl`: `{"run", "task", "sha256", "rows", "ingested"}`.
- `memory_proposals.jsonl`: `{"proposal_id", "edit_key", "rule_id", "rule": "M1|M2", "evidence": [...],
  "counts": {...}, "thresholds": {...}, "excluded": {...}, "store_digest"}`.
- Journal edit entry: the existing fields (`evolve.py:381-384`) plus `"evidence"` only for memory edits.
- Equality record: `env.json` `{"commit", "freeze_sha256", "harnessx_importable": false, "tree_sitter": true,
  "inputs": {path: bytes}, "exclusions": [...]}`.

## Error Handling

- `RetiredConfigError`: exit 2 with the key and its replacement, before any stage runs.
- A `[harnessx]` section produces exactly one warning, and loading continues.
- `memory.ingest` on a run without `remember` outputs is a no-op that says so. A malformed row fails the ingest
  and names the file and line, and nothing partial is written: rows are staged in a temporary file and renamed.
- A low-disk refusal names the store and the free space. The plane run's result is unaffected, and ingest can be
  repeated with `ousast plane remember`.
- `seed` never overwrites an existing task directory or a non-pending state. A facts file whose sha256 no longer
  matches is dropped from the store with a warning, and that task recomputes.
- `propose_from_memory` with an empty store after the guard returns no proposals, and `run_round` reports
  `no_proposals` as today.
- The equality script exits non-zero on the first failed instrument check. It also exits non-zero on any
  difference outside the exclusion list and prints the first differing path and key.

## Testing Strategy

- `tests/test_config.py`: the one-warning section and the retired keys (above).
- `tests/test_no_harnessx_references.py`: the tagged-only search of Requirement 2.4.
- `tests/test_plane_memory.py`: ingest is idempotent and content-addresses identical facts. `seed` marks a facts
  task done and serves its file, and does not for a changed pin, candidate digest or image. Low-disk refusal
  (monkeypatched `disk_usage`).
- `tests/test_plane_remember.py`, `test_plane_alerts.py`, `test_plane_loop.py`: fixture run directories built from
  the recorded validation-46 shapes. `remember` rows match `agree`'s per-candidate rows. `alerts` attributes
  functions. `measure` reproduces the increment's recorded metrics on the recorded artifacts. `propose` and
  `improve` work end to end on a fixture manifest.
- `tests/test_improve_memory.py`:
  - M1 and M2 fire at their thresholds and not below.
  - A disputed candidate counts neither way.
  - The guard removes rows by population, manifest case and holdout pair, so a proposal that exists only because
    of a holdout row disappears.
  - Provenance ids are stable across runs.
  - A reverted memory edit is not re-proposed on the same evidence, and is re-proposed on new evidence.
  - `run_round` without proposals writes a journal byte-identical to today's.
- `tests/test_plane_reconciler.py`: `mark_done` under the lock. The existing under-500-lines test stays.
- The existing gate and pair tests, `test_benchmark_output_is_byte_identical_to_golden_baseline`
  (`test_gate.py:104`) and the equality script (section 3) are the regression net.

## Requirement Traceability

| Requirement | Design section | Verified by |
| --- | --- | --- |
| 1.1 fate of every capability | 1 (table) | this document; commit 5 |
| 1.2 moved capabilities reachable, Model per task, fixture test | 1 (existing `verify`/`agree`), 4-6 (new tasks are Model-free) | `test_plane_verify.py`, `test_plane_tiebreak.py`, new plane task tests |
| 1.3 retired keys fail naming the replacement | 1 (`RetiredConfigError`) | `test_config.py` |
| 2.1 modules and guards gone | 2 Source | commit 6; audit test |
| 2.2 extra, override, lock gone; installs succeed | 2 Packaging | fresh-venv `pip install .` / `'.[semantic]'` |
| 2.3 tests deleted or renamed; audit regenerated | 2 Tests, Module audit | `test_module_audit.py` |
| 2.4 search returns only retirement notes | 2 Search | `test_no_harnessx_references.py` |
| 3.1 baseline without the extra | 3 | commit 1 record |
| 3.2 byte-identical after, exclusions written | 3 Comparison | commit 7 record |
| 3.3 `[harnessx]` loads with one warning | 1 | `test_config.py` |
| 4.1-4.3 docs, retirement notes, Kiro out of user docs | 7 | commit 8 review |
| 5.1-5.2 order, green steps, no deletion before replacement | Commit sequence | per-commit gates |
| 6.1 store keyed by repo + pin, fact reuse | 4 | `test_plane_memory.py`, `test_plane_remember.py` |
| 6.2 deterministic proposals through validator and gate | 5 | `test_improve_memory.py` |
| 6.3 loop as a plane Run with per-task Models and budgets | 6 | `test_plane_loop.py`; `ousast plane status` attribution |
| 6.4 provenance and train-on-test guard | 5 | `test_improve_memory.py` |

## Commit sequence (Requirement 5), mapped to future tasks

Each commit is gated on the full suite's own exit code, `ruff` and `mypy`.

1. **Baseline** (3.1): the equality script and `benchmarks/measurements/<date>-harnessx-removal-baseline/`,
   recorded with the extra uninstalled.
2. **Memory store and `remember`** (6.1): `plane/memory.py`, `tasks/remember.py`, `reconciler.mark_done`, seed and
   ingest wiring in `cli._plane`, generator annotations, fixture tests.
3. **Memory proposer** (6.2, 6.4): `improve/memory.py`, `run_round(proposals=...)`, `ousast improve --memory`,
   sidecar and journal evidence, guard tests.
4. **Loop Run** (6.3): `alerts`, `measure`, `propose` and `improve` tasks, `--loop` generation, fixed-pin
   Workspaces, fixture tests.
5. **Retire the scan paths** (1, 3.3): the `cli.py`, `fusion.py`, `verify_judge.py` and `stage_processors.py`
   changes, `RetiredConfigError`, the one warning, and the test renames that follow. At this point nothing imports
   `harness_ext`/`hunter_harness`. Their replacements (plane tasks, and the memory proposer from 2-4) have landed.
6. **Delete code and packaging** (2): the two modules, the extra, the mypy override, `uv.lock`, the deleted tests,
   the fixture rename, audit rows and the manifest regeneration, and the reference search test.
7. **Equality proof** (3.2): rerun the script, commit the comparison record next to the baseline, and link it in
   the commit message.
8. **Docs and specs** (4): the README, `docs/examples.md`, `docs/threat-model.md`, retirement notes, steering and
   release notes.

## Risks

- **Existing users of the LLM scan paths.** There is no `--llm` flag. Users who set `[models] verifier` or
  `[fusion] panel_model` get a hard error, which is intended (1.3). Users who installed the extra and set
  `[models] hunter` lose the second (HarnessX) hunter without an error. Only the release note covers that,
  because the key is still valid. No measurement suggests either path found anything the remaining paths miss.
  The absence of a measurement is itself the risk.
- **Plane precision is unsolved.** `plane-increment-2.json` agrees 28 candidates, of which 16 are declared
  sites. The other 12 are unadjudicated and several may be false. M1 treats a `rejected` final as negative
  evidence, while plane recall is 16/20, so "rejected" is not "safe". The thresholds (2 or more repositories, zero
  agreed hits) and the unchanged recall/FP gate are the guard. Precision work (judge design) remains out of scope.
- **Evidence is thin.** Today's store would hold 15 cases from one validation population, which is exactly the
  population the guard excludes for its own qualification. Expect `no_proposals` until a second population has
  run through the loop.
- **Disk.** The home volume is 98% full (2.4 GB free). One validation-46-sized Run adds about 3 MB of facts
  (content-addressed; about 0.1 MB when pins are unchanged) plus about 0.5 MB of rows. Ingest refuses below 1 GiB
  free. The store has no eviction in this spec.
- **The baseline measures the environment as well as the code.** `.venv` has `harnessx` installed today. A
  baseline taken without re-syncing would include it. The script's `find_spec` and freeze checks exist for that.
- **Seeding writes reconciler state from outside the reconciler.** It is confined to `mark_done` under the run
  lock. The reconciler's line budget (465 of 500) leaves no room for fact reuse inside the reconciler.
