# Tasks: OpenRouter SAST Harness

## Phase 0: Project Skeleton

- [x] Create Python package skeleton with CLI entry point `ousast`.
- [x] Add config loading for `openultrasast.toml` and environment variables.
- [x] Add resolved config artifact writer.
- [x] Add scan run directory creation under `.openultrasast/runs/<scan-id>/`.
- [x] Add basic tests for config loading and run directory creation.

## Phase 1: Intake And Preprocess

- [x] Implement repository snapshot collection.
- [x] Implement source file enumeration with ignore handling.
- [x] Implement language detection from extension and shebang.
- [x] Implement LOC counting.
- [x] Implement initial tag heuristics for parser, memory unsafe, crypto, auth boundary, deserialization, syscall, network, filesystem, and fuzzable targets.
- [x] Emit `preprocess/file_targets.json`.
- [x] Add tests for tag heuristics on small fixture repositories.

## Phase 2: Ranking

- [x] Define `FileTarget` and ranking schemas.
- [x] Implement heuristic score floors and boosts.
- [x] Implement OpenRouter chat client for ranker role.
- [x] Implement chunked ranker calls with JSON response validation.
- [x] Compute composite priority.
- [x] Emit ranking rationales and model metadata.
- [x] Add tests for composite priority and malformed model response handling.

## Phase 3: Quick Scan Reports

- [x] Implement static finding schema.
- [x] Implement quick-mode hunter prompt and bounded file context.
- [x] Implement structured finding extraction.
- [x] Enforce initial evidence level `suspicion` unless static corroboration exists.
- [x] Emit `findings.json`.
- [x] Emit Markdown report.
- [x] Add smoke test against a fixture repository with one known insecure pattern.

## Phase 4: OpenRouter Embeddings

- [x] Implement OpenRouter embedding client.
- [x] Run a vector-store bakeoff for metadata filtering, local persistence, incremental indexing, export/import, and retrieval quality.
- [x] Select default local vector store based on bakeoff results.
- [x] Implement code chunking with path, symbol, and line metadata.
- [x] Implement namespaces for repo code, docs, static findings, mechanisms, skills, and traces.
- [x] Implement index reuse keyed by repository snapshot and embedding model.
- [x] Implement bounded retrieval package builder per role.
- [x] Add tests for chunk metadata and retrieval filters.

## Phase 4A: Ranking Quality And False-Positive Loop

- [x] Define false-positive reason taxonomy.
- [x] Add false-positive learning records for rejected, duplicate, unsupported, contradicted, and unverified findings.
- [x] Track ranking metrics by tier: verified findings, false positives, time to verification, and missed fixture vulnerabilities.
- [x] Feed verifier outcomes into ranking calibration.
- [x] Feed rejected findings into retrieval filter adjustment and prompt constraints.
- [x] Add tests proving scoped false-positive demotion does not globally suppress the vulnerability class.

## Phase 5: Harness Runtime

- [ ] Define harness event model.
- [ ] Define processor interface and contract checks.
- [ ] Implement strict and warn modes.
- [ ] Add trace writer for events and processor state changes.
- [ ] Serialize harness config, prompt hashes, processor versions, and model roles.
- [ ] Add tests for processor contract violations.

## Phase 5A: Static Mapping Disciplines

- [ ] Add SARIF ingestion for Semgrep and CodeQL outputs.
- [ ] Normalize SARIF rules, locations, severity, fingerprints, and provenance into static hints.
- [ ] Add Semgrep mapping task records for pattern, variant, and rule-authoring loops.
- [ ] Add CodeQL mapping task records for source, sink, sanitizer, and path explanations.
- [ ] Add differential mapping records for changed files, changed functions, and changed trust-boundary crossings.
- [ ] Add sharp-edge records for insecure defaults, dangerous APIs, confusing config, and misuse-prone interfaces.
- [ ] Add tests for mapping analyzer output to `FileTarget` hints and verifier evidence candidates.

## Phase 6: Verification

- [ ] Define evidence ladder state machine.
- [ ] Implement independent verifier prompt and schema.
- [ ] Ensure verifier context excludes hunter reasoning.
- [ ] Implement pro-case, counter-case, tie-breaker, and required-next-step fields.
- [ ] Enforce that verified report status requires at least `static_corroboration`.
- [ ] Add tests for invalid evidence transitions.

## Phase 7: Docker Sandbox

- [ ] Implement Docker availability probe.
- [ ] Implement no-network read-only workspace sandbox runner.
- [ ] Add explicit scoped-network sandbox mode for task-required dynamic probes.
- [ ] Add scratch volume or tmpfs support.
- [ ] Add CPU, memory, pids, timeout, and capability limits.
- [ ] Add command execution artifact capture.
- [ ] Add sanitizer build environment for C/C++ fixtures.
- [ ] Add tests that verify workspace remains read-only.

## Phase 7A: Dynamic Evidence

- [ ] Implement dynamic analysis configuration with `enabled = false` by default.
- [ ] Implement service startup command records with declared ports and timeouts.
- [ ] Implement netcat-style local socket probe tool inside sandbox scope.
- [ ] Implement HTTP or protocol smoke-test artifact capture.
- [ ] Tie dynamic artifacts to evidence transitions without allowing model-only upgrades.
- [ ] Add tests that reject undeclared network targets.

## Phase 8: Standard Mode Hunter Pool

- [ ] Implement tier assignment by priority.
- [ ] Implement budget allocation and per-target limits.
- [ ] Implement parallel hunter scheduling.
- [ ] Persist hunter trajectories as JSONL.
- [ ] Integrate retrieval packages and selected skill snippets.
- [ ] Integrate verifier after hunter output.
- [ ] Add fixture scan demonstrating at least one verified static-corroborated finding.

## Phase 9: SARIF And CI Output

- [ ] Implement SARIF report writer.
- [ ] Implement machine-readable manifest.
- [ ] Add severity, confidence, evidence level, model IDs, and artifact refs to reports.
- [ ] Add CI-friendly exit code policy.
- [ ] Add tests for SARIF schema validity.

## Phase 10: Deep Mode

- [ ] Implement fuzzable target detection beyond existing fuzz entry points.
- [ ] Implement fuzz harness generation prompt and schema.
- [ ] Compile generated harnesses in sandbox.
- [ ] Run libFuzzer or equivalent with sanitizer instrumentation.
- [ ] Capture crashes and minimization artifacts.
- [ ] Advance findings to `crash_reproduced` only with artifact evidence.
- [ ] Add a small C/C++ parser fixture with reproducible sanitizer crash.

## Phase 11: Patch Oracle

- [ ] Implement patch proposal schema.
- [ ] Implement OpenUltraCode-style fix lifecycle states: intake, plan, implement, adversarial_review, reconcile, verify, ready.
- [ ] Run patching in a writable sandbox copy or git worktree.
- [ ] Generate minimal diffs only.
- [ ] Rerun reproducer and affected checks.
- [ ] Run differential fix audit against the generated patch.
- [ ] Run Semgrep or CodeQL delta checks when corresponding evidence exists.
- [ ] Run sharp-edge fix audit when API, config, auth, crypto, or defaults are changed.
- [ ] Advance findings to `patch_validated` only after validation passes.
- [ ] Add tests that reject patches changing unrelated files.

## Phase 12: MCP And OpenCode Commands

- [x] Add project-local opencode skills for scan, triage, fix audit, and implementation steering.
- [ ] Implement narrow MCP server.
- [ ] Add `openultrasast.scan`, `status`, `findings`, `get_finding`, `evidence`, `artifacts`, `propose_patch`, and `export_report` tools.
- [ ] Add opencode command docs for quick, standard, deep, verify, and patch workflows.
- [ ] Ensure MCP tools never expose arbitrary shell execution.
- [ ] Add integration test for MCP tool listing and scan status.

## Phase 13: Fusion

- [ ] Implement fusion trigger policy.
- [ ] Trigger fusion whenever a task requires deeper reasoning, including difficult findings, contradictory evidence, high-impact decisions, and risky fixes.
- [ ] Implement panel A, panel B, and decider role config.
- [ ] Implement cross-critique and revised answer flow.
- [ ] Implement vote/rank output schema.
- [ ] Implement reconciliation dispositions.
- [ ] Record model IDs, degradations, warnings, and final decision source.
- [ ] Add tests for fusion output validation.

## Phase 14: Skill Index

- [ ] Build Trail of Bits skill descriptor inventory.
- [ ] Chunk selected skill operating guidance into retrieval namespace.
- [ ] Implement skill router by language, tags, vulnerability class, and stage.
- [ ] Add prompt budget caps for skill snippets.
- [ ] Add tests for routing C parser targets to memory/fuzzing skills and crypto targets to constant-time/vector skills.

## Phase 15: Hardening And Release Readiness

- [ ] Add cost budget enforcement.
- [ ] Add model call retry and backoff policies.
- [ ] Add redaction for secrets in traces and reports.
- [ ] Add docs for threat model and sandbox limits.
- [ ] Add end-to-end examples.
- [ ] Add lint, typecheck, test, and CI gates.
