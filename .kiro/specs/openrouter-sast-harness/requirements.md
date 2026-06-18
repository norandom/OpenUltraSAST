# Requirements: OpenRouter SAST Harness

## Overview

OpenUltraSAST shall be an independent OpenCode-driven security harness for finding, validating, reporting, and optionally fixing source-code vulnerabilities at scale. It shall use OpenRouter-selected chat models for reasoning, OpenRouter embeddings for semantic retrieval, Docker for isolated analysis, and an explicit evidence ladder to prevent AI suspicion from being reported as verified security impact.

The project shall use Clearwing only as an implementation oracle. It shall not import Clearwing internals, fork Clearwing, or expose Clearwing's broad MCP surface.

## Goals

1. Provide a repeatable SAST harness that can scan local repositories and produce ranked, evidence-scored findings.
2. Make false-positive elimination a primary product goal by separating suspicion, corroboration, verification, reproduction, and patch validation.
3. Combine static analysis, semantic retrieval, LLM hunters, adversarial verification, and patch validation into one opencode-native workflow.
4. Keep model routing explicit through OpenRouter, with per-role model configuration and no silent substitution.
5. Preserve Docker isolation as a first-class security boundary for code execution, harness compilation, fuzzing, and patch validation.
6. Integrate Trail of Bits skills as scoped security expertise selected by language, framework, vulnerability class, mapping need, or verification need.
7. Emit machine-readable artifacts suitable for CI, triage, and later training or harness evolution.

## Completeness Model

Implementation progress shall be reported against functional harness capability, not raw checklist percentage. A task may be complete as scaffold while the product capability remains incomplete.

Completion levels:

1. `scaffold`: schemas, CLI shape, local artifacts, tests, or isolated primitives exist.
2. `usable`: the feature runs end-to-end for a narrow local fixture without manual wiring.
3. `integrated`: the feature participates in the scan harness with traces, evidence, reports, and degradation handling.
4. `production`: the feature is robust enough for real repositories, CI budgets, failure recovery, and analyst audit.

Progress reports shall identify both checklist progress and functional completeness. The project shall not describe OpenUltraSAST as a working harness until the `usable_harness_mvp` gate is satisfied.

Functional gates:

1. `scaffold_quick_scan`: quick scan can enumerate files, rank targets, emit basic static findings, and write JSON/Markdown artifacts. This gate does not constitute a security harness.
2. `usable_harness_mvp`: harness runtime, event tracing, static mapping ingestion, evidence ladder enforcement, independent verification, and JSON/Markdown/SARIF reporting work together on fixture repositories.
3. `standard_security_harness`: standard mode runs ranked hunters with retrieval packages, selected security skills, independent verification, false-positive learning, and auditable traces.
4. `sandboxed_dynamic_harness`: Docker sandbox, scoped dynamic probes, sanitizer/build artifacts, and evidence transitions work without hidden network or host mutation.
5. `fix_validation_harness`: patch proposals, adversarial fix audit, differential/static delta checks, and sandbox validation are integrated and cannot mark patches validated without passing evidence.
6. `opencode_product`: MCP tools, opencode commands/skills, fusion deepening, CI-ready reports, cost controls, and hardening are complete enough for routine opencode-driven use.

The current implementation state shall be documented as `usable_harness_mvp` until later gates are explicitly verified.

## Non-Goals

1. Do not make network pentesting the core workflow.
2. Do not reimplement all of Clearwing.
3. Do not report LLM-only claims as verified vulnerabilities.
4. Do not require a local embedding model.
5. Do not depend on a single OpenRouter model.
6. Do not mutate user repositories by default.

## Functional Requirements

### Repository Intake

1. The system shall accept a local repository path as the primary scan target.
2. The system should later support git URLs, but initial implementation may require local checkout.
3. The system shall snapshot basic repository metadata: root path, commit hash when available, language mix, file count, and ignored paths.
4. The system shall respect common ignore files such as `.gitignore`, `.ignore`, and explicit harness config excludes.

### Preprocessing

1. The system shall enumerate source files and assign initial language, LOC, and path metadata.
2. The system shall tag files using lightweight static heuristics, including memory-unsafe code, parser surfaces, crypto surfaces, authentication boundaries, syscall or process boundaries, serialization boundaries, and fuzzable entry points.
3. The system shall build a dependency or call graph where practical.
4. The system shall ingest optional static analyzer output such as Semgrep SARIF or CodeQL SARIF.
5. The system shall preserve preprocessing artifacts for later ranking, retrieval, and audit.

### Static Analysis And Mapping Discipline

1. The system shall treat Semgrep, CodeQL, differential review, and sharp-edge/API review as mapping disciplines, not just optional external scanners.
2. The system shall ingest Semgrep and CodeQL output as SARIF and normalize it into static hints, evidence candidates, and variant-search seeds.
3. The system shall support function-level entry-point and reachability analysis to identify attacker-controlled inputs, externally callable functions, public routes, CLI/process boundaries, parser entry points, smart-contract state-changing entry points, callbacks, and privileged/admin-only surfaces.
4. The system shall classify entry points by access level and trust boundary, including public/unrestricted, authenticated, role-restricted, contract-only/callback, local-only, and unknown/review-required.
5. The system shall preserve condition evidence for entry points, including feature flags, rollout toggles, pause guards, experiment gates, and runtime guard expressions that affect whether a threat actor can reach the code.
6. The system shall use function-level reachability modeling to prioritize candidate bugs inside reachable entry-point functions and to demote pattern-only findings that lack a plausible attacker-controlled path.
6. The system shall support differential analysis between a base and head revision to identify changed attack surfaces, newly reachable code, and regression-prone fixes.
7. The system shall support sharp-edge mapping for APIs, configuration, defaults, cryptographic interfaces, and dangerous framework patterns that create predictable misuse.
8. The system shall preserve analyzer provenance so each finding can cite which static tool, rule, diff, entry-point analysis, or skill-derived checklist contributed evidence.

### OpenRouter Embeddings And Retrieval

1. The system shall use OpenRouter embedding endpoints for semantic indexing.
2. The system shall chunk source code, docs, static findings, prior mechanisms, and Trail of Bits skill descriptors into separate collections or namespaces.
3. The system shall store vectors in a local persistent vector database by default.
4. The system shall support reusing an existing index when the repository snapshot has not changed.
5. The system shall retrieve bounded context packages for rankers, hunters, verifiers, and patchers.
6. The system shall evaluate vector-store candidates against ranking quality, metadata filtering, incremental indexing, local persistence, cost, and reproducibility before selecting a default.
7. The vector store shall support precise metadata filters for path, language, symbol, vulnerability class, evidence level, scan ID, and repository snapshot.

### Ranking

1. The system shall score candidate files on at least three axes: surface, influence, and reachability.
2. The system shall compute a composite priority using an explicit formula, initially `surface * 0.5 + influence * 0.2 + reachability * 0.3`.
3. The system shall keep low-surface high-influence files eligible for analysis.
4. The system shall combine static heuristics, dependency graph data, entry-point reachability, embeddings, and OpenRouter LLM scoring.
5. The system shall record score rationales and model identity.
6. The system shall measure ranking quality with fixture repositories and prior scan outcomes, including false-positive rate by tier and missed-true-positive rate where ground truth exists.
7. The system shall feed verifier outcomes back into ranking calibration so repeated false-positive patterns lose priority over time.

### False-Positive Elimination Loop

1. The system shall track every rejected, contradicted, duplicate, unsupported, and unverified finding as false-positive learning data.
2. The system shall record why a finding failed: unreachable path, missing attacker control, sanitizer disproved, static rule mismatch, incorrect model assumption, duplicate finding, or insufficient impact.
3. The system shall use HarnessX-style adjustment loops to update prompts, retrieval filters, ranking calibration, skill routing, verifier tie-breakers, and static mapping seeds from false-positive outcomes.
4. The system shall keep false-positive learnings auditable and reversible; learned suppressions shall cite evidence and scope.
5. The system shall prefer evidence-gated demotion over deletion so analysts can inspect why a suspected issue was suppressed or downgraded.

### Harness Execution

1. The system shall model the scan as a HarnessX-style harness composed of processors, tools, memory, sandbox, trace, and model roles.
2. The system shall expose stage hooks for task start, stage start, before model, after model, before tool, after tool, stage end, and task end.
3. The system shall contract-check processor inputs and outputs in strict mode for CI and warn mode for local exploration.
4. The system shall serialize harness configuration, processor versions, model roles, and prompt hashes into scan artifacts.

### Hunter Pool

1. The system shall fan out analysis across ranked targets using budgeted tiers.
2. The system shall support at least three analysis depths: quick, standard, and deep.
3. Quick mode shall rely on static analysis, ranking, and bounded LLM review without code execution.
4. Standard mode shall use sandboxed tool-calling hunters and adversarial verification.
5. Deep mode shall add harness generation, sanitizer builds, fuzzing, dynamic reproduction, crash reproduction, and patch validation where applicable.
6. The system shall record every hunter trajectory as structured JSONL.

### Evidence Ladder

1. Every finding shall carry exactly one current evidence level.
2. Evidence levels shall be ordered as: `suspicion`, `static_corroboration`, `crash_reproduced`, `root_cause_explained`, `exploit_demonstrated`, `patch_validated`.
3. Findings below `static_corroboration` shall not be reported as verified.
4. Exploit or PoC generation shall require at least `crash_reproduced` or equivalent trigger evidence.
5. Auto-patching shall require at least `root_cause_explained` and shall only advance to `patch_validated` after tests or reproducer validation pass.

### Verification And Fusion

1. The system shall verify findings using independent context that excludes hunter chain-of-thought and raw hunter reasoning.
2. The verifier shall steel-man both the vulnerability case and the false-positive case.
3. The verifier shall output explicit tie-breaker evidence requirements.
4. The system shall support OpenUltraCode-style fusion for task-required deepening, high-impact findings, uncertain findings, risky fixes, or unresolved disagreement, using two panels and an explicit decider.
5. Fusion output shall disclose model IDs, panel roles, degradations, warnings, votes, and final decision source.
6. Every adversarial finding shall receive a disposition: accepted, rejected, mitigated, deferred, or blocked.
7. Fusion shall be mandatory whenever the task requires deeper reasoning than the normal ranker, hunter, verifier, and static mapping loop can provide.
8. Fusion shall not be forced for routine low-risk issues unless the task explicitly asks for deeper analysis or the evidence remains unresolved.

### Docker Sandbox

1. The system shall run untrusted build, test, fuzz, and PoC commands inside Docker by default.
2. Analysis containers shall have network disabled by default.
3. Source mounts shall be read-only except in explicit patch workspaces.
4. Containers shall use a writable scratch volume or tmpfs.
5. Containers shall enforce CPU, memory, pids, timeout, and capability limits.
6. The system shall support sanitizer variants, initially ASan and UBSan for C/C++ targets.
7. The system should support gVisor or another hardened runtime when available.

### Dynamic Analysis

1. The system shall support optional dynamic analysis when runtime evidence is needed to verify, reproduce, or de-risk a finding.
2. Dynamic analysis may include service startup, local socket checks, netcat-style probes, protocol smoke tests, PoC execution, or Clearwing-style network validation patterns.
3. Dynamic network access shall be disabled by default and enabled only through explicit scan configuration or task-required evidence collection.
4. Dynamic probes shall run in sandboxed environments with declared network scope, timeouts, command logs, and captured artifacts.
5. Dynamic analysis shall contribute evidence but shall not turn OpenUltraSAST into a general network pentest agent.

### Patch Oracle

1. The system shall optionally generate minimal defensive patches for verified findings.
2. The patch workflow shall follow OpenUltraCode discipline: intake, bounded plan, implementation, adversarial review, reconciliation, and fresh verification.
3. The patch oracle shall target the smallest safe change.
4. The patch oracle shall not rewrite unrelated code or change public signatures unless required and approved.
5. Patch validation shall rerun the reproducer, affected tests, or relevant build checks in a writable sandbox.
6. Patch artifacts shall be emitted as diffs, not silently applied to the user's repository by default.
7. The system shall audit proposed fixes for regression risk using differential analysis and relevant Trail of Bits skills before marking them ready.

### Reporting

1. The system shall emit JSON, SARIF, Markdown, and a manifest per scan.
2. Reports shall sort findings by severity, evidence level, reachability, and confidence.
3. Reports shall include model IDs, static evidence, verifier results, reproduction evidence, patch status, and artifact paths.
4. Reports shall distinguish suspected, verified, exploited, and patch-validated findings.

### MCP And OpenCode Integration

1. The project shall expose a narrow MCP server for OpenCode integration.
2. MCP tools shall focus on project-level operations: scan, status, findings, evidence, artifacts, patch proposal, and report export.
3. The MCP server shall not expose arbitrary internal tools as public MCP methods.
4. OpenCode commands shall invoke the harness with explicit model role configuration and visible assumptions.

## Non-Functional Requirements

1. The system shall be deterministic where possible: fixed config, artifact manifests, prompt hashes, and model identifiers.
2. The system shall degrade visibly when optional tools, Docker, embeddings, or specific models are unavailable.
3. The system shall avoid hidden network access from analysis containers; any dynamic network access shall be explicit, scoped, logged, and artifact-backed.
4. The system shall support CI usage with bounded runtime and cost budgets.
5. The system shall keep findings auditable from report back to source, trace, model call, verifier decision, and artifact.

## Acceptance Criteria

1. `scaffold_quick_scan`: A user can run a local repository scan in quick mode and receive ranked static findings with JSON and Markdown reports. This may use heuristics and static patterns only.
2. `usable_harness_mvp`: A user can run quick or standard fixture scans through the harness runtime and inspect event traces, normalized static mapping evidence, verifier decisions, and report artifacts.
3. `standard_security_harness`: A user can run standard mode and receive adversarially verified findings with explicit evidence levels, selected retrieval context, skill routing, and false-positive learning records.
4. `sandboxed_dynamic_harness`: A user can run deep mode on a small C/C++ parser target and receive sandboxed build/fuzz artifacts when the target is fuzzable.
5. `fix_validation_harness`: A patch cannot be marked validated unless a sandboxed validation command passes and the fix audit has no accepted blocking findings.
6. `opencode_product`: A user can drive scans, triage, evidence inspection, report export, fusion, and patch proposal through narrow MCP/OpenCode interfaces without exposing arbitrary shell execution.
7. A finding cannot be marked verified unless it reaches at least `static_corroboration` through enforced evidence transitions.
8. A scan manifest records repository snapshot, harness config, OpenRouter model IDs, embedding model, prompt hashes, processor versions, evidence transitions, and artifact paths.
