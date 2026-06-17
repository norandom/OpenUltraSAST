# Assessment: OpenUltraSAST Kickoff

## Executive Assessment

OpenUltraSAST should be built as a harness runtime specialized for security analysis, not as a direct Clearwing clone. The strongest design is to treat Clearwing's sourcehunt pipeline as a proven reference flow, HarnessX as the runtime abstraction, OpenUltraCode as the verification and fusion discipline, OpenRouter as the provider plane, and Trail of Bits skills as targeted domain expertise.

The minimum viable system is not deep fuzzing. The minimum viable system is an auditable quick scan that can rank files, generate structured findings, eliminate obvious false positives, enforce evidence levels, and emit reports. Deep Docker-backed validation should come after the evidence model, trace model, false-positive loop, and report model are stable.

## Why This Project Is Viable

Clearwing demonstrates that a SAST + LLM hybrid can be useful when it avoids treating model output as truth. Its best transferable ideas are:

- Static preprocessing before LLM analysis.
- File ranking by surface, influence, and reachability.
- Tiered hunter budgets instead of equal attention for every file.
- Independent adversarial verification.
- Evidence ladder that separates suspicion from crash reproduction and patch validation.
- Docker isolation for builds, fuzzing, PoCs, and patches.
- SARIF, Markdown, and JSON artifacts.

The most important product differentiator should be false-positive elimination. A scanner that finds many plausible issues but cannot separate evidence-backed findings from model hallucinations will not be trusted. Ranking, retrieval, verification, and HarnessX-style adjustment should all be optimized around reducing false positives without hiding the audit trail.

HarnessX provides the missing generalization: the scanner should be a composed harness with typed processors and traces, not a fixed pipeline that becomes hard to evolve. This matters because SAST workflows vary heavily by language, build system, vulnerability class, and available evidence.

OpenUltraCode provides the missing discipline: high-risk findings and proposed fixes need bounded plans, adversarial review, reconciliation, explicit model disclosure, and verification gates. This is directly applicable to false-positive control and to avoiding fixes that look plausible but introduce regressions.

Trail of Bits skills provide mapping discipline as much as they provide tools. CodeQL thinking maps interprocedural flows, Semgrep maps repeatable patterns and variants, differential review maps changed attack surface, and sharp-edge review maps APIs and defaults that make misuse likely. OpenUltraSAST should convert those disciplines into structured tasks and evidence, not only prompt inspiration.

## Recommended Initial Product Shape

The first release should support this workflow:

```text
ousast scan /path/to/repo --mode quick
```

It should produce:

```text
.openultrasast/runs/<scan-id>/manifest.json
.openultrasast/runs/<scan-id>/preprocess/file_targets.json
.openultrasast/runs/<scan-id>/rank/ranking.json
.openultrasast/runs/<scan-id>/findings.json
.openultrasast/runs/<scan-id>/report.md
```

The key product promise should be:

```text
OpenUltraSAST tells you where security review should start, what it suspects, what evidence exists, what evidence is missing, and which findings have survived independent verification.
```

## Core Architecture Recommendation

Use a Python implementation initially. Clearwing and HarnessX are both Python, Docker and SARIF libraries are mature, and Trail of Bits tooling integration will be simpler. OpenCode integration can happen through MCP and command files rather than requiring the core scanner to be TypeScript.

Recommended modules:

```text
openultrasast/config.py
openultrasast/cli.py
openultrasast/models.py
openultrasast/provider/openrouter.py
openultrasast/preprocess/
openultrasast/index/
openultrasast/rank/
openultrasast/harness/
openultrasast/hunters/
openultrasast/verify/
openultrasast/fusion/
openultrasast/sandbox/
openultrasast/reports/
openultrasast/mcp/
```

## Build vs. Reuse Decisions

| Area | Recommendation | Reason |
| --- | --- | --- |
| Harness runtime | Build minimal HarnessX-inspired core first | Direct HarnessX dependency may add unstable surface before needs are proven |
| OpenRouter chat | Build direct OpenAI-compatible client | Need explicit model IDs, cost metadata, and role controls |
| OpenRouter embeddings | Build direct client | Embeddings are central and should not be hidden behind chat abstractions |
| Vector store | Choose one local default | Avoid abstracting before retrieval needs are proven |
| Docker sandbox | Build focused wrapper | Security defaults are project-specific |
| Trail of Bits skills | Index descriptors, mapping tasks, and snippets | Avoid prompt bloat while preserving CodeQL/Semgrep/differential/sharp-edge discipline |
| Clearwing | Reference only | Independence is a project requirement |

## Configuration Shape

Model names and the vector store should be selected before implementation. The config shape should look like this:

```toml
[models]
ranker = "<openrouter-ranker-model>"
hunter = "<openrouter-hunter-model>"
verifier = "<openrouter-verifier-model>"
patcher = "<openrouter-patcher-model>"

[embeddings]
model = "<openrouter-embedding-model>"
store = "<selected-local-vector-store>"

[sandbox]
network = false
workspace_readonly = true
memory_mb = 2048
timeout_seconds = 300
pids_limit = 512

[dynamic]
enabled = false
network_scope = []

[evidence]
minimum_report_verified = "static_corroboration"
minimum_exploit = "crash_reproduced"
minimum_patch = "root_cause_explained"
```

The actual model names should be explicit before implementation. Avoid baking in placeholder defaults that silently pick a moving target.

## Vector Store Decision

Choosing the vector store is a core design decision, not plumbing. It directly affects ranking quality and false-positive rates because poor retrieval contaminates hunter and verifier context.

Selection criteria:

- Strong metadata filters for path, language, symbol, repository snapshot, evidence level, and vulnerability class.
- Incremental indexing for changed files.
- Local persistence that works inside opencode workflows.
- Deterministic export/import for reproducible scan artifacts.
- Acceptable query latency on medium repositories.
- Clean storage of OpenRouter embedding model metadata.
- Ability to combine vector retrieval with lexical or structural filters.

The first milestone should include a short bakeoff on fixtures before locking the default store.

## Most Important Engineering Constraint

Evidence transitions must be enforced in code. A model can recommend a transition, but the harness should decide whether the required artifact exists.

Examples:

- `suspicion -> static_corroboration`: requires static evidence, independent verifier agreement, or a matching analyzer finding.
- `static_corroboration -> crash_reproduced`: requires stored crash/reproducer artifact.
- `crash_reproduced -> root_cause_explained`: requires verifier explanation tying crash to source and impact.
- `root_cause_explained -> exploit_demonstrated`: requires exploit or trigger artifact beyond accidental crash.
- `root_cause_explained -> patch_validated`: requires patch diff and passing validation command.

False-positive elimination should be handled the same way: a model can recommend demotion or suppression, but the harness should require a scoped reason and counter-evidence.

False-positive reasons should include:

- No attacker-controlled path.
- Code is unreachable in supported configuration.
- Static rule matched a safe wrapper or sanitizer.
- Model confused similar symbols or files.
- Finding duplicates an existing issue.
- Impact is not security-relevant.
- Dynamic probe or test disproved triggerability.

## OpenRouter Design Needs

OpenRouter should be treated as two capabilities:

1. Chat/completion routing for reasoning roles.
2. Embedding endpoint for retrieval.

Every model call should record:

```text
role
model_id
provider metadata
prompt hash
response hash
cost estimate
temperature and parameters
fallback/degradation status
```

The project should reject ambiguous model routing for reproducible scans. If a role uses auto routing, the manifest must record the actual model selected by OpenRouter if available.

## Docker Design Needs

Docker is not just convenience. It is the trust boundary between arbitrary target repositories and the user's host.

Minimum safety profile:

- No hidden network in analysis containers.
- Read-only source mount.
- Writable scratch only.
- Timeouts around every command.
- Memory, CPU, and pids limits.
- Dropped capabilities by default.
- Separate writable copy for patch validation.

Deep mode should not be implemented until this boundary exists.

## Dynamic Analysis Strategy

Network verification is not out of scope. It is just not the core idea of the harness. OpenUltraSAST should remain SAST-first, but it should use dynamic analysis when runtime evidence is the right way to confirm a finding.

Useful dynamic checks include:

- Starting a target service in a sandbox.
- Using netcat-style TCP probes against declared local ports.
- Running local HTTP or protocol smoke tests.
- Executing a bounded PoC against a sandboxed service.
- Using Clearwing-style network checks as validation patterns when a source finding has a runtime network surface.

The rule is not "no network ever." The rule is "no hidden or open-ended network activity." Dynamic probes must be explicit, scoped, logged, time-bounded, and tied to evidence advancement.

## Trail Of Bits Skill Strategy

The skills are best used as a routing corpus and checklist library. The harness should select compact snippets by target profile.

Good examples:

- C parser with pointer arithmetic: `c-review`, `address-sanitizer`, `libfuzzer`, `harness-writing`.
- Python parser: `atheris`, `property-based-testing`.
- Crypto code: `constant-time-analysis`, `wycheproof`, `vector-forge`, `zeroize-audit`.
- SARIF flow: `sarif-parsing`, `semgrep`, `codeql`.
- Changed code or proposed fixes: `differential-review`, `graph-evolution`.
- Dangerous APIs, defaults, or configuration: `sharp-edges`, `insecure-defaults`.
- Smart contracts: use chain-specific scanners only when the language and framework match.

Bad pattern:

```text
Paste all security skill instructions into every hunter prompt.
```

That would increase cost, reduce precision, and mix irrelevant assumptions into reviews.

## Fix Authoring And Audit Strategy

UltraCode should define the patch lifecycle. A patch is not complete when a model emits a diff. A patch is complete only after a bounded plan, minimal implementation, adversarial review, reconciliation, and fresh verification.

Fix stages:

```text
verified finding -> bounded fix plan -> minimal patch -> sandbox validation -> adversarial fix audit -> reconciliation -> fresh verification -> patch artifact
```

Trail of Bits disciplines should audit the fix:

- Differential review checks whether the patch changed more attack surface than intended.
- Semgrep checks whether the vulnerable pattern or variants remain.
- CodeQL checks whether taint/dataflow still reaches the sink when applicable.
- Sharp-edge review checks whether the fix leaves a misleading or misuse-prone API behind.

Fusion should always be used to go deeper when the task requires it: risky fixes, contradictory evidence, difficult remediation tradeoffs, high-impact reports, unresolved verifier disagreement, or explicit high-assurance review. It should not be spent on routine low-risk patches when ordinary evidence is already sufficient.

## Kiro Spec Completion Criteria

The current spec is ready to drive implementation when these decisions are made:

1. Language/runtime: Python is recommended.
2. Vector store: choose Chroma, LanceDB, Qdrant local, or SQLite vector extension.
3. Initial OpenRouter chat models by role.
4. Initial OpenRouter embedding model.
5. First fixture repository or synthetic vulnerable examples.
6. Whether to depend directly on HarnessX or implement a minimal compatible harness core.

## Recommended MVP Cut

MVP should include:

- Local path scan.
- File enumeration and static tags.
- OpenRouter ranker.
- Quick-mode hunter.
- Evidence ladder with enforced transitions.
- Independent verifier.
- JSON and Markdown reports.
- Manifest with model IDs and prompt hashes.

MVP should exclude:

- Deep fuzzing and broad dynamic analysis.
- Auto-patching.
- Fusion panels for routine MVP findings.
- Full MCP server.
- Multi-repository campaigns.
- Training bridge.

MVP should still model the future fix lifecycle in the data model, because evidence, reports, and patch artifacts need stable IDs before patching exists.

These exclusions keep the first milestone testable and prevent architecture from hardening around unverified assumptions.

## Implementation Order Rationale

Do not start with Docker or broad fusion. Those are expensive and only pay off after the data model and evidence model are correct. Start with the smallest useful loop:

```text
preprocess -> rank -> quick finding -> verify -> report
```

Once this loop works on fixtures, add embeddings. Once retrieval is stable, add sandboxed commands. Once sandboxing is stable, add deep fuzzing. Add fusion as soon as tasks require deeper adjudication than the normal verifier can provide.

## Immediate Next Questions

1. Which OpenRouter chat models should be used for ranker, hunter, verifier, and patcher roles?
2. Which OpenRouter embedding model should be the default?
3. Which vector store should be selected for the first implementation?
4. Should the project start with synthetic fixtures or scan a real open-source target first?
5. Should the first implementation include MCP, or should MCP wait until the CLI and artifacts stabilize?
