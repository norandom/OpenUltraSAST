# Design: OpenRouter SAST Harness

## Architecture Summary

OpenUltraSAST is a harness-oriented SAST system, not a monolithic scanner. The core runtime composes processors, model roles, retrieval, tools, sandbox policy, traces, verification gates, and reporting into a reproducible scan harness.

The central quality objective is false-positive elimination. The harness should not merely find more possible bugs; it should repeatedly narrow suspicion into evidence-backed findings and learn from rejected claims.

Conceptual lineage:

- HarnessX: harness primitives, event hooks, processor contracts, trace-driven evolution.
- OpenUltraCode: bounded context, fix authoring discipline, adversarial review, reconciliation, fusion, verification evidence.
- Clearwing sourcehunt: preprocess, rank, tiered hunters, evidence ladder, adversarial verifier, patch oracle, variant loop, reports.
- Trail of Bits skills: domain-specific mapping, analysis, audit, and verification methods selected at the right stage, not embedded globally.

## High-Level Flow

```text
repo path
  -> intake snapshot
  -> preprocess and static tags
  -> graph and optional SARIF ingest
  -> embeddings and retrieval index
  -> file/function ranking
  -> tiered hunter pool
  -> independent verifier
  -> optional fusion adjudication
  -> optional reproducer/exploit triage
  -> optional patch oracle
  -> reports and artifacts
```

## Main Components

### CLI

Initial command surface:

```text
ousast scan <path> --mode quick|standard|deep --config openultrasast.toml
ousast status <scan-id>
ousast findings <scan-id>
ousast report <scan-id> --format markdown|json|sarif
ousast patch <finding-id> --propose
ousast index <path> --rebuild
```

The CLI should be thin. It loads config, creates a scan, starts the harness runtime, and writes artifacts.

### MCP Server

MCP should expose only stable project operations:

```text
openultrasast.scan
openultrasast.status
openultrasast.findings
openultrasast.get_finding
openultrasast.evidence
openultrasast.artifacts
openultrasast.propose_patch
openultrasast.export_report
```

The MCP server must not expose arbitrary shell, Docker, or internal hunter tools. Those stay inside controlled harness stages.

### Harness Runtime

The runtime owns the scan lifecycle and event pipeline. It should follow the HarnessX separation:

```text
ModelConfig: role -> OpenRouter model, parameters, budget, fallback policy
HarnessConfig: processors, tools, memory, sandbox, trace, control policy
ScanConfig: target path, mode, scope, excludes, report options
```

Required event hooks:

```text
task_start
stage_start
before_model
after_model
before_tool
after_tool
stage_end
task_end
```

Each processor declares the event types it handles and the state fields it reads or writes. Strict contract mode fails the scan when processors violate schemas. Warn mode records degraded state.

### OpenRouter Provider

The provider layer should implement two explicit clients:

```text
OpenRouterChatClient
OpenRouterEmbeddingClient
```

Chat roles:

```text
ranker
hunter
verifier
fusion_panel_a
fusion_panel_b
fusion_decider
patcher
reporter
```

Provider rules:

- No silent model substitution.
- Every model response records model ID, provider metadata when available, token counts, cost estimate, prompt hash, and response hash.
- Fallbacks must be configured per role and reported as degradations.
- Embedding model ID must be stored in the vector index metadata.

### Retrieval Store

The retrieval layer maintains separate namespaces:

```text
repo_code
repo_docs
static_findings
mechanisms
trailofbits_skills
scan_traces
false_positive_learnings
```

Chunk metadata should include:

```json
{
  "repo_id": "...",
  "snapshot": "...",
  "path": "src/parser.c",
  "symbol": "parse_frame",
  "language": "c",
  "chunk_type": "function",
  "start_line": 120,
  "end_line": 220,
  "tags": ["parser", "memory_unsafe"],
  "embedding_model": "openrouter/..."
}
```

Retrieval packages must be bounded by role. A verifier gets the finding, relevant source, static corroboration, and counter-evidence candidates. It does not get hunter chain-of-thought.

#### Vector Store Selection Criteria

The vector store is a core ranking and false-positive-control dependency. The first implementation should choose one default after evaluating:

```text
metadata filtering precision
incremental reindexing by repository snapshot
local persistence and portability
query latency on medium repositories
embedding model metadata support
hybrid lexical/vector retrieval support or integration path
deterministic export/import for scan reproducibility
operational simplicity for opencode users
```

Ranking depends on retrieval quality. Poor metadata filters will contaminate verifier context and increase false positives. The store must make it easy to retrieve "same symbol, same package, same vulnerability class, same evidence level" rather than semantically similar but irrelevant code.

### Preprocessor

The preprocessor produces `FileTarget` records. It should start simple and grow by plugins.

Initial fields:

```text
path
absolute_path
language
loc
tags
imports_by
transitive_callers
static_hints
sarif_hints
reachability_hints
has_fuzz_entry_point
defines_security_constants
```

Initial tags:

```text
memory_unsafe
parser
crypto
deserialization
syscall_entry
network_entry
filesystem_entry
fuzzable
privileged
```

### Static Analysis Mapping Layer

The static analysis layer turns tool output and skill discipline into a map for the harness. It is not only a source of finished findings.

Primary mapping sources:

```text
Semgrep: syntactic and lightweight semantic patterns, custom rule iteration, variant seeds
CodeQL: interprocedural dataflow, taint paths, structural vulnerability queries
Differential review: changed attack surfaces, regression-prone patches, new trust-boundary crossings
Sharp-edge review: unsafe APIs, insecure defaults, confusing configuration, misuse-prone interfaces
SARIF parsing: normalized evidence, rule metadata, locations, severity, fingerprints
```

Mapping outputs:

```text
static_hints on FileTarget
sarif_hints on FileTarget
taint_paths and source/sink pairs
variant_search_seeds
changed_surface records
sharp_edge records
evidence candidates for verifier
```

This layer should use Trail of Bits skills as task templates and checklists. For example, the CodeQL discipline supplies query/dataflow thinking, Semgrep supplies pattern and variant loops, differential review supplies changed-code blast-radius analysis, and sharp-edge review supplies API misuse mapping.

### Ranker

Ranking should combine heuristics, graph features, static hints, and model judgment.

Scores:

```text
surface: direct vulnerability likelihood, 1-5
influence: downstream blast radius, 1-5
reachability: attacker-controlled path likelihood, 1-5
priority: surface * 0.5 + influence * 0.2 + reachability * 0.3
```

The ranker should emit concise rationales:

```json
{
  "path": "src/parser.c",
  "surface": 5,
  "influence": 4,
  "reachability": 4,
  "priority": 4.5,
  "rationale": "C parser with external input, pointer arithmetic, and many callers",
  "model_id": "openrouter/...",
  "static_boosts": ["memory_unsafe", "parser", "sarif_high"]
}
```

Ranking is not only prioritization; it is a false-positive filter. The ranker should use verifier outcomes and dynamic evidence outcomes to calibrate which surfaces deserve attention. Repeated rejected patterns should be demoted unless new evidence appears.

Ranking metrics:

```text
verified findings per tier
false positives per tier
false-positive reason distribution
time-to-verification per tier
retrieval hit quality per role
missed known-vulnerable fixture targets
```

### False-Positive Elimination Loop

HarnessX-style adjustment is the mechanism that reduces false positives over time. Each scan produces traces, verifier decisions, rejected hypotheses, static analyzer deltas, retrieval packages, and evidence transitions. The harness should use those outputs to adjust future runs.

Adjustment targets:

```text
ranker score calibration
retrieval filters and namespace weights
hunter prompt constraints
skill routing rules
verifier tie-breaker templates
static mapping seeds
variant search patterns
finding deduplication rules
```

False-positive records:

```text
finding_id
rejection_reason
counter_evidence
scope of suppression or demotion
affected ranker/static/retrieval inputs
verifier model_id
human_override if present
```

False-positive learning must be scoped. A rejected claim in one framework, version, path, or call pattern should not globally suppress a vulnerability class.

### Hunter Pool

The hunter pool schedules targets by priority tier and depth.

Suggested tiers:

```text
A: priority >= 3.0, most budget
B: priority >= 2.0, moderate budget
C: priority < 2.0, opportunistic budget
```

Hunter inputs:

```text
target metadata
bounded source context
static hints
retrieved related code
selected Trail of Bits skill snippets
sandbox capabilities
budget
evidence requirements
```

Hunter outputs must be structured and evidence-oriented. They should not rely on hidden reasoning.

### Verifier

The verifier runs independently from the hunter. It receives only auditable facts:

```text
finding claim
source excerpts
static evidence
retrieved relevant context
reproducer or crash artifacts when available
negative evidence candidates
```

Verifier output:

```json
{
  "is_real": true,
  "severity": "high",
  "confidence": 0.82,
  "evidence_level": "static_corroboration",
  "pro_case": "...",
  "counter_case": "...",
  "tie_breaker": "Build a reproducer that drives len past buffer capacity",
  "required_next_step": "attempt_crash_reproduction"
}
```

### Fusion Adjudication

Fusion is the mandatory deepening mechanism whenever the task requires more reasoning depth than the normal ranker, hunter, verifier, and static mapping loop can provide.

Fusion triggers:

- Critical or high severity findings.
- Findings with verifier disagreement.
- Findings that gate patching or disclosure.
- Findings where static and semantic evidence conflict.
- Findings where a patch could introduce regression risk.
- Findings where multiple skills disagree on exploitability or remediation.
- User or task requests for deeper analysis, ultrathink-style review, or high-assurance adjudication.

Fusion protocol:

```text
panel A independently reviews bounded evidence
panel B independently reviews bounded evidence
panels critique each other
panels revise
panels vote/rank
decider issues final disposition
reconciler records accepted/rejected/blocked items
verifier records fresh evidence
```

Fusion should not be forced for routine low-severity findings when ordinary evidence is already sufficient. It must run when the task requires deeper analysis, when evidence does not converge, or when the decision gates a risky fix, exploit claim, disclosure, or high-impact report.

### Docker Sandbox

Sandbox defaults:

```text
network: none
workspace: read-only
scratch: writable tmpfs or volume
cap_drop: all
cap_add: SYS_PTRACE only when sanitizer/debugger needs it
memory: bounded
cpu: bounded
pids: bounded
runtime: docker default, optional gVisor
```

Sandbox use cases:

```text
static tool execution
build system probing
sanitizer builds
fuzz harness compilation
PoC execution
local service startup
netcat-style local socket probes
protocol smoke tests
patch validation in writable copy
```

Patch validation must use a writable copy, never the user's working tree by default.

### Dynamic Analysis Boundary

OpenUltraSAST is SAST-first, but dynamic analysis is in scope when it provides necessary evidence. The harness may run controlled runtime checks such as service startup, local HTTP/TCP probes, netcat-style reachability checks, PoC execution, and Clearwing-style network validation patterns.

Dynamic analysis rules:

```text
disabled by default
enabled only by explicit config or task-required evidence
scoped to declared hosts, ports, containers, and commands
logged as artifacts
bounded by timeout and resource limits
never treated as an open-ended network pentest loop
```

Dynamic evidence can support transitions such as `static_corroboration -> crash_reproduced`, `static_corroboration -> root_cause_explained`, or `root_cause_explained -> exploit_demonstrated` when the artifact actually demonstrates the claim.

### Trail Of Bits Skill Integration

Trail of Bits skills should be indexed and selected by routing metadata.

Examples:

```text
C/C++ memory target -> c-review, address-sanitizer, libfuzzer, harness-writing
Python parser target -> atheris, property-based-testing
Rust target -> cargo-fuzz, zeroize-audit when secrets are present
Crypto target -> constant-time-analysis, wycheproof, vector-forge
SARIF processing -> sarif-parsing
Semgrep mapping loop -> semgrep, semgrep-rule-creator, semgrep-rule-variant-creator
CodeQL mapping loop -> codeql, sarif-parsing
Changed-code review -> differential-review, graph-evolution
API footgun review -> sharp-edges, insecure-defaults
Smart contract target -> chain-specific scanner skill
```

Do not paste entire skills into every prompt. Store descriptors, retrieval chunks, and short operating checklists. Pull only the relevant snippets into a role-specific context package.

### UltraCode Fix Workflow

OpenUltraCode discipline should govern fix authoring and fix audit. The patch oracle is not a single prompt that writes code and declares success.

Fix workflow:

```text
intake verified finding and evidence
create bounded fix plan
generate minimal patch in writable sandbox or worktree
run affected checks and reproducer
run adversarial fix review
reconcile accepted/rejected/deferred review items
run fresh verification
emit patch diff and validation report
```

Fix audit inputs:

```text
original finding evidence
patch diff
differential analysis of changed code
Semgrep/CodeQL result delta when available
tests and reproducer output
sharp-edge regression checklist when API/config behavior changes
```

The workflow can propose a fix without applying it. It can only mark a fix as ready when the adversarial review is reconciled and fresh verification evidence exists.

### Data Model

Core entities:

```text
Scan
RepositorySnapshot
HarnessRun
ProcessorTrace
ModelCall
FileTarget
Finding
Evidence
Artifact
PatchProposal
VerificationDecision
FusionDecision
FalsePositiveLearning
RankingCalibration
```

Finding fields:

```text
id
scan_id
title
description
severity
confidence
status
evidence_level
path
start_line
end_line
symbol
vulnerability_class
attack_scenario
impact
remediation
discovered_by
verified_by
model_ids
artifact_refs
created_at
updated_at
```

Evidence levels:

```text
suspicion
static_corroboration
crash_reproduced
root_cause_explained
exploit_demonstrated
patch_validated
```

### Artifact Layout

Suggested scan directory:

```text
.openultrasast/runs/<scan-id>/
  manifest.json
  config.resolved.json
  repo_snapshot.json
  preprocess/
  index/
  rank/
  traces/
  model_calls/
  sandbox/
  findings.json
  report.md
  report.sarif
  patches/
```

## Implementation Strategy

Build the system in vertical slices:

1. Quick scan: intake, preprocess, rank, LLM/static finding generation, JSON/Markdown report.
2. Verification: independent verifier, evidence ladder enforcement, SARIF export.
3. Retrieval: OpenRouter embeddings, persistent index, bounded context packages.
4. Static mapping: Semgrep/CodeQL SARIF ingest, differential mapping, sharp-edge records.
5. False-positive loop: rejected finding taxonomy, ranking calibration, retrieval adjustment, and scoped suppressions.
6. Sandbox: Docker command runner, static tools, read-only source, scratch volume.
7. Dynamic evidence: controlled service startup, local probes, PoC execution, and artifact capture.
8. Deep mode: sanitizer builds, fuzz harness generation, crash artifacts.
9. Patch mode: UltraCode-style fix authoring, adversarial fix audit, validation loop.
10. MCP/opencode integration: narrow tools and commands.
11. Fusion: mandatory deepening for task-required hard findings, contradictory evidence, and risky fixes.

## Key Design Decisions

1. Evidence level is a state machine, not a label the model can freely assign.
2. Verifier context excludes hunter reasoning to reduce contamination.
3. OpenRouter model selection is role-scoped and auditable.
4. Embeddings and vector-store metadata filtering are part of the runtime, not an offline optional add-on.
5. Docker isolation is mandatory for execution-heavy modes.
6. Trail of Bits skills are retrieved as scoped expertise, not global prompt bloat.
7. MCP surface is narrow and project-oriented.
8. Fixes are authored and audited through an UltraCode-style workflow, not a one-shot patch prompt.
9. Fusion is the required deepening path when the task demands high-assurance reasoning, not a replacement for routine analysis.
10. Harness adjustment loops must reduce repeated false positives without hiding auditable evidence.

## Risks

1. OpenRouter embedding availability and model-specific response formats may vary.
2. Deep mode can become expensive without strict budget controls.
3. Docker sandbox escape risk requires conservative defaults and no-network execution.
4. LLM findings can inflate false positives unless the evidence ladder is enforced in code.
5. Multi-language callgraph quality will vary; ranking must tolerate partial graph data.
6. Skill retrieval can overfit prompts if descriptors are too broad.

## Open Questions

1. Which local vector store should be the default: Chroma, LanceDB, SQLite vector extension, or Qdrant local?
2. Should the first implementation be pure Python like Clearwing/HarnessX, or TypeScript to align with more opencode extension tooling?
3. Should OpenUltraSAST vendor a minimal HarnessX-inspired runtime or depend directly on HarnessX?
4. What minimum OpenRouter embedding model should be required for acceptable code retrieval?
5. Should patch proposals be applied only through git worktrees?
