# Requirements Document

## Introduction

OpenUltraSAST today answers one question well: which regexes fired. It does not answer the three questions a rugged DevOps CI workflow actually asks: what exists in this repository, where problems are most likely and how to aim tests, and whether a finding is worth fixing. This feature turns the scan into those three stages. Stage 1 is a static inventory of what exists. Stage 2 is a complexity map of likely problem areas plus test-tuning hints. Stage 3 is isolated regression that proves triggerability before CI treats a finding as blocking.

The work is a follow-up to the HarnessX ruleset-governance spec, not a replacement of it. CWE policy, project score, and rule-status shadowing stay in place. This spec owns the stage contract, the complexity map, the isolated regression verdict, the tool-using hunter on stages 2–3, and an evaluation corpus that is not a cheat sheet.

## Boundary Context

- **In scope**: a three-stage scan contract mapped onto existing scan depths; a static inventory that reports what exists without claiming verification; a complexity map of hotspots with test-tuning hints; isolated regression that produces a worth-fixing verdict; a tool-using hunter confined to stages 2–3; evaluation against split-sink and mutation corpora; visible degradation when the sandbox or a model is unavailable; evolutionary feedback from regression verdicts back into the complexity map.
- **Out of scope**: rewriting CWE-to-severity policy or the project-score formula; authoring or rewriting detection pattern text; full fuzzing campaigns; generating or applying patches; network pentesting; importing Clearwing.
- **Adjacent expectations**: stage 1 continues to run in the zero-dependency default install with no model and no sandbox. CWE policy, scoring, traces, and SARIF remain owned by the existing governance spec. The operator supplies an isolated-sandbox runtime (Docker CLI) for stage 3 and an LLM credential for the tool-using hunter; neither is a packaged library dependency of the core install.

## Requirements

### Requirement 1: Three-Stage Scan Contract

**Objective:** As a DevOps engineer, I want a scan to run as three ordered stages that map onto the existing scan depths, so that CI can choose inventory-only, map-and-tune, or prove-worth-fixing without a new command family.

#### Acceptance Criteria

1. When a scan runs at depth `quick`, the Scan Orchestrator shall execute stage 1 only and shall not start a model call or execute target-derived code.
2. When a scan runs at depth `standard`, the Scan Orchestrator shall execute stage 1 then stage 2.
3. When a scan runs at depth `deep`, the Scan Orchestrator shall execute stage 1 then stage 2 then stage 3.
4. The Scan Orchestrator shall record the stages requested, the stages completed, and any skipped stage with a reason in the scan manifest.
5. If a later stage cannot run, the Scan Orchestrator shall complete earlier stages, record a degradation, and shall not discard those earlier artifacts.
6. The Scan Orchestrator shall keep the existing scan command and depth names so existing CI invocations continue to work.

### Requirement 2: Stage 1 Static Inventory

**Objective:** As a security reviewer, I want a static inventory of what exists in the repository, so that I can see files, surfaces, and pattern hits without treating them as verified vulnerabilities.

#### Acceptance Criteria

1. When stage 1 completes, the Static Inventory shall emit a repository snapshot, file targets with language and surface tags, entry-point reachability hints, ranked files, and static findings from the existing pattern ruleset and any provided static-analyzer input.
2. The Static Inventory shall label static pattern hits as inventory, not as verified findings, in the report and in the finding evidence level.
3. While no static-analyzer input is provided, the Static Inventory shall still complete using the built-in pattern ruleset and heuristics.
4. If an enabled rule's CWE does not resolve in policy, the Scan Runtime shall fail loud before producing inventory findings (existing startup invariant, preserved).
5. The Static Inventory shall not execute target-derived code and shall not require a model.

### Requirement 3: Stage 2 Complexity Map

**Objective:** As an AppSec engineer, I want a complexity map of where problems are most likely, so that review and testing attention go to real hotspots instead of every regex hit.

#### Acceptance Criteria

1. When stage 2 runs, the Complexity Map shall produce an ordered list of hotspots, each identifying a file and, when known, a function, with a complexity score and a rationale built from size, nesting, surface tags, reachability, existing inventory-hit density, and test-presence gaps.
2. The Complexity Map shall rank hotspots independently of a single regex match: a file with no pattern hit may still be a hotspot, and a pattern hit in a trivial helper may rank below a complex reachable parser.
3. When stage 2 completes, the Complexity Map shall write a map artifact that the report and later stages consume, including the scoring signals used for each hotspot.
4. While a hunter model is unavailable, the Complexity Map shall still produce the heuristic map and shall record that the hunter did not refine it.
5. The Complexity Map shall not mark a hotspot as verified or worth fixing.

### Requirement 4: Test-Tuning Hints

**Objective:** As a developer owning CI tests, I want the complexity map to tell me how to tune tests, so that I add coverage where it reduces real risk instead of mirroring cheat-sheet sinks.

#### Acceptance Criteria

1. When the Complexity Map emits a hotspot, the Test Tuning Advisor shall attach a test-gap hint that names the missing coverage (no adjacent test file, no test referencing the function, or no sanitizer/fuzz entry for a fuzzable surface).
2. The Test Tuning Advisor shall recommend a test kind from a closed set: unit, property, sanitizer, http-contract, or fuzz-harness, with a one-line reason tied to the hotspot's signals.
3. The Test Tuning Advisor shall not write test files into the scanned repository.
4. When a hotspot already has covering tests, the Test Tuning Advisor shall say so and shall not recommend a duplicate test kind.

### Requirement 5: Stage 3 Isolated Regression and Worth-Fixing

**Objective:** As a CI owner, I want isolated regression that answers whether a finding is worth fixing, so that the build fails only on triggerable, reachable issues.

#### Acceptance Criteria

1. When stage 3 runs, the Regression Runner shall select a bounded set of top hotspots and/or inventory findings and shall attempt a minimal regression or proof-of-concept inside an isolated analysis sandbox.
2. The isolated analysis sandbox shall run with network disabled, the source tree mounted read-only, a writable scratch area, and configured memory, process, and timeout limits.
3. The Regression Runner shall emit one of four verdicts per candidate: `triggerable`, `not_triggerable`, `already_covered`, or `inconclusive`.
4. When a candidate is `triggerable` and the related finding is reachable, the Worth-Fixing Gate shall mark it `worth_fixing`.
5. When a candidate is `not_triggerable` or `already_covered`, the Worth-Fixing Gate shall mark it `not_worth_fixing` and shall not fail the build for that candidate.
6. When the verdict is `inconclusive`, the Worth-Fixing Gate shall not fail the build for that candidate and shall record why (timeout, sandbox unavailable, no candidate generated, or setup failed).
7. Where `--fail-on worth-fixing` is selected, the Scan Orchestrator shall fail the scan if and only if at least one `worth_fixing` verdict was produced.
8. The Regression Runner shall never execute target-derived code on the host outside the isolated sandbox.

### Requirement 6: Tool-Using Hunter on Stages 2 and 3

**Objective:** As an OpenUltraSAST maintainer, I want the hunter on later stages to use repository tools instead of dumping a file into a prompt, so that it can follow dataflow across lines and files the way a real review does.

#### Acceptance Criteria

1. Where a hunter model is configured, the Hunter Pool shall run a bounded tool-using loop against stage-2 hotspots, with tools limited to reading a file inside the repository, searching repository text, and listing callers or references already known to the scan.
2. The Hunter Pool shall confine every tool path to the scanned repository root and shall reject path arguments that escape that root.
3. When the hunter reports a candidate issue, the Scan Runtime shall record it at evidence level `suspicion` until independent static or regression evidence raises it.
4. While no hunter model is configured, the Hunter Pool shall skip the tool loop, leave the heuristic complexity map in place, and record a degradation.
5. The Hunter Pool shall not treat a model JSON list as static corroboration.
6. When stage 3 runs and a hunter model is configured, the Hunter Pool may propose a regression snippet, but the Regression Runner shall execute that snippet only inside the isolated sandbox after a structural safety check (no network, no writes outside scratch).

### Requirement 7: Evolutionary Feedback from Regression to Map

**Objective:** As a maintainer, I want regression verdicts to retune the complexity map, so that the scan gets better at spending attention where issues actually trigger.

#### Acceptance Criteria

1. When a hotspot's regression is `triggerable`, the Complexity Map shall raise that hotspot's subsequent score on the same repository.
2. When a hotspot's regression is `not_triggerable`, the Complexity Map shall lower that hotspot's subsequent score without deleting the underlying inventory hit.
3. The Scan Runtime shall persist those adjustments in a loop-owned ledger keyed by repository and hotspot identity, applied at map load the same way rule status overlays apply at ruleset load.
4. If a ledger entry would hide a reachable severity-5 inventory hit from the worth-fixing set, the Worth-Fixing Gate shall still consider that hit.
5. The evolutionary loop shall not edit detection pattern text and shall not edit authoritative CWE severity.

### Requirement 8: Grounded Evaluation, Not Cheat Sheets

**Objective:** As a maintainer, I want stage 2 and stage 3 quality gates to use split-sink and mutation cases, so that a regex that only matches textbook one-liners cannot claim success.

#### Acceptance Criteria

1. The Benchmark Harness shall include at least one split-sink case per in-scope language family (Python, JavaScript, Java, C/C++) where the source and the sink are on different lines or the payload is assigned before use.
2. The Benchmark Harness shall include at least one mutation of a known sink (equivalent API, intermediate variable, or wrapper) that a same-line pattern does not match.
3. When stage 1 is scored alone, the Benchmark Harness may use existing smoke fixtures, and shall not treat stage-1 recall as proof of stage-2 or stage-3 quality.
4. When stage 2 is scored, the Benchmark Harness shall require the complexity map to rank the true vulnerable function in the top band of hotspots on the split-sink corpus, even when stage 1 missed the sink.
5. When stage 3 is scored and the sandbox is available, the Benchmark Harness shall require a `triggerable` verdict on at least one planted split-sink that stage 1 missed.
6. The CI merge gate for this feature shall fail if stage 2 ranking on the split-sink corpus is no better than ranking files by pattern-hit count alone.

### Requirement 9: CI Companion Budgets and Degradation

**Objective:** As a CI owner, I want stage costs and failures to be bounded and visible, so that pull-request jobs stay cheap and nightly jobs can run the later stages without silent fallback.

#### Acceptance Criteria

1. While running in pull-request depth `quick`, the CI Pipeline shall complete stage 1 without a sandbox runtime and without a model.
2. Where a nightly or labeled job requests `standard` or `deep`, the CI Pipeline shall run those stages under the configured time, finding-count, and cost budgets.
3. If the sandbox runtime is missing when stage 3 is requested, the Scan Orchestrator shall skip stage 3, record `sandbox_unavailable`, and complete stages 1–2.
4. If a model is missing when stage 2 hunter refinement is requested, the Scan Orchestrator shall keep the heuristic map, record `hunter_model_unavailable`, and shall not invent hunter findings.
5. The Scan Orchestrator shall bound stage 3 to a configured maximum number of regression candidates per scan.
6. When any stage is skipped or truncated, the report shall show the degradation in the same manifest list used by existing capability fallbacks.
