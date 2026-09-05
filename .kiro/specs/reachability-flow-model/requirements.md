# Requirements Document

## Introduction

OpenUltraSAST cannot yet steer effort where risk is reduced because it has no model of how an entry point reaches a sink. Reachability today means "inside a handler," taint is one hop inside one file, the LLM hunter cannot create a sandbox candidate, and the improve loop cannot add the facts that would raise recall. This spec adds a call graph and composed taint summaries over the existing `FunctionIR` records, attaches path-based reachability to findings and ranking, puts the hunter on paths with one checkable question per gap, turns model answers into gated facts, and ranks fix points by reachable risk removed. Concolic execution is out of scope; the sandbox remains the only place target code runs.

## Boundary Context

- **In scope**: call graph, taint summaries, path records, reachability attachment to findings, rank, complexity map and worth-fixing; hunter path context; hunter findings as sandbox candidates; fact oracle and candidate-fact cache; `facts` improve lever; fix-point ranking and report section; offline tests and measurement on existing slices.
- **Out of scope**: guard semantics; CST walker fixes; whole-program alias analysis; symbolic or concolic execution; new dispositions or evidence rungs; LLM as parser; any merge gate change; profile-specific fact tables beyond the gate defined by `pair-corpus-honesty`.
- **Adjacent expectations**: `FileIR` shape is frozen except additive fields; `load_facts` merges candidate facts below hand-written facts; the improve loop's existing accept gate and per-profile holdout clause apply unchanged to the new lever; sandbox safety checks apply to hunter snippets as today.

## Requirements

### Requirement 1: Call graph and graph reachability

**Objective:** As an AppSec engineer, I want to know whether an entry point actually reaches a function, so that a finding's reachability is a path and not a line-in-handler guess.

#### Acceptance Criteria

1. When a tree is mapped, the system shall build a call graph whose nodes are functions from `FileIR` records and whose edges are resolved call sites, across files, using name and import resolution.
2. When a call site cannot be resolved, the system shall record it as an unresolved edge and shall not treat the callee as unreachable or safe.
3. When entry points exist, the system shall compute for each function the shortest distance from any entry point and one witness path, bounded by a configured maximum depth.
4. The system shall prefer over-approximation: an ambiguous name resolving to several definitions yields edges to each, marked ambiguous.
5. If the semantic extra is absent, then the system shall build the graph for Python from the stdlib parse and shall mark other languages `graph_unavailable` without failing the scan.
6. The system shall write the graph and distances as a run artifact without any target code execution.

### Requirement 2: Taint summaries composed along the graph

**Objective:** As an engineer, I want flows that cross function and file boundaries to appear as one path, so that a request parameter reaching a sink three calls down is visible.

#### Acceptance Criteria

1. When a function is analyzed, the system shall produce a summary stating which parameters reach which sinks, which parameters reach the return value, and which parameters are fully constant-dominated, using the existing intra-file taint engine.
2. When a caller passes a tainted argument to a callee whose summary maps that parameter to a sink, the system shall record a path from the caller's source through the callee to the sink.
3. The system shall compose summaries to a configured depth and shall stop with `flow_incomplete` beyond it, carrying the partial path in the record.
4. When a hop's callee is unresolved, the system shall record the path as incomplete at that hop, never as safe.
5. The system shall emit path records with entry, ordered hops, sink, sink line, and the summary used at each hop.

### Requirement 3: Reachability drives rank, map, and worth-fixing

**Objective:** As a DevOps engineer, I want ranking and worth-fixing to use real reachability, so that budget and CI failures go to reachable risk.

#### Acceptance Criteria

1. When a finding lies in a function with a finite graph distance from an entry point, the system shall mark it `reachable` and attach the distance and witness path to its reachability evidence.
2. When a finding lies in a function with no path within the depth bound, the system shall mark it `unknown`, not `unreachable`.
3. The rank formula's reachability term shall use graph distance when available, falling back to today's hints otherwise, with the change recorded in the rationale.
4. The complexity map shall add path count and minimum distance as signals and shall not use them as the sole score.
5. The worth-fixing gate shall accept graph-reachable findings as reachable; the existing `inferred-file-surface` case stays.
6. The system shall keep the split-sink map gate passing and shall extend it with a path check defined in Requirement 8.

### Requirement 4: Hunter on paths

**Objective:** As an engineer, I want the hunter to work on a path and ask one checkable question, so that model spend goes to what static analysis cannot do.

#### Acceptance Criteria

1. When a hunter runs on a hotspot that has path records, the system shall provide a `path_context` tool returning the entry, hops, sink, summaries, and known guards for a chosen path.
2. The hunter prompt shall ask for a verdict on a specific path and a proposed input, not a whole-file review, when path records exist.
3. When a hunter finding names a sink line that the overlay or the graph can locate, the system shall make it eligible as a sandbox candidate after the existing safety check, without requiring an inventory promotion.
4. The system shall keep hunter findings at `suspicion` until an independent check agrees: a sandbox trigger, a composed path to that sink, or an accepted fact; evidence rises on that check, not on origin.
5. The hunter shall stay within the existing step and cost budgets; path context counts toward them.

### Requirement 5: Fact oracle with gated candidate facts

**Objective:** As a maintainer, I want the model to answer one question about a callee and have the answer reused as data, so that recall rises without hand-writing every fact and without paying tokens on every scan.

#### Acceptance Criteria

1. The system shall define a closed set of question kinds: `nullable_return`, `bounded_argument`, `transformer_set_get`, `returns_parameter_taint`, `sanitizes_parameter`.
2. When the static engine stops at an unresolved or unsummarized callee on a path, the system shall record a question for that callee; questions shall be asked only when a hunter or verifier model is configured.
3. When a model answers, the system shall store a candidate fact with the question, the answer, the model id, the source hash, and a timestamp, in a cache next to the calibration ledgers.
4. The system shall not load candidate facts into adjudication unless they have been accepted by the improve loop's `facts` lever; hand-written facts always take precedence over candidate facts.
5. The system shall not execute target code to answer a question and shall not send secrets; redaction applies to question context.
6. If no model is configured, then the system shall record the open questions in the manifest and proceed.

### Requirement 6: Facts as an improve-loop lever

**Objective:** As a maintainer, I want the improve loop to be able to accept or reject facts, so that the evolutionary machinery can move detection and not only rule status.

#### Acceptance Criteria

1. The improve loop shall gain a `facts` lever whose edits add or remove a candidate fact from the accepted set.
2. The validator shall accept only edits whose fact kind is in the closed set and whose source is the candidate cache or a benchmark signal; free-form pattern text is rejected.
3. When a `facts` edit is evaluated, the existing accept gate and the per-profile holdout clause shall apply unchanged; rejection reverts byte for byte.
4. The journal shall record each fact edit with its provenance and the metrics before and after.
5. The system shall never remove or override a hand-written fact through this lever.

### Requirement 7: Fix points ranked by reachable risk removed

**Objective:** As an operator, I want to know which few fixes remove the most reachable risk, so that I fix the worst things first.

#### Acceptance Criteria

1. When path records exist, the system shall compute fix points as functions or guard sites that dominate multiple paths in the path graph.
2. Each fix point shall carry an estimate of risk removed: the sum over dominated paths of policy severity weighted by evidence, and the number of paths collapsed.
3. The report shall gain a "fix first" section listing fix points in order of risk removed, each with its witness paths.
4. The system shall not let fix-point ranking hide a reachable severity-5 finding from the worth-fixing candidate set.
5. The fix-point list shall be written as a run artifact and exposed to reports without executing target code.

### Requirement 8: Measurement and unchanged gates

**Objective:** As a maintainer, I want the path model measured on the corpora we have, so that the shift is grounded.

#### Acceptance Criteria

1. On the split-sink fixtures, the system shall report whether a path exists from a planted entry point to each planted function, and the map gate shall assert at least one such path per language family.
2. On slices whose labels name a function, the pair payload shall report the fraction of labeled functions that have a finite graph distance.
3. The stage-1 detection gate, the local pair gate, and the existing split-sink gate assertions shall be unchanged.
4. Default tests shall not require a model, a sandbox, or network; oracle and hunter tests use scripted clients.
5. The extra-free suite shall stay green with graph-dependent assertions skipping when the extra is absent.
