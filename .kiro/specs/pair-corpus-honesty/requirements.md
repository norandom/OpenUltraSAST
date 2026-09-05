# Requirements Document

## Introduction

Engineers evolving OpenUltraSAST's overlay cannot trust the pair scoreboard: coverage detections are dropped, vfc labels mostly say `sink = "unknown"`, a quarter of the vfc corpus fails to parse because excerpts start mid-comment, two sast pairs are unlabelable as vendored, and there is no Node/TypeScript/Python web corpus and no agent-authored corpus. This spec makes the scoreboard honest per slice, per mechanism, and per provenance, adds three web and agent-authored slices, and lets the improve loop accept a change only when no provenance profile regresses. It supersedes `real-world-vfc-slice` for the corpus and scorer plane.

## Boundary Context

- **In scope**: pair scorer fidelity; catalog label schema (function, mechanism, provenance, known limits, held-out split); harvest anchoring and extraction modes; sast corpus hygiene; `vibe-py`, `vfc-js`, `agent-vfc` slices; dataset pointers; deterministic provenance fingerprint at scan time; per-profile and per-mechanism dashboard; per-profile acceptance in the improve loop; offline tests.
- **Out of scope**: taint, facts, CST walker, dispositions, or tolerance of parser ERROR nodes (engine specs); BaxBench generation slices; profile-specific fact tables or thresholds; any new merge gate; vendoring files without a stated license; LLM-based classification.
- **Adjacent expectations**: `local` stays the 100% pair gate; the stage-1 smoke gate stays inventory-only; `OverlayRecord` may gain one optional additive field; the improve loop's existing accept gate (recall floor, FP ceiling, score, no matched regression) stays and grows one clause; ledger file formats do not change.

## Requirements

### Requirement 1: Scorer counts every adjudicated detection

**Objective:** As an engineer evolving adjudication, I want the pair scorer to count what the overlay actually found, so that sink aliases and coverage flows move the number instead of vanishing.

#### Acceptance Criteria

1. When an overlay slice pair is scored, the system shall count a `coverage` record that carries a source-to-sink flow as a detection on the vulnerable side and as a leak on the fixed side, symmetrically with `promote`.
2. When an expected row names a function, the system shall match a promotion or coverage record only if the record lies inside that function's line range.
3. When an expected row names neither a rule id nor a sink nor a function, the system shall not count a CWE-only match as a detection and shall flag the row as `weak_label` in the payload.
4. When any overlay slice is evaluated, the system shall report inventory and overlay metrics side by side for that slice, not only for `vfc`.
5. When a pair is evaluated, the system shall report how many files on each side were `parse_failed` and how many proposals were `unadjudicated`, so parser loss is visible on the dashboard.
6. The system shall keep `local` as the only slice whose result can fail CI.
7. Where a hunter model is configured, the system shall report a third scorer, `hunter`, that runs the tool hunter on each isolated pair function and scores it with the same pair rules, so the LLM plane is measured on the same corpus; absence of a model shall skip the scorer with a recorded degradation.

### Requirement 2: Labels carry function, mechanism, and known limits

**Objective:** As a maintainer, I want every pair to say what should fire, where, and by which mechanism, so that recall can be read per mechanism and unachievable pairs do not pollute the achievable number.

#### Acceptance Criteria

1. Each expected row shall carry a `mechanism` value from a closed, versioned vocabulary stored as data next to the catalogs.
2. Each pair shall carry a `provenance` value from the closed set `human`, `agent`, `mixed`, `synthetic`.
3. When a pair is only achievable with information outside the vendored files, the catalog shall declare `known_limit` with a reason, and the system shall evaluate the pair but exclude it from the achievable metrics and report it separately.
4. When a catalog is loaded, the system shall reject an expected row whose `sink` is `unknown` and whose `function` and `rule_id` are both absent, and shall reject an unknown `mechanism` or `provenance` value.
5. Each pair shall carry a `split` value of `train` or `holdout`, declared in the catalog and never chosen at run time.
6. Where a recipe names a function, the generated expected row shall carry that function name.

### Requirement 3: Harvest anchors at the declarator

**Objective:** As a maintainer growing the corpus, I want harvest to extract the function body and nothing before it, in C, JavaScript, TypeScript, and Python, so that excerpts parse and pairs are attributable.

#### Acceptance Criteria

1. When harvest searches for a function by name, the system shall ignore occurrences inside comments and string literals and shall anchor on the declarator line.
2. Where a recipe gives a line range instead of a name, the system shall extract exactly that range from the parent and fix blobs.
3. Where a recipe gives a fix commit and a file, the system shall extract the function enclosing the first changed hunk on both sides.
4. When the language is Python, the system shall extract by indentation, not by braces.
5. When harvest is re-run for the curl recipes, the system shall produce excerpts that start at the declarator; the mid-comment excerpts shall no longer exist in the catalog.
6. The system shall not fetch during pytest, and extraction shall be unit-tested on local strings.

### Requirement 4: sast corpus hygiene

**Objective:** As an engineer, I want the textbook slice to contain only pairs that are labelable from the vendored files, so that a miss there is an engine miss.

#### Acceptance Criteria

1. The Juliet CWE-121 strcpy pair shall vendor the buffer declarations that differ between `bad` and `goodG2B`, so the two bodies are not byte-identical.
2. The OWASP Java hash pair shall be declared `known_limit` with reason `cross_artifact`, or shall vendor the property file that makes it labelable; either satisfies this criterion.
3. When the sast slice is evaluated, the payload shall report achievable pairs and known-limit pairs as separate counts.

### Requirement 5: Web and agent-authored slices

**Objective:** As an AppSec engineer, I want labeled Node, TypeScript, and Python web pairs, including agent-authored code, so that the harness is measured on the code operators are writing now.

#### Acceptance Criteria

1. The system shall add a `vibe-py` slice built from Real-Vuln-Benchmark manifests: pinned commit, file, line range, function, primary and acceptable CWEs, and authorship, with false-positive trap entries used as fixed-side twins.
2. The system shall add a `vfc-js` slice built from SecBench.js sink locations and fix commits, harvesting from the upstream package repositories, and shall not vendor SecBench.js test files.
3. The system shall add an `agent-vfc` slice of security-fix commits carrying an AI agent co-author trailer or generation marker, in JavaScript, TypeScript, or Python, each human reviewed before entering the catalog.
4. Each vendored pair shall carry repo, commit, parent, commit URL, license, provenance, mechanism, and split; a pair without a stated license shall not be vendored.
5. Each new slice shall start with a reviewed set on the order of tens of pairs and shall not require network in CI.
6. When the new slices are added, `datasets.toml` shall point at Real-Vuln-Benchmark, SecBench.js, AIDev, BaxBench, SecurityEval, CodeSecEval, CWEval, and CyberSecEval, and shall note that CyberSecEval labels are defined by its own rules and are not recall ground truth.

### Requirement 6: Provenance fingerprint at scan time

**Objective:** As an operator, I want a scan to say whether the tree looks agent-authored, so that profiles can be applied and reported without a model.

#### Acceptance Criteria

1. When a scan preprocesses a tree, the system shall compute a provenance value from deterministic signals only: agent configuration files and directories, generation markers in files, and commit trailers when a git history is readable.
2. The system shall record the provenance value and the signals that produced it in the manifest.
3. The system shall not call a language model to classify provenance.
4. If no signal is found, then the system shall record `human` with an empty signal list rather than guessing.

### Requirement 7: Profile dashboards and per-profile acceptance

**Objective:** As a maintainer running the improve loop, I want metrics per provenance profile and per mechanism, and an accept gate that refuses a change that helps one profile by hurting another, so that tuning can branch without overfitting.

#### Acceptance Criteria

1. When pairs are evaluated, the system shall report metrics per provenance profile and per mechanism in the machine-readable payload.
2. When the improve loop evaluates a candidate change, the system shall compute pair metrics per profile on the `holdout` split and shall reject the change if any profile's pair-correct or Youden regresses beyond a configured tolerance.
3. The system shall keep the existing accept gate clauses unchanged and shall not treat any non-local slice's Youden as a merge condition.
4. The system shall support at most four provenance profiles and shall report when a profile has fewer holdout pairs than a configured minimum.
5. Where a scan carries a provenance value, reports shall name the profile so an operator can relate dashboard numbers to their tree.

### Requirement 8: Offline testability and unchanged gates

**Objective:** As a maintainer, I want CI to prove the corpus loads and the scorer is honest without network, so that the corpus cannot rot and the gates cannot drift.

#### Acceptance Criteria

1. When the test suite loads the default catalog, it shall observe `vibe-py`, `vfc-js`, and `agent-vfc` among the slices and every referenced file on disk.
2. When the pairs command runs for each new slice with JSON output, it shall exit zero and include per-profile and per-mechanism metrics.
3. The stage-1 detection gate, the split-sink map gate, and the local pair gate shall be unchanged by this spec.
4. The extra-free suite shall stay green; overlay-dependent assertions shall skip when the semantic extra is absent.

### Requirement 9: Review tiers instead of a binary review gate

**Objective:** As a maintainer, I want every pair to carry how its label was established, so that the corpus can grow past what one person can review while only trusted tiers steer the improve loop.

#### Acceptance Criteria

1. Each pair shall carry a `review_tier` from the closed set `seeded` (ground truth reviewed by the upstream benchmark), `advisory` (a CVE or GHSA with a public fix commit), `title` (mechanism inferred from a commit message, unreviewed), `reviewed` (a named reviewer in this repository).
2. When pairs are evaluated, the system shall report metrics per review tier in the machine-readable payload.
3. The improve loop's per-profile holdout clause shall use only `seeded` and `reviewed` pairs; `advisory` and `title` pairs shall be scored and reported but shall not gate.
4. When a recipe carries `reviewer = "pending"`, its tier shall be `title` and it shall load into the catalog, replacing the former candidates-only gating; the `title` tier is the review queue.
5. The catalog loader shall reject a pair whose tier is `reviewed` but names no reviewer.

### Requirement 10: Pointer slices score public code without vendoring it

**Objective:** As a maintainer, I want to score pairs whose upstream repository states no license, so that the corpus is not capped by redistribution rights while the repository never redistributes that code.

#### Acceptance Criteria

1. A slice catalog may mark a pair `vendored = false`; such a pair carries repo, parent, commit, path, and extraction recipe but no excerpt files in the repository.
2. When a non-vendored pair is evaluated and the network is allowed, the system shall harvest both sides into a local cache outside the repository tree and score them exactly like a vendored pair.
3. When the network is not allowed, non-vendored pairs shall be skipped with a recorded degradation and shall not fail any test or gate.
4. The default `pytest` run and every CI gate shall evaluate vendored pairs only; a separate nightly command shall evaluate pointer slices.
5. Harvested cache files shall never be committed; the cache directory shall be ignored by git.
6. The `vibe-py` slice shall gain the LLM-generated Real-Vuln repositories as non-vendored `agent` pairs, and the `agent-vfc` slice shall gain unlicensed agent-authored fix commits as non-vendored pairs, each with `review_tier` set.

