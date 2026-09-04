# Requirements Document

## Introduction

OpenUltraSAST users scan **working trees they are writing**: mixed files, incomplete edits, generated code, framework wrappers, and no labels. Today the harness still *decides* with pattern inventory. The complexity map ranks; the sandbox can run; neither adjudicates “this sink is fed by a source” versus “this sink is hardcoded, sanitized, or unreadable.”

This feature splits the scan into three operator-visible roles that must not collapse: **regex proposes, semantics adjudicates, sandbox proves.** Labeled suites (cheat-sheet fixtures, OWASP Benchmark, Juliet, CVE pairs) remain **calibration**. They are not the definition of in-scope code.

## Boundary Context

- **In scope**: Role split on `quick` / `standard` / `deep`; overlay dispositions; tree-sitter (and optional Joern) as the semantic engine; tunable retrieval/rank **before prove**; `unadjudicated` on messy files; sandbox only after promote; calibration vs unlabeled working trees.
- **Out of scope**: Deleting pattern rules; making an LLM the adjudicator; rewriting CWE policy or project-score formula; requiring Joern or an embedding model for `quick`; auto-generated flow facts from the improve loop; treating benchmark Youden as a merge gate that can unblock a smoke-gate breach. Embedding rank is a **budget**, not a fourth verdict.
- **Adjacent expectations**: Stage plan, complexity map, Docker sandbox, pair catalog, and 90/10 detection gate from `three-stage-scan` keep their contracts. This spec overlays adjudication on that pipeline; it does not replace stage accounting, sandbox flags, or `LANGUAGE_MANIFESTS`.

## Requirements

### Requirement 1: Three roles stay distinct

**Objective:** As an operator, I want every finding to show whether it is a proposal, an adjudication, or a proof, so that a sink hit is never mistaken for a worth-fixing verdict.

#### Acceptance Criteria

1. When OpenUltraSAST completes a `quick` scan, the system shall emit inventory proposals only and shall not emit adjudication dispositions or sandbox verdicts.
2. When OpenUltraSAST completes a `standard` scan, the system shall attach an adjudication disposition to each inventory proposal it considered and shall not execute target-derived code to obtain that disposition.
3. When OpenUltraSAST completes a `deep` scan, the system shall offer sandbox proof only for candidates that adjudication promoted and that remain reachable or inferred-file-surface, ordered by the tunable rank/retrieval budget.
4. The system shall not treat an inventory proposal as worth-fixing.
5. The system shall not treat an adjudication promote as crash-reproduced, exploit-demonstrated, or patch-validated.

### Requirement 2: Messy working trees are the primary target

**Objective:** As a developer writing ordinary code, I want the harness to degrade honestly on files that are not labeled benchmarks, so that silence is not reported as safety.

#### Acceptance Criteria

1. When a scanned file is incomplete, generated, minified, or otherwise not interpretable as structured source, the system shall leave matching inventory proposals **unadjudicated** and shall record that reason on the finding.
2. When no available semantic engine can follow data from a source to a sink for that file (parse failure, missing grammar, cross-file call, dynamic dispatch, or missing callee), the system shall leave the proposal unadjudicated rather than demote it.
3. When OpenUltraSAST scans a working tree with no benchmark manifest and no expected-finding labels, the system shall still emit proposals, dispositions, and (in `deep`) proofs without requiring a counterpart “fixed” tree.
4. If the operator reads a report for an unadjudicated proposal, then the system shall present it as unresolved inventory, not as a verified vulnerability and not as a cleared finding.
5. The system shall not require a file to resemble an OWASP Benchmark or Juliet test case in order to produce a proposal.

### Requirement 3: Adjudication promote, demote, coverage

**Objective:** As an AppSec reviewer, I want the overlay to keep, drop, or add findings based on flow, so that hardcoded and sanitized sinks stop looking like attacks.

#### Acceptance Criteria

1. When a proposal’s sink is reachable from an identified untrusted source without an identified sanitizer in the adjudicated region, the system shall **promote** the proposal.
2. When a proposal’s sink is fed only by a constant, a sanitizer, or an identified non-attacker source in the adjudicated region, the system shall **demote** the proposal and shall not list it as a promoted finding.
3. When adjudication finds an untrusted source flowing to a dangerous sink that inventory did not propose, the system shall emit a **coverage** finding at corroboration-or-lower evidence, tagged as overlay-originated.
4. When both a source-to-sink path and a sanitizer appear to apply, the system shall not promote unless the sanitizer does not dominate that path.
5. The system shall persist promote, demote, unadjudicated, and coverage outcomes in the scan artifacts with the proposal identifier they refer to.

### Requirement 4: Calibration corpora do not define product success

**Objective:** As a maintainer, I want labeled suites to measure the overlay without becoming the only in-scope code, so that we do not overfit textbook cases.

#### Acceptance Criteria

1. When the stage-1 detection gate runs, the system shall score inventory only on the existing cheat-sheet corpus and shall not fold overlay Youden or unlabeled-scan counts into that gate.
2. When the pair-efficiency evaluation runs on the SAST slice, the system shall score **adjudicated** outcomes (promote on the vulnerable side, demote or silent on the false or good side), not raw inventory hits.
3. When overlay changes raise SAST Youden and also cause the stage-1 detection gate to fail, the system shall treat the detection-gate failure as blocking.
4. The system shall keep labeled pair fixtures and SAST-slice cases out of the stage-1 cheat-sheet corpus map.
5. The system shall not require a labeled counterpart tree in order to scan an operator working tree.

### Requirement 5: Evidence and models stay honest

**Objective:** As a reviewer, I want overlay and hunter output to stay on the evidence ladder, so that a model cannot mint proof.

#### Acceptance Criteria

1. The system shall keep inventory and successful intra-file adjudication at `static_corroboration` or below.
2. When the tool hunter emits a finding, the system shall keep that finding at `suspicion` unless an independent corroborating stage has already raised it.
3. If an overlay or hunter result claims an evidence level above corroboration without a sandbox or verifier step that earned it, then the system shall reject that claim.
4. The system shall not use a language model as the adjudication engine that decides promote or demote.
5. Where CWE policy applies, the system shall resolve severity from the central CWE policy, not from the overlay or the proposing rule’s private severity string.

### Requirement 6: Sandbox proves only promoted work

**Objective:** As a DevOps engineer, I want isolation to spend budget on promoted sinks, so that `deep` does not execute every regex hit.

#### Acceptance Criteria

1. When `deep` runs and the sandbox is available, the system shall select regression candidates from promoted findings, not from demoted findings.
2. When a finding is unadjudicated, the system shall not treat a sandbox skip as proof that the finding is safe.
3. If the sandbox is unavailable, then the system shall keep promoted findings as unproven corroboration, record `sandbox_unavailable`, and shall not invent a worth-fixing verdict.
4. When sandbox proof is `triggerable` on a promoted reachable finding, the system shall allow `worth_fixing` to follow the existing worth-fixing rule from the three-stage scan.
5. The system shall not execute target-derived code outside the existing isolated sandbox path.

### Requirement 7: Operator-visible artifacts and fail-on

**Objective:** As an operator, I want the report to show the three-role pipeline on real trees, so that I can act on promoted and worth-fixing items without trusting unlabeled silence.

#### Acceptance Criteria

1. When a `standard` or `deep` scan finishes, the system shall write overlay artifacts that list each considered proposal, its disposition, and any flow facts or unadjudicated reason.
2. When the markdown or SARIF report is written, the system shall distinguish promoted, demoted, unadjudicated, and coverage items.
3. Where `--fail-on worth-fixing` is used, the system shall fail only on worth-fixing as already defined, not on unadjudicated inventory.
4. The system shall keep `quick` usable without overlay configuration and without a model.
5. If overlay fact data is missing or invalid, then the system shall degrade to inventory-only for that scan, mark proposals unadjudicated with that reason, and shall not abort `quick`.

### Requirement 8: Semantic engines are multi-language and optional-at-runtime

**Objective:** As an AppSec engineer scanning mixed-language trees, I want adjudication to use a real parser family, so that Python-only stdlib parsing is not the product engine.

#### Acceptance Criteria

1. When a tree-sitter grammar for the file’s language is available, the system shall use that parse as the primary intra-file IR for adjudication.
2. When tree-sitter is unavailable for that language, the system shall try a stdlib parse only for Python and shall otherwise leave the proposal unadjudicated with language_unsupported or parse_failed.
3. Where Joern is installed and the language is one Joern can export, the system shall be allowed to attach Joern flow facts as **additional** corroboration; Joern absence shall not fail `quick` or `standard`.
4. If Joern and tree-sitter disagree or Joern returns incomplete paths, then the system shall not demote on that disagreement; it shall promote only on a complete dominating path or leave the item unadjudicated.
5. The system shall not require Joern or tree-sitter to be present for a `quick` inventory scan.
6. The system shall not use a language model as the parse or taint engine.

### Requirement 9: Mechanism memory ranks prove budget, not truth

**Objective:** As an operator on a large messy tree, I want proven-bug *mechanisms* (not raw file slices) to decide **what to prove next**, so that the sandbox follows patterns that have worked on real bugs.

#### Acceptance Criteria

1. When `deep` has more promoted candidates than the sandbox budget, the system shall order them using the existing ranker axes plus OpenRouter embedding similarity over mechanism records, after hard filters on language, CWE, and tags.
2. When no embedding model or API key is configured, the system shall order candidates with the heuristic ranker only, record that degradation, and shall not skip prove.
3. The system shall not demote or drop a promotion solely because mechanism similarity is low.
4. When the embedding index is missing or stale, the system shall rebuild it from the mechanism log via OpenRouter embeddings; if that rebuild fails, the system shall record the degradation and continue on heuristic order.
5. The system shall keep hard filters operator-tunable (language, CWE, tags) without changing CWE severity policy.
6. When a finding is sandbox-proven triggerable (or otherwise verified at corroboration-or-higher with a prove step), the system shall append an abstract mechanism record to the mechanism log: summary, CWE, language, tags, what made it exploitable — without file:line as the identity.
7. The system shall treat the append-only mechanism log as the source of truth; any vector index shall be a rebuildable cache of that log.
8. The system shall not persist mechanisms from inventory-only, demoted, or unadjudicated proposals.
