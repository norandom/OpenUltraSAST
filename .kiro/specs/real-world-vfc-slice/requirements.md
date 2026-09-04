# Requirements Document

## Introduction

AppSec engineers cannot tell whether OpenUltraSAST improved on real product code. The labeled pair slices today are in-tree fixtures (`local`), small GitHub/SVEN functions (`github`), and textbook OWASP/Juliet files (`sast`). Operators care whether the harness fires on a real buggy snapshot of OpenSSL, Firefox, or Chromium and stays quiet after the patch. This spec adds a reviewed, isolated-function **vfc** slice drawn from public vulnerability-fixing commits in those projects, scored as an honesty dashboard (not a merge gate), so the tool can be evolved against labeled product code instead of cheat-sheet recall.

## Boundary Context

- **In scope**: A new pair slice of reviewed isolated function pairs from OpenSSL, Firefox (gecko-dev / mozilla-central / mozilla-firefox/firefox), and Chromium; provenance on every vendored file; overlay-versus-inventory scoreboard on that slice; a harvest procedure that does not clone megarepos; offline runnable catalog; testability of catalog load and slice evaluation.
- **Out of scope**: Cloning mozilla-central or Chromium into the repository or CI; FixFox (embargoed until 2030); live Bugzilla scraping; making overlay or vfc Youden a merge or smoke gate; buffer-size / CWE-121 semantics; inter-file taint; parser packaging; changing pattern inventory rules so the seed pairs pass.
- **Adjacent expectations**: Existing pair evaluation still scores `local` as the 100% CI gate and `github` / `sast` as honesty dashboards. Overlay dispositions, taint, and the stage-1 detection gate stay owned by their current specs. Dataset pointers may list Firefox/Chromium/OpenSSL sources; the dumps themselves are not vendored.

## Requirements

### Requirement 1: Seed vfc slice from OpenSSL, Firefox, and Chromium

**Objective:** As an AppSec engineer, I want a labeled vuln-versus-fix slice from OpenSSL, Firefox, and Chromium, so that I can measure the harness on real product functions instead of only textbook files.

#### Acceptance Criteria

1. When an operator requests the vfc pair slice, OpenUltraSAST shall evaluate a catalog of isolated vuln-versus-fix pairs whose slice name is `vfc`.
2. The vfc slice shall include at least one reviewed pair whose origin project is OpenSSL, at least one whose origin project is Firefox, and at least one whose origin project is Chromium.
3. When the default pair catalog is loaded, the system shall include the vfc pairs together with the existing local, github, and sast pairs.
4. If a candidate has only an advisory write-up and no public version-control commit for both the vulnerable and fixed snapshots, then the system shall not accept that candidate as a vfc pair.

### Requirement 2: Provenance on every vendored pair

**Objective:** As a maintainer, I want every vfc file to carry repo, commit, identifier, and license, so that labels can be audited and redistributed legally.

#### Acceptance Criteria

1. When a vfc pair is vendored, the system shall record the source repository, the fixing commit identifier, a public commit URL, the CVE or equivalent public identifier when one exists, and the license of the original file.
2. When a vfc source file is stored in the catalog, the file shall contain a human-readable provenance header with those same fields.
3. The system shall use the same relative path on the vulnerable snapshot and the fixed snapshot of a pair.
4. If license information cannot be stated for a candidate, then the system shall not vendor that candidate.

### Requirement 3: Honesty dashboard, not a merge gate

**Objective:** As a developer merging changes, I want vfc misses and leaks to be visible without failing CI, so that real-project honesty cannot be gamed by blocking the merge.

#### Acceptance Criteria

1. When the pair efficiency gate runs, the system shall not fail because a vfc pair is a miss or a leak.
2. The system shall not add vfc pair names to the stage-1 detection smoke-gate fixture list.
3. When an operator evaluates the vfc slice, the system shall report pair-correct, vuln-side detection, silent-on-fix, and Youden for that slice.
4. The system shall not require the vfc slice to reach a 100% pair-correct rate, and shall not treat overlay or vfc Youden as a merge condition.

### Requirement 4: Overlay versus inventory scoreboard

**Objective:** As an engineer evolving adjudication, I want inventory and overlay scores side by side on the vfc slice, so that I can see whether the overlay helped or hurt on real product functions.

#### Acceptance Criteria

1. When an operator evaluates the vfc slice, the system shall report inventory scoring and overlay scoring for that slice as separate scoreboard figures.
2. Where overlay cannot adjudicate a vfc file, the overlay scoreboard shall fall back to inventory for that pair rather than recording silence as safety.
3. The system shall not replace the local-slice pair gate with overlay or vfc Youden.
4. When the vfc scoreboard is emitted as machine-readable output, both scorers shall be present so a later run can be compared without re-deriving the split.

### Requirement 5: Harvest without megarepos or embargoed dumps

**Objective:** As a maintainer, I want a repeatable way to add reviewed pairs from public commits, so that the catalog can grow without vendoring Firefox, Chromium, or 16 GB VFC dumps.

#### Acceptance Criteria

1. The system shall provide a harvest procedure that fetches a named file at a parent commit and a fixing commit from a public host and extracts one function into the vuln and fixed snapshots.
2. When harvest runs, the system shall not require a full clone of mozilla-central, gecko-dev, or Chromium to produce a pair.
3. The system shall not vendor FixFox or other embargoed datasets.
4. DiverseVul-style automatic vulnerable labels shall not be treated as ground truth unless a human review step has accepted the pair.
5. The runnable catalog that CI evaluates shall remain a small reviewed set (on the order of tens of pairs, not thousands).

### Requirement 6: Isolated, reviewed functions the overlay can be honest about

**Objective:** As an operator, I want each pair to be a single isolated function with a reviewed label, so that a miss or leak is attributable to the harness rather than to an unlabeled megatree.

#### Acceptance Criteria

1. When a vfc pair is evaluated, the scanner shall see only the vulnerable file or only the fixed file, never both in the same tree.
2. Each vfc pair shall isolate the changed function (plus the minimum types or stubs needed to keep that function intact), not an entire project tree.
3. The catalog shall prefer injection, XSS, or path-traversal pairs when a public commit exists, and may include memory-safety pairs as known inventory-only leaks until a later memory-safety spec.
4. A maintainer shall be able to read the expected CWE, sink, and evidence for each seed pair.

### Requirement 7: Slice is testable offline

**Objective:** As a maintainer, I want CI to prove the vfc catalog loads and the slice command runs without network access, so that the labeled corpus cannot rot unnoticed.

#### Acceptance Criteria

1. When the test suite loads the default pair catalog, it shall observe vfc among the slice names and shall observe that every vfc vuln file and fixed file exists on disk.
2. When an operator runs the pairs command for slice `vfc`, the command shall complete and emit a scoreboard that includes the OpenSSL, Firefox, and Chromium seed pair names.
3. If the semantic extra is absent, then vfc evaluation shall still complete (via inventory fallback) rather than fail the extra-free suite.
4. The extra-free detection smoke gate shall still ignore vfc pair names and vfc Youden.
