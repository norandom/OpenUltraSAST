# Requirements Document

## Introduction

AppSec engineers scanning mixed working trees need overlay adjudication on Python, JavaScript, C/C++, and Java, not only on files a Python stdlib parse can read. Today a `standard` or `deep` scan leaves JS/C/Java inventory as `language_unsupported` even when a host parser CLI is present, so those proposals never promote or demote. This spec makes an **optional semantic extra** the way to turn on a real structured parse for those languages, while `quick` stays usable with no extra packages and a missing extra stays fail-closed.

## Boundary Context

- **In scope**: Optional extra install; overlay using a structured parse for Python, JavaScript, C/C++, and Java when that extra provides a grammar; fail-closed `unadjudicated` when the extra or grammar is missing; `quick` unchanged and extra-free; existing overlay dispositions unchanged.
- **Out of scope**: New pair corpora or Firefox/VFC harvest (`real-world-vfc-slice`); Joern CPG queries; inter-file or whole-program taint; buffer-size / CWE-121 semantics; language-model parse or taint; replacing pattern inventory.
- **Adjacent expectations**: `propose-adjudicate-prove` still owns dispositions, facts, taint rules, and prove-budget. `three-stage-scan` still owns `quick` / `standard` / `deep` and the sandbox. This spec only supplies the structured parse those stages already asked for.

## Requirements

### Requirement 1: Core install and quick stay extra-free

**Objective:** As a developer or CI job, I want `quick` inventory with no optional packages, so that a default install never pulls parser wheels.

#### Acceptance Criteria

1. When OpenUltraSAST runs a `quick` scan, the system shall emit inventory proposals without requiring the semantic extra.
2. The system shall not require the semantic extra to be installed in order to import or run the default OpenUltraSAST command.
3. If the semantic extra is absent, then a `quick` scan shall still complete and shall not abort because a parser package is missing.

### Requirement 2: Extra enables structured parse on in-scope languages

**Objective:** As an AppSec engineer with the semantic extra installed, I want overlay to read JavaScript, C/C++, Java, and Python as structured source, so that those files can be promoted or demoted instead of left unsupported.

#### Acceptance Criteria

1. Where the semantic extra is installed and a grammar for the file’s language is available, when OpenUltraSAST runs a `standard` or `deep` scan, the system shall use that structured parse as the primary intra-file input to overlay adjudication for Python, JavaScript, C, C++, and Java.
2. When a JavaScript file contains `eval` of a request query (or the language-equivalent untrusted source to a known sink) and the extra provides a JavaScript grammar, the system shall be able to emit a `promote` overlay disposition for that proposal.
3. When a C or Java file contains a sink fed only by a constant or a dominating sanitizer (for example a literal format string to `printf`) and the extra provides a grammar for that language, the system shall `demote` that proposal rather than leave it `language_unsupported`.
4. The system shall feed the structured parse into the existing overlay dispositions (`promote`, `demote`, `unadjudicated`, `coverage`) and shall not introduce a new disposition.

### Requirement 3: Missing extra or grammar fails closed

**Objective:** As an operator without the extra or without a grammar for one language, I want honest `unadjudicated` outcomes, so that silence is not reported as safety.

#### Acceptance Criteria

1. If the semantic extra is not installed, then when OpenUltraSAST adjudicates a JavaScript, C, C++, or Java file, the system shall leave matching inventory proposals `unadjudicated` with `language_unsupported` or `parse_failed`.
2. If the extra is installed but no grammar is available for that file’s language, then the system shall leave those proposals `unadjudicated` with `language_unsupported` or `parse_failed` and shall not crash the scan.
3. When the extra is absent, the system shall still try a stdlib parse only for Python and shall otherwise follow the fail-closed rule in criterion 1.
4. If a file cannot be parsed even with a grammar present (syntax error or incomplete source), then the system shall leave matching proposals `unadjudicated` with `parse_failed`.
5. The system shall not treat a missing extra as a failed `standard` scan by itself.

### Requirement 4: One parse path, no hand-rolled language visitors

**Objective:** As a maintainer, I want a single structured-parse path for all in-scope languages, so that we do not grow a new visitor per language.

#### Acceptance Criteria

1. When the extra supplies grammars for more than one in-scope language, the system shall extract overlay parse facts (assignments, calls, constants) through one shared structured-parse path rather than a separate visitor per language.
2. The system shall not add a new language-specific stdlib or regex AST as the product parse engine for JavaScript, C, C++, or Java.
3. Where a host parser CLI is present but the semantic extra is not, the system shall not claim a successful structured parse for overlay unless the extra’s grammar actually produced one.

### Requirement 5: Overlay and stages stay in their existing contracts

**Objective:** As an operator, I want the extra to change who can be adjudicated, not what a disposition or stage means, so that prove-budget and fail-on rules stay honest.

#### Acceptance Criteria

1. The system shall not use a language model as the parse or taint engine.
2. The system shall not require Joern for the semantic extra to succeed.
3. When overlay promotes or demotes from a structured parse, the system shall keep that result at `static_corroboration` or below.
4. The system shall not select sandbox candidates from demoted or unadjudicated findings solely because a structured parse ran.
5. The system shall not fold overlay Youden or extra-install status into the stage-1 detection gate (`python -m openultrasast.gate`).

### Requirement 6: Extra present and extra absent are both testable

**Objective:** As a maintainer, I want CI to prove both the extra-free core and the extra-enabled overlay, so that default install and AppSec install cannot silently diverge.

#### Acceptance Criteria

1. When the test suite runs without the semantic extra, the system shall still pass the extra-free `quick` and fail-closed overlay checks in Requirements 1 and 3.
2. Where the semantic extra is installed in a test environment, the system shall exercise Requirement 2 for at least one JavaScript file and at least one C or Java file.
3. If a test environment lacks the extra, then the suite shall skip extra-enabled checks rather than fail the extra-free core.
