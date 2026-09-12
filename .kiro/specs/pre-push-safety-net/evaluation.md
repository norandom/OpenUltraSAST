# Evaluation: core optimization and cross-language transfer

Status: evaluation contract accepted with requirements/design for task generation, 2026-09-12. Implements requirements 6.1–6.5 and 8.1–8.4.
No new repository has been pinned, scanned or admitted by this document.

## Workload roles

| Workload | Role | Required evidence |
|---|---|---|
| Existing pinned PMPro | Primary development and cost-attribution example | Known CVE retained; fixed/benign controls; total build/evidence/query cost |
| Existing WP Statistics and MW WP Form | PHP structural regressions | Hook/field flows preserved; vendor exclusion does not become a ranking trick |
| JavaScript/Express Node API | Required transfer and hook integration workload | Same frozen core; route/middleware/handler/service context; vulnerable/fixed/benign changes |
| Separate untouched Node API repository | Generalization evaluation | Predeclared labels/population; no tuning on its results; all misses and gaps retained |
| Existing pinned VAmPI | Python and authorization regression | Actual transitive SQLI witness plus obligation findings; no omitted position targets |
| Existing pinned libpng | C graph/cost and capability-limit control | Envelope measured; unsupported arithmetic/bounds explicitly reported |
| Future C or C++ positive control | Additional abstract-property transfer | Reviewed vuln/fix for a supported property; C++ frontend behavior verified independently |

## Recommended JavaScript starting point

**OWASP NodeGoat is the proposed first Express wiring/teaching candidate.** It is a deliberately
vulnerable Node application with remediation teaching material, and its package manifest declares
Express. It exercises server-side code without making an entire browser application the primary
measurement unit. [Project](https://github.com/OWASP/NodeGoat),
[package manifest](https://github.com/OWASP/NodeGoat/blob/master/package.json).

This is candidate selection, not detection evidence. Before adding an executable recipe, pin an
immutable commit, verify readable source/license bytes, identify the exact affected operation and
its caller context, and review the vulnerable and fixed forms. An authored repair must be labeled
as authored; do not present it as an upstream CVE fix. Do not assume the tutorial's vulnerability
categories correspond to supported arbiters: a MongoDB operator-injection case is not automatically
covered by SQL string-taint facts. Select a supported positive control and retain other cases as gaps.

NodeGoat is intentionally educational and will be inspected during integration. It cannot establish
production generalization on its own. Its inspected manifest uses an older Express 4 dependency
range; it is not evidence of coverage for current module/async/framework patterns. Require those
patterns in the additional Node workload and record its exact versions. Reserve an independently selected Node API repository with
reviewable security-fix history before the transfer result is used to tune the core. Selection must
not depend on getting a favorable scanner score. No npm installation or project execution is needed
to establish the static input; runtime controls, when needed, belong in a separate controlled harness.

## Paired changes and negative controls

1. Request input crosses route -> imported handler -> service -> supported dangerous operation;
   a correct family-specific repair stops the finding on the fixed side.
2. A removed authorization/ownership guard exposes an unchanged operation. A guard that is present
   but does not govern the operation must not discharge it; correctly ordered governing middleware must.
3. Callback/async data transfer preserves a supported source-to-operation witness. Unresolved dynamic
   calls are counted as a context gap, not silently treated as no flow.
4. Input validation for an unrelated context does not cleanse SQL/command/path operations. Path
   normalization alone is not assumed to establish confinement to an allowed root. Test both the
   real repair and a plausible but insufficient repair.
5. Benign refactoring, renaming, formatting, parameter binding and unaffected backlog do not generate
   new hook alerts. Retain benign push counts so low noise cannot be inferred only from security cases.
6. `node_modules` and other declared vendor files are absent from both graph and targets, with
   first-party callers still represented. Missing external semantics remain visible coverage limits.

Do not force all these shapes into one repository. Keep authored cross-language contract tests
separate from reviewed repository changes, and preserve their provenance in the scorecard.

## Freeze, transfer, classify

1. Freeze core ranker features/weights, arbiter/query semantics, engine version, budget, and existing
   framework facts after the PMPro experiment. Run Node with available adapters first; save that result.
2. Classify each miss before changing anything: unread input/instrument failure, frontend normalization,
   missing framework fact, ranker scope/budget, wrong abstract semantics, or unsupported abstract domain.
3. If a framework fact or frontend adaptation is needed, review it separately and rerun both languages.
   Report adapted transfer separately from the unchanged-core result. A core change starts a new
   version and requires a fresh untouched evaluation; it is not hidden in a "JavaScript config" label.
4. Compare actual findings, fixed-side silence, actionable precision, benign interruptions, coverage,
   and elapsed cost together. Equivalent normalized evidence must produce identical core tier/score
   results; equivalent syntax across languages is not required and is not presumed.
5. Do not generalize a C envelope result to C/C++ detection. Select a positive control only after its
   property fits a declared arbiter; numerical bounds/overflow needs a suitable domain and separate
   validation. Do not expand taint sources or sanitizer names to simulate arithmetic reasoning.

## First bounded implementation experiment

Replay one supported PMPro change/fix and one Node/Express change/fix through the same ranker,
graph exclusion policy, deadline and admission contract. Add at least one benign change per workload.
Produce one joint scorecard before any further core optimization. A missing Node frontend, broken
middleware mapping or wrong sanitizer model is an explicit finding of this experiment, not a reason
to remove Node from the evaluation or silently fall back to a PHP-only release claim.
