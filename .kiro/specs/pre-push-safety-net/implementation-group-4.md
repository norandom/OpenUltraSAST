# Group 4 implementation and verification

Date: 2026-09-13. The maintainer authorized group 4 as a whole. Scope is tasks
4.1–4.3: targeted novelty comparison, actionability admission and compact reporting.
Groups 1–3 are verified at `6ba2b06`; full transaction replay remains task 5.1.

Status: implementation in progress. Task completion requires independent review
and fresh evidence. No production capability is enabled for normal hook alerts;
capability admission still requires task 8.3 evaluation.

## Verification boundary

Exercise production policy functions with immutable Git snapshots and actual engine
answers, plus deterministic error-path and equivalent-origin controls. Prove source
bytes were read before interpreting empty answers. Synthetic evaluated capabilities
exercise admission mechanics only and never establish real capability eligibility.
The established gates protect detector regressions; these controls do not establish
production hook latency, broad alert precision or feature-level readiness.

## Task 4.1 verification

VERIFIED (TASK scope), independent review APPROVED. Full suite: 1,167 passed,
nine skipped in 122.44 seconds; global Ruff/format (233 files), mypy (110 source
files), all three regression gates and diff checks passed. The first OFF control
failed on novelty behavior. Review regressions reproduced false NEW classifications
from wrong-mechanism base rows and non-string operations; both now stay unknown.

`benchmarks/measurements/2026-09-13-delta-comparison-smoke.json` records actual
JavaScript guard removal as worsened, unchanged backlog moved by comments as
unchanged, and a PHP source newly connected to a mapped unchanged sink as new.
All inputs were read and both sides' questions completed. Current reviewed policy
was independently rechecked against captured actual answers after the schema-only
repair; the artifact preserves exact source hashes and that narrower provenance.
Concurrent lab costs were 214.81, 214.52 and 291.01 seconds respectively under
900-second budgets. These are not hook latency measurements.

Automatic dominance-only change-context projection remains an explicit upstream
limitation for the later replay integration. These controls use declared questions
and Git context directly; no missing-coverage result was erased. Ambiguous source
and identifier changes remain unknown. Task 4.1 brings progress to 12/27 tasks;
admission and rendering remain pending within this authorized group.

## Task 4.2 verification

VERIFIED (TASK scope), independent review APPROVED. Full suite: 1,207 passed,
nine skipped in 99.04 seconds; global Ruff/format (235 files), mypy (110 source
files), detection/map/pair gates and diff checks passed. OFF admission controls
failed before implementation. Review reproduced a SQL witness acquiring shell advice
through a broad injection-family key; evaluated operation-symbol restrictions now
reject that mismatch, missing bindings, receiver changes and embedded-name matches.

Deltas bind exact base/head and semantics; unbound legacy records cannot be admitted.
Evaluation declarations retain calibration and untouched-population provenance and
must supply positive controls and reviewed alerts. Every disposition preserves its
evidence and matching declarations. Deduplication retains witnesses, locations,
refs and exact comparisons; unchanged debt on one comparison cannot erase a new
claim on another. Advisory and blocking share admission; coverage policy is separate.

`benchmarks/measurements/2026-09-13-admission-policy-smoke.json` records current
policy against captured actual engine answers: all remain diagnostic with the empty
default registry. Explicitly synthetic PHP/WordPress and JavaScript/Express controls
receive equivalent admission and enforcement behavior. They do not qualify any
real capability; task 8.3 still owns actual eligibility. Task 4.2 brings progress to
13/27 tasks. Compact reporting remains in this authorized group.
