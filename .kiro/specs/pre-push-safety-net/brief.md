# Brief: pre-push-safety-net

Status: requirements, design and tasks approved; groups 1–7 implemented and verified (23/27 subtasks). Compatible preparation/graph/query reuse is demonstrated, including packaged JavaScript evidence equivalence. Group 7 adds multi-ref Git input, non-destructive opt-in hook integration and bounded optional witness selection. Group 8 pending. Rollout remains NO-GO: changed-code feasibility and independent capability qualification are not established; normal capabilities remain disabled. Language: English.

## Problem

AI increases the rate of code changes. Developers need a bounded pre-push check that catches
actionable security regressions without a recurring queue of speculative SAST warnings. The
maintainer explicitly rejects noisy advisory output as well as noisy blocking output.

## Current State

The existing ranker, Joern arbiters, immutable replay, change comparison, actionability policy
and absolute deadline are integrated. Vendor code is physically excluded from frontend graphs
and targets. Explicit local caching reuses complete discovery, validated isolated graph copies
and compatible query evidence while reapplying current admission. Changed source/declarations
invalidate affected graph units; no incremental Joern mutation is implemented.

Group 5's PMPro/Node cold experiment remains NO-GO. Group 6 adds a packaged JavaScript
correctness control with equal cached/uncached evidence and admission; an identical-revision
hit is fast, while the changed-code deadline remains a separate unmet gate. Automatic
context projection and independent capability eligibility remain explicit limits. See
implementation-group-6.md and the committed reuse control evidence. Historical whole-PMPro
ranking costs and manually selected CVE slices do not establish automatic push latency.

## Desired Outcome

A developer pushes committed code and receives either a concise actionable security finding or a
bounded result with explicit coverage. Unrelated working-tree changes, backlog findings, and model
speculation do not become push warnings. The same analysis can be invoked explicitly for diagnosis.

## Approach

Resolve pushed snapshots, feed changed and affected first-party context to the existing ranker,
reuse compatible results, and run admitted detector capabilities within a total deadline. The ranker
remains the scope mechanism. Exclude third-party vendor code from targets AND graphs as already decided.
Compare relevant base/head evidence
before calling a defect new. Apply a separate actionability policy after arbitration. Evaluate on
security and benign changes across repositories/frameworks, with cold and warm caches separated.

## Scope

- In: resulting pushed tips, affected context, caching, bounded execution, change-related actionable
  alerts, coverage status, optional enforcement, evaluation and reproducible local artifacts.
- Out: every historical commit introduced by a push, whole-repository certification, style rules,
  dependency-vulnerability inventory, automatic source edits, mandatory cloud/LLM services,
  prompt optimization, and new memory-safety abstractions.

## Boundary Candidates

One product boundary owns the pre-push transaction from Git input to user outcome. It consumes the
existing ranker's scope and analysis engine through explicit scope/budget/results contracts. Reusable ranking and
family semantics remain with their existing specs rather than being reimplemented in the hook.

## Upstream / Downstream

- Upstream: `contributor-scan` engine/packaging/family correctness; existing facts and rungs.
- Adjacent: `flow-aware-ranking` schedules work; `zero-with-a-reason` diagnoses missing work;
  `finding-feedback-loop` owns durable human review and later learning.
- Downstream: developer pre-push workflow and explicit local/CI replay of the same snapshot contract.

## Constraints and Initial Evaluation Targets

- User direction: actionability and low noise are mandatory in every mode.
- Proposed rollout: advisory first; blocking is explicit opt-in after per-capability validation.
- Proposed latency experiment: 30-second warm-push p95 on a declared reference workload/hardware,
  with a configurable deadline and 2-second cancellation/report allowance. This is an unproven
  design target, not a demonstrated SLA. Cold runs use the same deadline and disclose incompleteness.
- No promise of all-language coverage; capabilities are admitted per language/framework/family.
- Initial work must establish feasibility and noise before investing in an LLM ranker.

## Cross-language amendment — 2026-09-12

Keep PMPro as the primary worked optimization example, and require a JavaScript/Express/Node API
transfer experiment before claiming the core improvement generalizes. Abstract evidence, ranking,
scope and arbitration contracts remain shared. Language/frontend/framework facts supply concrete
semantics; missing semantics remain a stated limit. Do not add PHP-specific core ranking shortcuts.

See `evaluation.md` for the proposed workload matrix: NodeGoat as an Express wiring/teaching
candidate, a separate untouched Node API repository, existing Python regressions, and libpng as
a C envelope/limit control. C/C++ detection is measured only for a labeled property the chosen
abstraction can decide; bounds reasoning is not inferred from successful taint analysis.
