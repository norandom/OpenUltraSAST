# Brief: pre-push-safety-net

Status: requirements, design and tasks approved; groups 1–4 verified complete (14/27 subtasks). Groups 5–8 pending; real capability eligibility and hook latency remain unproven. Language: English.

## Problem

AI increases the rate of code changes. Developers need a bounded pre-push check that catches
actionable security regressions without a recurring queue of speculative SAST warnings. The
maintainer explicitly rejects noisy advisory output as well as noisy blocking output.

## Current State

The scan driver and Joern arbiters exist, with demonstrated PHP/Python cases. Immutable push-tip
resolution, isolated source materialization and lexical change context are implemented and verified.
Ranker integration, persistent graph caching and an end-to-end deadline remain pending.
The driver builds a whole-root graph before cutting the region budget. The latest PMPro ranking
experiment alone spends about 130 seconds building and 296 seconds extracting evidence. A manually
selected two-file slice finding a CVE does not demonstrate automatic incremental analysis.

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
