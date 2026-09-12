# Research and design decisions: pre-push-safety-net

## Summary

- Date: 2026-09-12. Discovery scope: complex integration of the existing ranker and detector with Git.
- User direction: a scalable pre-push safety net as AI accelerates development; WordPress is one case.
- Clarifications: advisory must be actionable, not SAST noise; the ranker is the scope mechanism;
  third-party vendor code must remain outside targets and graphs.
- Requirements, design and tasks are now approved, and group 1 implementation is verified complete; see
  `tasks.md` for verified completion. The discovery log below preserves the earlier drafting state
  and measurements. No hook latency claim is made.

## Research Log

### Repository state and measurement limits

Reviewed through `a8069ac`, including `60963f5` (overlay reuse/scoped seeds), `9f881b4`
(closure workaround bounded by upstream version), `60d13d7` (evidence ordering), `3b3b96b`
(parser-script readability probe), `b821ac6` (layout), and the latest ranking baselines.

| Workload | Original position budget | 4.0.625 + layout budget | Build / evidence seconds |
|---|---:|---:|---:|
| PMPro | 391 | 82 | 129.9 / 295.7 |
| WP Statistics | 504 | 91 | 45.4 / 68.7 |
| MW WP Form | 513 | 54 | 45.2 / 80.3 |
| VAmPI | 16 | 16 | 5.6 / 18.4 |

Source: `benchmarks/ranking/baselines/2026-09-11-evidence-rank-layout.json`, read and parsed during
the review. All four recorded `pairs_unanswered=0`; these are historical artifacts, not fresh runs.
WP Statistics's scope shrank after vendor removal. VAmPI's transitive SQLI target is excluded from
the position budget, so the value is not verified all-target recall. A 72-minute whole-PMPro scan
recorded in `flow-aware-ranking/brief.md` demonstrates a finishing scan, not hook feasibility or
precision of its 250 entailed findings. The focused review run passed 87 existing tests; it did not
rebuild Joern graphs or evaluate hook behavior.

The latest ranker head has 67 strictly higher-scored same-tier regions ahead of PMPro's CVE and
85 ahead of WP Statistics's. Reordering equal scores alone cannot beat budgets 68 and 86. MW WP
Form has 39 strictly higher-scored regions, so its corresponding lower bound is 40. These are
arithmetic bounds from the stored head, not a measured new ranking algorithm.

### Existing seams

- `preprocess.py:preprocess_repository` reads filesystem bytes and then records HEAD; snapshot
  identity must be established before calling this path for a push.
- `model/scan.py:scan_repository` builds a graph before applying `max_regions`. Its evidence order
  is experimental and `cli.py` currently does not enable it. Region budget is not graph cost.
- `model/layout.py` supplies vendor exclusions and test/shipped classification. Preserve it.
- `cpg/backend.py` has process-group cancellation, census and parser readability checks, but fresh
  temporary graphs and per-command rather than per-push deadlines.
- `cli.py` samples unjudged paths by slicing the original region order; the new contract must return
  exact selected/deferred IDs from the ranker/driver instead of reconstructing them by count.
- `model/specs.py:taint_specs` still flattens sanitizers across a language. Contributor task 5.6 is
  a prerequisite to admitting capabilities whose correctness depends on context-specific cleansing.
- `reports.py:scan_exit_code` has broad scan policies; the hook needs an independent admission and
  coverage decision, without changing the meaning of ordinary scan output.
- Docker, Compose and ops default to 4.0.623, whereas the evaluated baseline is 4.0.625.

### Git contract

Git supplies ref-update lines to pre-push and uses its exit status to allow or abort the operation.
The design consumes the supplied object identities and handles creation/deletion explicitly; it
does not infer the pushed tree from the checkout. [Official hook contract](https://git-scm.com/docs/githooks#_pre_push)

Use machine-readable diffs between recorded snapshots, with rename/deletion attribution and
NUL-delimited paths. A chosen new-branch comparison base is recorded separately from a previous
remote tip. [Official diff documentation](https://git-scm.com/docs/git-diff)

### Graph reuse and slicing

Joern documents data-flow and usage slices extracted from a CPG; data-flow slicing can itself be
expensive. This does not establish cheap incremental updates to a changed source tree. The design
therefore reuses exact compatible artifacts and rebuilds changed units, with latency as an explicit
feasibility gate. [Official CPG slicing documentation](https://docs.joern.io/cpg-slicing/)

## Architecture Pattern Evaluation

| Option | Benefit | Limitation | Decision |
|---|---|---|---|
| Whole scan on every push with a better ranker | Reuses current driver | Graph build precedes rank selection; measured costs exceed a short hook | Baseline/control only |
| Changed-file-only graph | Small apparent input | Can lose unchanged callers, guards, fields and dispatch context | Reject as a completeness claim |
| Ranker scope + first-party graph reuse + total deadline | Preserves current architecture and explicit vendor boundary | Changed graph units still rebuild; speed must be measured | Proposed |
| New incremental graph engine or mandatory daemon | Potential reuse across edits | Unverified backend semantics and additional lifecycle complexity | Defer until measurements require it |

## Design Decisions

1. **Preserve scope ownership.** Change context is input to the existing ranker, not a new selector.
   The push layer executes its decisions and records deferred work. Vendor code never returns as
   a side effect of context expansion. Unknown vendor behavior uses declared summaries or remains unresolved.
2. **Separate claim from interruption.** Existing rungs describe analysis evidence. Hook admission
   additionally requires evaluated capability, change attribution and actionability. This meets the
   user's low-noise requirement without pretending an LLM confidence score proves a bug.
3. **Compare evidence, not just finding lists.** A missing base finding can mean truncated analysis.
   Targeted comparable base checks are required for novelty, including removed-guard cases.
4. **Adopt Git and the existing engine.** Build only the push transaction, cache and admission adapters.
   Do not add an IR, database or service merely to describe future scale.
5. **Measure honest warm work.** Repeating an identical tip is a cache-hit control; warm changed-code
   pushes are the product workload. Separate both from cold builds and dependency/configuration changes.

## Risks and review decisions

- Proposed 30-second target and enforcement defaults await review; neither is inferred user approval.
- Exact graph reuse may help repeated pushes more than everyday edits. The feasibility experiment
  must expose this and can stop rollout; timeout notices alone do not make a useful safety net.
- Initial high-precision admission can lower recall. Joint recall/coverage/noise gates prevent
  suppressing everything from masquerading as success.
- Unknown dynamic and cross-language edges remain real limits; ranking cannot manufacture context.
- Existing inspected plugins are not fresh holdouts. Fix scope and evaluation before another tuning cycle.

## Review record

### Cross-language clarification

The maintainer explicitly retained PMPro as the core optimization example and requested transfer
to common JavaScript/Node APIs (Express in particular), with C/C++ as a useful additional example.
Added requirement 8 and the Language and Framework Contract to make agnostic analysis testable.
`evaluation.md` separates development, framework integration, untouched evaluation and C envelope
roles. NodeGoat is a proposed Express integration candidate, not a pinned or measured workload.

Local inspection found existing request sources and eval/exec/query/path/outbound sinks in
`ruleset/semantic/javascript.toml`, JavaScript obligation facts, and Express-style route/middleware
mapping in `mapping.py`. This establishes reusable implementation seams, not passing end-to-end
coverage. The five current repository recipes contain PHP, Python and C workloads but no JavaScript
recipe. Existing `libpng.toml` explicitly marks its bounds CVE out of scope and measures only envelope.
That distinction is preserved. No new core algorithm, frontend or recipe is implemented here.

Fresh amendment validation read the six current spec documents, confirmed 35 unique EARS criteria
with explicit design traceability, parsed the amended metadata, and checked the cross-language and
vendor contracts. The command and `git diff --check` both exited 0. This validates documents only;
Node/Express transfer remains the proposed experiment, not a measured result.

### Earlier validation

Fresh document validation read all five spec files, parsed metadata, checked all 31 unique EARS
criteria against design traceability, and confirmed populated boundary/file/testing sections.
An initial mechanical check rejected two criteria starting with "Before"; both were rewritten as
event-driven EARS statements and the repeated check passed (exit 0). `git diff --check` passed.
Existing contributor/ranker approval fields were compared with HEAD and remained unchanged;
new requirements/design approvals remain false. Stored ranking-head arithmetic independently
reproduced the equal-score tie bounds of 68, 86 and 40.

The content review checked boundary ownership, failure handling, vendor exclusion, ranker scope,
and independent finding/coverage/push status. Draft defaults remain clearly labeled. Runtime
integration, performance and capability admission remain unverified work; no code tests were
needed for these documentation-only amendments.
