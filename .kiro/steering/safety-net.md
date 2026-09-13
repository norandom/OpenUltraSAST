# Product direction: a security safety net before push

Updated 2026-09-12 from the maintainer's explicit direction. This direction supersedes the
WordPress-first release framing in older steering; historical measurements remain historical.

## Purpose

AI accelerates code production. OpenUltraSAST should help developers catch concrete security
regressions before pushing, with enough evidence to understand and repair them. It is also a
teaching system for understanding what abstract analysis can establish and where it stops.

The maintainer's acceptance criterion is an actionable safety net, not a code nag. Advisory mode
does not lower the evidence bar. A nonblocking stream of speculative findings still fails the product.

## Product principles

- Make new or worsened security defects visible; do not repeatedly present unrelated backlog.
- Every normal hook alert needs a supported security claim, a connection to the proposed change,
  an exact location, and a concrete repair direction. A confidence label alone is insufficient.
- Keep suspicion and uncalibrated detector output in opt-in diagnostic artifacts.
- Separate finding disposition from coverage. An incomplete scan gets a concise operational notice,
  not a fabricated vulnerability or a clean verdict. Silence is bounded by the recorded scope.
- The ranker is the scope mechanism: it selects and orders the regions/questions receiving analysis.
  Change information supplies its context; there is no second heuristic scope selector in the hook.
  Ranking never establishes a defect or earns permission to alert.
- Third-party vendor code is excluded from both analysis targets and graphs. This is an explicit
  product boundary. Flows requiring its internals need declared summaries or remain unresolved;
  context expansion must not silently reintroduce vendor sources.
- Preserve vulnerability-family semantics: escaping for one context does not discharge another.
- Reuse results only when code, context, analysis semantics, and scope still match.
- A push deadline covers all work, including snapshot preparation, graph construction, retries,
  queries, optional model calls, and reporting. A region count is not a runtime bound.

## Scope and evidence

PMPro remains the primary worked example for core optimization. JavaScript/Node APIs, especially
Express routing and middleware, are a required transfer workload alongside Python; they must not
be deferred until a PHP-specific implementation has hardened. Polyglot repositories and common
injection, path, authorization, and configuration scenarios belong in the evaluation according to
demonstrated capabilities. Parsing a language does not imply support for its security properties.
C/C++ supplies an additional shared-machinery and abstraction-limit workload; C bounds/arithmetic
reasoning remains a separate abstraction question.

Language-agnostic analysis is an architectural requirement: frontends and versioned framework facts
map concrete code to shared sources, sinks, carried values, guards/obligations, configuration values
and evidence. Core ranking, scope selection and arbitration consume those contracts. No PMPro paths,
WordPress API names, Express method names or language-specific score boosts belong in core ranking.
Equivalent normalized evidence must produce equivalent core tier/score decisions. This is a contract
to verify, not an assumption that every frontend already produces equally complete graphs.

Optimize on PMPro, freeze the core, and measure transfer to Node/Express before further tuning.
Report changes needed in framework facts separately from core changes. Once an example informs a
change it becomes development/regression data; keep a separate untouched repository for evaluation.

Measure precision and actionability of alerts, recall on labeled security changes, fixed-side
silence, benign-push interruption rate, completed coverage, and cold/warm latency. Report sample
counts and uncertainty. More findings or a better rank position is not product success.

Keep the repeatedly inspected plugins as regression workloads. Evaluate new ranking or alert
policies on untouched repositories and benign changes as well. A policy that suppresses all alerts
does not pass: useful recall and coverage are required alongside low noise.

## Specification boundaries

- `pre-push-safety-net`: immutable pushed snapshots, ranker integration, reusable results, total budget,
  change attribution, actionability admission, and concise hook behavior.
- `contributor-scan`: reusable scan driver/backend, family correctness, packaging, repository validation.
- `flow-aware-ranking`: reusable scheduling of questions and honest ranking experiments.
- `zero-with-a-reason`: broader pipeline diagnostics; the hook consumes concrete coverage information.
- `finding-feedback-loop`: review ledger, dismissals, and later feedback-driven evolution.

The hook does not require an LLM ranker or an optimizer. Start with the existing detector, earn
alert admission per capability, and add scheduling sophistication only when it improves the measured
developer outcome. Do not rebuild a custom IR, add a second engine, or assume incremental Joern
updates as a shortcut to an unmeasured latency promise.

## Approval state

The product direction above is user-requested. The amended requirements, design and initial
evaluation profile in `pre-push-safety-net` were approved for task generation on 2026-09-12
("ok, next kiro phase"). The maintainer then approved the task plan and starting group 1
("approve.") and then group 2 ("ok, next kiro phase, approved"). Groups 1–4 are now verified
complete (14/27 total), including the approved frontend-retention prerequisite.
Group 4 adds bound novelty, operation-specific admission and compact artifacts;
4.1/4.2 passed independent review and 4.3 used the documented Kiro manual fallback
after agent dispatch became unavailable. Group 5 is next for full replay and the
first bounded experiment. Task completion still requires review and fresh evidence.
Real capability eligibility, automatic dominance context projection and hook
performance remain unproven; the default capability registry is empty.
