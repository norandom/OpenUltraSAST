# Implementation Plan

- [ ] 1. Foundation: call graph and reachability
- [ ] 1.1 Collect imports into FileIR and build a name-resolved call graph
  - `FileIR` gains an additive `imports` field filled by both the CST walker and the stdlib Python parse.
  - Graph nodes are functions; edges resolve same-file, imported-module, ambiguous (one edge per definition, capped), or unresolved; no call is dropped.
  - Observable: a three-file fixture yields exact, import, ambiguous, and unresolved edges with the expected counts; extra-free Python still builds a graph.
  - _Requirements: 1.1, 1.2, 1.4, 1.5_
  - _Boundary: CallGraph_

- [ ] 1.2 Compute bounded distance and witness paths from entry points
  - BFS from entry-point functions to a configured depth; each reached node gets distance and one witness path; unreached nodes have no distance and are reported as unknown.
  - Graph, distances, and unresolved count are written as a run artifact in MAP without executing target code.
  - Observable: on the split-sink Python fixture the planted function has a finite distance and a witness path through the route; `callgraph.json` exists after a standard scan.
  - _Requirements: 1.3, 1.6, 3.6_
  - _Boundary: CallGraph_
  - _Depends: 1.1_

- [ ] 2. Core: summaries and path records
- [ ] 2.1 Summarize each function with the existing taint engine
  - Summary states parameter-to-sink, parameter-to-return, and constant-dominated parameters; keyed by source hash and facts version; cached.
  - Observable: a function that forwards its parameter into `execute` reports param 0 to that sink; a function returning its parameter reports param 0 in param_to_return; a second run reuses the cache.
  - _Requirements: 2.1_
  - _Boundary: Summaries_
  - _Depends: 1.1_

- [ ] 2.2 Compose summaries along the graph into path records
  - Tainted arguments extend a path into a callee whose summary reaches a sink; return taint flows back to the caller; unresolved callees or depth exhaustion mark the path incomplete at that hop; composition never demotes.
  - Path records carry entry, hops, sink, sink line, summaries used, and open questions; written as `paths.json`.
  - Observable: a route in one file calling a helper in another that executes a query yields one complete path; cutting the helper's definition yields an incomplete path, not silence.
  - _Requirements: 2.2, 2.3, 2.4, 2.5_
  - _Boundary: Summaries, Paths_
  - _Depends: 2.1, 1.2_

- [ ] 3. Integration: reachability consumers
- [ ] 3.1 Attach graph reachability to findings, rank, and the complexity map
  - A finding inside a function with finite distance is reachable with distance and witness in its evidence; no distance stays unknown; rank uses distance when present and records it; map gains path count and minimum distance signals without using them as the sole score.
  - Observable: a sink in a helper two calls below a route becomes reachable; rank rationale shows graph_distance; the map order on split-sink still differs from hit-count order.
  - _Requirements: 3.1, 3.2, 3.3, 3.4_
  - _Boundary: ReachabilityAttach_
  - _Depends: 1.2_

- [ ] 3.2 Feed worth-fixing and extend the map gate with a path check
  - Worth-fixing accepts graph-reachable findings; the split-sink map gate additionally asserts a path from a planted entry to a planted function per language family.
  - Observable: a triggerable fake-sandbox verdict on a graph-reachable helper is worth fixing; map gate passes with the new assertion; existing assertions unchanged.
  - _Requirements: 3.5, 3.6, 8.1, 8.3_
  - _Depends: 3.1, 2.2_

- [ ] 4. Integration: hunter on paths
- [ ] 4.1 (P) Add the path_context tool and a path-scoped prompt
  - The hunter can request one path by id and receives entry, hops, sink, summaries, guards (empty for now), and open questions; when paths exist the prompt asks for a verdict and a proposed input on that path.
  - Path context counts toward the existing step and cost budgets.
  - Observable: a scripted client that calls path_context and returns a finding yields a suspicion finding tagged with the path id; a client that ignores the path still works as today.
  - _Requirements: 4.1, 4.2, 4.5_
  - _Boundary: HunterPaths_
  - _Depends: 2.2_

- [ ] 4.1b (P) Resolve the hunter client through HarnessX when the extra and `[harnessx]` provider are present
  - `resolve_hunter_client(prefer_harnessx=..., harnessx_provider=..., model=...)` prefers a HarnessX provider adapter (its own credentials) and falls back to the OpenAI-compatible endpoint (`OPENROUTER_API_KEY` + `OPENROUTER_BASE_URL`, e.g. DeepSeek); the adapter must not use `asyncio.run` on non-coroutine awaitables.
  - Observable: with the extra absent the resolver returns the OpenRouter client; with a scripted provider object the adapter yields a ChatResponse; the pairs `--hunter` scorer uses the same resolver.
  - _Requirements: 4.5_
  - _Boundary: HunterPaths_

- [ ] 4.2 Make hunter findings with a locatable sink eligible as sandbox candidates
  - A hunter finding whose line matches a path sink line or an overlay sink line becomes a forced hotspot after the safety check, ranked after overlay promotions, within the candidate cap; evidence stays suspicion until a sandbox trigger or a path agreement is recorded.
  - Observable: with the fake sandbox, a scripted hunter finding on a path sink runs and its verdict is recorded; a hunter finding with no locatable sink is not a candidate; evidence level is unchanged by eligibility alone.
  - _Requirements: 4.3, 4.4_
  - _Boundary: HunterPaths_
  - _Depends: 4.1_

- [ ] 5. Integration: fact oracle and facts lever
- [ ] 5.1 (P) Record open questions and ask a model only when configured
  - Composition records closed-kind questions at unresolved or unsummarized hops; when a model is configured the oracle asks with redacted callee context and appends candidate facts with model id, context hash, and timestamp; idempotent per key; no model means questions are listed in the manifest.
  - Observable: a scripted client answering nullable_return produces one candidate fact; a second run does not duplicate it; with no client the manifest lists the open question; no target code runs.
  - _Requirements: 5.1, 5.2, 5.3, 5.5, 5.6_
  - _Boundary: FactOracle_
  - _Depends: 2.2_

- [ ] 5.2 Load accepted facts below hand-written facts
  - The fact loader merges an accepted-facts file after the hand-written directory; collisions keep the hand-written row and record a degradation; candidate facts are never loaded.
  - Observable: an accepted nullable fact is visible to adjudication; the same id in a hand-written file wins; a candidate-only fact is invisible.
  - _Requirements: 5.4, 6.5_
  - _Boundary: FactOracle_
  - _Depends: 5.1_

- [ ] 5.3 Add the facts lever to the improve loop under the existing gate
  - A facts edit accepts or retracts a candidate fact; the validator allows only closed kinds sourced from the cache or a benchmark signal and never retracts hand-written facts; the existing accept gate and the per-profile holdout clause decide; rejection reverts the accepted file byte for byte; the journal records the edit and metrics.
  - Observable: a scripted candidate fact that turns a missed pair into a pass on holdout is accepted and persisted; one that regresses a profile is rejected and the file is unchanged; a pattern-text edit is rejected by the validator.
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_
  - _Boundary: FactsLever_
  - _Depends: 5.2_

- [ ] 6. Integration: fix points
- [ ] 6.1 Compute fix points as dominators and rank by risk removed
  - A node dominates a path when every route from its entry to its sink passes through it; risk removed sums policy severity weighted by evidence over dominated paths; written as `fixpoints.json`.
  - Observable: a diamond fixture where one helper sits on four paths ranks that helper first with four paths collapsed; a reachable severity-5 finding stays in the worth-fixing candidate set regardless of fix-point order.
  - _Requirements: 7.1, 7.2, 7.4, 7.5_
  - _Boundary: FixPoints_
  - _Depends: 2.2_

- [ ] 6.2 Report fix first
  - Markdown and manifest gain a fix-first section listing fix points with witness paths; labelled as estimates.
  - Observable: a standard scan report on the split-sink fixture contains the section; `--fail-on` behavior is unchanged.
  - _Requirements: 7.3_
  - _Depends: 6.1_

- [ ] 7. Validation
- [ ] 7.1 Measure labeled-function reachability on pair slices
  - For slices whose labels name a function, the pairs payload reports the fraction with finite distance; recorded in the roadmap next to the pair-corpus baseline.
  - Observable: `pairs --slice vibe-py --json` includes the fraction; the roadmap has the number.
  - _Requirements: 8.2_
  - _Depends: 3.1_

- [ ] 7.2 Prove gates unchanged and default tests offline
  - Detection gate, local pair gate, and existing split-sink assertions produce the same verdicts; extra-free suite green with graph assertions skipping; no default test uses a model, sandbox, or network.
  - Observable: gate entrypoints unchanged; pytest green in both matrices.
  - _Requirements: 8.3, 8.4, 8.5_
  - _Depends: 3.2, 4.2, 5.3, 6.2_

## Implementation Notes

- Guards on path records stay empty until `guard-dominance-regime`; the tool and record shapes reserve the field so that spec is additive.
- `oracle_enabled` defaults to false until the first accepted facts have been reviewed by a maintainer; open questions are still recorded.
- Do not change evidence stamps of existing sources in this spec; log the regex-as-corroboration question as a revalidation trigger for `propose-adjudicate-prove`.
- Expect more sandbox candidates once hunter eligibility lands; the existing `max_candidates` cap and heuristic order hold cost.
