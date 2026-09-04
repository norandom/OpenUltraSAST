# Implementation Plan

- [x] 1. Foundation: overlay vocabulary and fact data
- [x] 1.1 Define overlay records and fail-closed reasons
  - Dispositions are promote, demote, unadjudicated, coverage only.
  - Unadjudicated reasons are parse_failed, language_unsupported, flow_incomplete, facts_unavailable.
  - Demote is illegal without a recorded constant or sanitizer in the record.
  - Tests construct records and reject demote-without-reason.
  - Observable: a unit test fails if a demote record omits the dominating fact.
  - _Requirements: 3.5, 2.1, 2.2, 5.1_
  - _Boundary: OverlayRecord_

- [x] 1.2 (P) Load source, sink, and sanitizer facts as versioned data
  - Facts bind to CWE ids that already exist in policy.
  - Invalid or missing fact files yield facts_unavailable, not a crash of `quick`.
  - Observable: loading a broken fact file returns a structured error the overlay can attach to every proposal.
  - _Requirements: 5.5, 7.5_
  - _Boundary: FactStore_

- [x] 2. Semantic engines: tree-sitter first
- [x] 2.1 Probe tree-sitter like Docker and parse in-scope languages
  - Primary IR comes from tree-sitter when a grammar exists (Python, JS, C/C++, Java if present).
  - Missing CLI or grammar does not crash `quick`; those files become unadjudicated.
  - Stdlib Python parse is last resort only when tree-sitter is absent.
  - Observable: a JS `eval(req.query.x)` file yields IR when tree-sitter JS is available, and language_unsupported when it is not.
  - _Requirements: 8.1, 8.2, 8.5, 8.6, 2.1_
  - _Boundary: FileIR_
  - _Depends: 1.1_

- [x] 2.2 (P) Probe Joern as an optional CPG sidecar
  - Joern facts may add paths; Joern missing or incomplete must not demote.
  - `quick` and `standard` succeed without Joern.
  - Observable: with Joern absent, overlay still runs; a Joern-only miss does not turn a tree-sitter promote into demote.
  - _Requirements: 8.3, 8.4, 8.5_
  - _Boundary: JoernSidecar_

- [x] 2.3 Follow one-hop assignments and call arguments on the IR
  - Cover `bar = param`, f-string or concat into `sql`, then `execute(sql)`, in Python and the equivalent JS/C patterns the facts describe.
  - Incomplete callees mark flow_incomplete, not safe.
  - Observable: split-sink Python fixture yields a source-to-sink path; a call into a missing module does not.
  - _Requirements: 2.2, 3.1, 3.4, 2.5_
  - _Boundary: TaintEngine_
  - _Depends: 2.1, 1.2_

- [x] 3. Adjudicate inventory proposals
- [x] 3.1 Promote, demote, and leave unadjudicated
  - Every inventory proposal for a considered file appears exactly once.
  - `eval(request.args)` promotes; `eval("1")` demotes; unreadable file stays unadjudicated.
  - Observable: overlay output length equals proposal count for that file, plus coverage items only.
  - _Requirements: 1.2, 3.1, 3.2, 2.4, 3.5_
  - _Boundary: Overlay_
  - _Depends: 2.3_

- [x] 3.2 Emit coverage findings for uninventoried sinks with flow
  - Coverage stays at corroboration or below and is tagged overlay-originated.
  - No coverage item is stamped as worth-fixing or sandbox-proven.
  - Observable: `hashlib.new('md5')` with tainted input appears as coverage when facts include that sink and inventory missed it.
  - _Requirements: 3.3, 1.4, 1.5, 5.1_
  - _Boundary: Overlay_

- [x] 4. Integration: stages, prove filter, reports
- [x] 4.1 Run overlay in standard, not in quick
  - `quick` artifacts contain no dispositions.
  - `standard` attaches a disposition to each considered proposal without executing target code.
  - Observable: a `quick` run on a tiny tree has no overlay file; `standard` writes overlay artifacts.
  - _Requirements: 1.1, 1.2, 7.1, 7.4_
  - _Boundary: StagePlan, Overlay_
  - _Depends: 3.1_

- [x] 4.2 Select deep candidates from promotions only
  - Demoted findings are absent from the sandbox candidate list.
  - Unadjudicated findings are not used as negative proof when the sandbox is skipped.
  - Sandbox unavailable keeps promoted items unproven and records sandbox_unavailable.
  - Order remaining promotions with the heuristic ranker; if embeddings are configured, retrieval may reorder but must not drop.
  - Observable: a tree with one demoted `exec("ls")` and one promoted `eval(request.args)` offers only the latter to regression when Docker is probed; with embeddings off, heuristic order is used.
  - _Requirements: 1.3, 6.1, 6.2, 6.3, 6.4, 6.5, 9.1, 9.2, 9.3, 9.4, 9.5_
  - _Boundary: ProveFilter_
  - _Depends: 4.1_

- [x] 4.3 Distinguish dispositions in markdown and SARIF
  - Promoted, demoted, unadjudicated, and coverage are visible without reading JSON.
  - `--fail-on worth-fixing` does not fail on unadjudicated inventory.
  - Observable: report.md contains the four labels; fail-on worth-fixing on an unadjudicated-only tree exits 0.
  - _Requirements: 7.2, 7.3, 2.4_
  - _Boundary: Reports_
  - _Depends: 4.1_

- [x] 4.4 Mechanism memory with OpenRouter embeddings as the only semantic ranker
  - Append-only mechanism log is source of truth; json-local `mechanisms` namespace is a rebuildable OpenRouter vector cache.
  - Hard-filter by language, CWE, tags; rank remaining by OpenRouter cosine on mechanism text vs promotion overlay text.
  - No TF-IDF. Missing key or embed failure → heuristic order plus a recorded degradation; prove still runs.
  - Write mechanisms only from sandbox-proven findings; never from unadjudicated inventory.
  - Observable: after one triggerable finding, a paraphrased second promotion ranks above an unrelated CWE; with OPENROUTER_API_KEY unset, both remain candidates in heuristic order.
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8_
  - _Boundary: ProveBudget_
  - _Depends: 4.2_

- [x] 5. Evidence honesty
- [x] 5.1 Keep hunter and overlay off the proof rungs
  - Overlay promote remains static_corroboration or below.
  - Hunter output remains suspicion unless an independent stage already raised it.
  - A fixture that tries to stamp overlay as exploit_demonstrated is rejected.
  - Observable: existing hunter suspicion tests still pass; overlay records never contain crash_reproduced or higher.
  - _Requirements: 5.1, 5.2, 5.3, 5.4_
  - _Boundary: Overlay, ToolHunter_
  - _Depends: 3.1_

- [x] 6. Calibration vs unlabeled product
- [x] 6.1 Score the sast pair slice on overlay outcomes
  - Vulnerable side counts promote; false or good side counts demote or silent promoted-empty.
  - Stage-1 detection gate still uses inventory on cheat-sheet manifests only.
  - Overlay Youden cannot mark a failed detection gate as passed.
  - Sast and pair fixtures remain outside LANGUAGE_MANIFESTS.
  - Observable: `ousast pairs --slice sast` changes when overlay demotes Juliet goodG2B exec; `python -m openultrasast.gate` still ignores that slice.
  - _Requirements: 4.1, 4.2, 4.3, 4.4_
  - _Boundary: OverlayPairEval_
  - _Depends: 3.1, 4.1_

- [x] 6.2 Scan an unlabeled messy tree without expected findings
  - A syntax-broken file next to a clear request-to-eval file: broken file unadjudicated, eval promoted.
  - No counterpart fixed tree and no manifest required.
  - Observable: `ousast scan` on that tmp tree writes both dispositions.
  - _Requirements: 2.3, 2.5, 4.5, 7.4_
  - _Boundary: Overlay_
  - _Depends: 4.1_

- [x] 7. End-to-end validation
- [x] 7.1 Regression of three-stage contracts
  - Quick still has no model and no target execution.
  - Deep still does not run outside the existing sandbox.
  - MCP still rejects deep.
  - Observable: existing three-stage-scan tests for modes, sandbox, and MCP remain green.
  - _Requirements: 1.1, 6.5, 7.4_
  - _Depends: 4.2, 5.1_

## Implementation Notes

- Python adjudication uses stdlib `ast` when tree-sitter has no grammar; JS/C/Java stay `language_unsupported` until a grammar actually parses.
- Pair eval on the sast slice uses overlay when at least one promote/demote/coverage exists; otherwise it falls back to inventory so C/Java Juliet cases do not collapse without grammars.
- Intra-file taint is one-hop names plus source patterns in expressions. Heap channels (ConfigParser get/set) stay `flow_incomplete`.
- OpenRouter embeddings reorder promotions only; missing key records `embeddings_unavailable` and prove still runs.
- Hunter findings stay off the sandbox candidate list; only overlay promotions are proven.
