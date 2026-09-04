# Implementation Plan

This plan ships the three-stage scan without rebuilding CWE policy or the regex inventory. Foundation introduces the stage contract. Core builds the map, tool hunter, sandbox, and regression verdicts in parallel where boundaries do not overlap. Integration wires them onto `quick` / `standard` / `deep`. Validation adds split-sink corpora and the anti-cheat-sheet gate.

## Phase 1 — Foundation: Stage contract

- [x] 1. Introduce the stage plan and mode mapping
- [x] 1.1 Encode the three stages and the mode-to-stage table
  - Depth `quick` requests only static, `standard` requests static then map, `deep` requests static then map then regress.
  - A skipped stage is a structured reason, not an exception, and can be serialized into the existing degradations list.
  - Observable completion: a unit test asserts the three mappings and that `quick` never includes map or regress.
  - _Requirements: 1.1, 1.2, 1.3, 1.6_
  - _Boundary: StagePlan_

- [x] 1.2 Add complexity and regression configuration with candidate caps
  - Configuration exposes map top-k, max hunter hotspots, max regression candidates, and optional language image pins, with defaults that keep pull-request scans cheap.
  - Sandbox memory, pids, timeout, network-off, and read-only workspace remain the existing sandbox settings.
  - Observable completion: loading config without a file yields those defaults; an override file changes top-k and max candidates only.
  - _Requirements: 9.2, 9.5_
  - _Boundary: Packaging Configuration_
  - _Depends: 1.1_

- [x] 1.3 Expand fail-on vocabulary with worth-fixing
  - The scan command accepts `worth-fixing` alongside the existing fail-on values and does not change the meaning of `findings` or `verified`.
  - The existing report exit helper must recognize the new value; unknown values still fail loud.
  - MCP continues to reject `deep` and must not gain docker or shell tools.
  - Observable completion: `--help` lists `worth-fixing`; a scan with no worth-fixing verdicts and `--fail-on worth-fixing` exits 0; MCP still refuses `deep`.
  - _Requirements: 5.7, 5.8_
  - _Boundary: StagePlan_
  - _Depends: 1.1_

## Phase 2 — Core: Map, hunter tools, sandbox (parallel after foundation)

- [x] 2. Build the heuristic complexity map and test-tuning hints
- [x] 2.1 (P) Compute per-file and per-function complexity signals
  - Signals include size, nesting, surface tags, reachability, inventory-hit density as a feature not the score, and whether an adjacent test appears to exist.
  - Function identity uses entry-point names when present and otherwise remains empty.
  - Observable completion: a parser file with no pattern hit scores higher than a one-line helper that matches a pattern, proven by a unit test on a constructed target list.
  - _Requirements: 3.1, 3.2_
  - _Boundary: ComplexityMapBuilder_

- [x] 2.2 (P) Emit the ordered hotspot map artifact
  - Each hotspot carries score, band, rationale, signals, and linked inventory ids; the map records whether it is heuristic-only.
  - Observable completion: building a map writes a JSON artifact whose hotspot order is not identical to sorting by inventory-hit count on the same fixture.
  - _Requirements: 3.2, 3.3, 3.5, 8.6_
  - _Boundary: ComplexityMapBuilder_
  - _Depends: 2.1_

- [x] 2.3 Attach test-gap hints without writing into the scanned tree
  - Each hotspot gets a gap of no adjacent test, no function reference, no fuzz entry, or covered.
  - Recommended test kind is one of unit, property, sanitizer, http-contract, or fuzz-harness, and is omitted when the gap is covered.
  - Observable completion: a covered hotspot emits `covered` and no test kind; a fuzzable C parser without a harness emits `fuzz-harness`; the scanned tree is unchanged.
  - _Requirements: 4.1, 4.2, 4.3, 4.4_
  - _Boundary: TestTuningAdvisor_
  - _Depends: 2.2_

- [x] 2.4 Apply a complexity ledger overlay that cannot hide severity-5 reachable inventory
  - Triggerable verdicts raise a hotspot's later score; not-triggerable verdicts lower it; the underlying inventory hit remains.
  - A reachable policy-severity-5 inventory finding stays in the regression candidate set regardless of a negative ledger delta.
  - Observable completion: after a not-triggerable overlay the hotspot score drops, and a sev-5 reachable finding is still selected as a candidate, proven by a unit test.
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_
  - _Boundary: ComplexityMapBuilder_
  - _Depends: 2.2_

- [x] 3. Add repo-bound hunter tools and a scripted tool loop
- [x] 3.1 (P) Clamp tool paths and expose read, grep, and reference search
  - Read, grep, and reference listing resolve only under the scan root; `..` and absolute escapes raise a path-escape error.
  - Grep runs with the standard library over enumerated source files.
  - Observable completion: a unit test reads a repo file, greps a split-sink assignment, and rejects `../etc/passwd`.
  - _Requirements: 6.1, 6.2_
  - _Boundary: HunterTools_

- [x] 3.2 Run a bounded tool-using hunter that records suspicion only
  - When a hunter model is configured, the loop may call the three tools against map hotspots and must not stamp results as static corroboration.
  - When no model is configured, the loop does not run and a degradation is produced by the orchestrator later.
  - Observable completion: a scripted client that never calls a tool fails the test; a client that greps then returns a finding yields evidence level `suspicion` and id prefix `tool-hunter:`.
  - _Requirements: 6.1, 6.3, 6.4, 6.5_
  - _Boundary: ToolHunter_
  - _Depends: 3.1, 2.2_

- [x] 4. Stand up the isolated sandbox runner
- [x] 4.1 (P) Probe whether the sandbox runtime is usable
  - A short `docker info` style probe returns available or unavailable without throwing into the scan.
  - Observable completion: the fake probe can be forced off; the real probe is skippable in unit tests.
  - _Requirements: 9.3_
  - _Boundary: SandboxProbe_

- [x] 4.2 (P) Run jobs through Docker CLI flags that match the threat model
  - Network is disabled, source is read-only, scratch is writable, memory/pids/timeout apply, capabilities are dropped, source tree is not writable, and the host Docker socket is never mounted.
  - A fake runner records the job and returns a programmed result so default tests do not need a daemon.
  - Observable completion: the constructed command line includes network-none and read-only and excludes docker.sock; the fake runner is used by unit tests.
  - _Requirements: 5.2, 5.8_
  - _Boundary: DockerCliRunner_
  - _Depends: 4.1_

- [x] 4.3 Reject unsafe regression snippets before execution
  - Snippets that refer to the Docker socket, host network, or writes under the source mount are not executed and become `inconclusive`.
  - Observable completion: each forbidden shape is rejected in a unit test and no runner job is created.
  - _Requirements: 5.8, 6.6_
  - _Boundary: RegressionRunner_
  - _Depends: 4.2_

## Phase 3 — Core: Regression verdicts

- [x] 5. Produce worth-fixing verdicts from sandboxed candidates
- [x] 5.1 Select a bounded candidate set from hotspots and severe reachable inventory
  - Selection honors max-candidates and always includes reachable severity-5 inventory even when the ledger demoted the hotspot.
  - Observable completion: a unit test with six hotspots and max-candidates three returns three, plus the sev-5 reachable extra when present.
  - _Requirements: 5.1, 7.4, 9.5_
  - _Boundary: RegressionRunner_
  - _Depends: 2.4_

- [x] 5.2 (P) Add language recipes with inconclusive fallback
  - Python and JavaScript recipes run a scratch snippet with the repo on the language path; C compiles and runs when the image has a compiler; a missing recipe yields `inconclusive` rather than a crash.
  - Observable completion: Python and JavaScript recipes produce a job; an unknown language returns inconclusive without calling the runner.
  - _Requirements: 5.1, 5.6_
  - _Boundary: RegressionRunner_
  - _Depends: 5.1_

- [x] 5.3 Map sandbox outcomes to the four verdicts and the worth-fixing gate
  - Outcomes map to triggerable, not_triggerable, already_covered, or inconclusive; worth-fixing requires triggerable plus reachable or inferred-file-surface.
  - Not-triggerable and already-covered do not fail the build; inconclusive records a reason and does not fail the build.
  - Observable completion: a table-driven test covers the four verdicts and the worth-fixing boolean.
  - _Requirements: 5.3, 5.4, 5.5, 5.6_
  - _Boundary: WorthFixingGate_
  - _Depends: 5.2, 4.2_

## Phase 4 — Integration: Wire stages into the scan

- [x] 6. Run stages from the existing scan command
- [x] 6.1 Keep quick as stage-1 inventory with no model and no target execution
  - Quick still loads policy, ruleset, preprocess, rank, pattern inventory, structural verify, and score.
  - The report labels those hits as inventory, not as worth-fixing.
  - Policy still fails loud on an unmapped enabled CWE.
  - Observable completion: existing quick tests stay green; the report contains an inventory section and does not start a sandbox or a hunter model.
  - _Requirements: 1.1, 2.1, 2.2, 2.3, 2.4, 2.5, 9.1_
  - _Boundary: StagePlan_
  - _Depends: 1.1_

- [x] 6.2 Run the complexity map on standard and record heuristic-only when no model is set
  - Standard writes the map artifact, includes it in the manifest, and records `hunter_model_unavailable` when the hunter is skipped.
  - Observable completion: `ousast scan --mode standard` on a fixture produces `complexity_map.json` and a completed map stage without Docker.
  - _Requirements: 1.2, 1.4, 3.3, 3.4, 6.4, 9.4, 9.6_
  - _Depends: 2.3, 6.1_

- [x] 6.3 Stop exiting on deep; run or skip regression with visible degradation
  - Deep no longer hard-exits. If the sandbox is missing, stages 1–2 complete and regress is skipped with `sandbox_unavailable`.
  - If the sandbox is present, regression runs under the candidate cap and writes verdicts.
  - Observable completion: `ousast scan --mode deep` without Docker exits 0 after stages 1–2 and lists the skip in the manifest; with a fake runner it records verdicts.
  - _Requirements: 1.3, 1.5, 5.1, 9.3, 9.6_
  - _Depends: 5.3, 6.2_

- [x] 6.4 Attach the tool hunter to map hotspots when a model is configured
  - Hunter findings are suspicion-only and may propose a snippet that still must pass the safety check and run only in the sandbox.
  - Observable completion: with a scripted client, standard+model produces tool-hunter suspicions; a proposed snippet is executed only on deep after the safety check.
  - _Requirements: 6.1, 6.3, 6.5, 6.6_
  - _Depends: 3.2, 6.2_

- [x] 6.5 Surface map, hints, and worth-fixing in the report and honor fail-on
  - Markdown, manifest, and SARIF remain; the report gains map and worth-fixing sections.
  - `--fail-on worth-fixing` fails only when a worth-fixing verdict exists.
  - Observable completion: a scan with one worth-fixing verdict fails under that flag and passes under `--fail-on never`.
  - _Requirements: 2.2, 4.1, 5.7, 7.3_
  - _Depends: 6.3_

## Phase 5 — Validation: Grounded corpora and CI

- [ ] 7. Replace cheat-sheet success for stages 2 and 3
- [x] 7.1 Add split-sink fixtures for Python, JavaScript, Java, and C/C++
  - Each language family has at least one case where source and sink are on different lines or assigned before use.
  - Observable completion: stage-1 pattern scan misses at least one planted sink in each family, documented in the manifest expected set.
  - _Requirements: 8.1_
  - _Boundary: Benchmark Harness_

- [x] 7.2 (P) Add a mutation of a known sink that a same-line pattern does not match
  - At least one wrapper or intermediate-variable mutation exists per the evaluation plan.
  - Observable completion: stage 1 misses the mutation; the case is listed as expected in a split-sink or mutation manifest.
  - _Requirements: 8.2_
  - _Boundary: Benchmark Harness_

- [ ] 7.3 Gate stage 2 on ranking the true function in the high band and beating pattern-hit order
  - Stage 1 may still use existing smoke fixtures; that recall is not treated as stage-2 success.
  - The merge gate fails if map order equals pattern-hit-count order on the split-sink corpus.
  - Observable completion: a dedicated gate command or test fails a stub map that sorts by hit count and passes the heuristic map on the split-sink corpus.
  - _Requirements: 8.3, 8.4, 8.6_
  - _Depends: 7.1, 2.2_

- [ ] 7.4 Prove stage 3 can trigger a planted miss when the sandbox is available
  - Docker-marked tests skip when the probe fails; when they run, at least one stage-1 miss is `triggerable`.
  - Default pytest does not require a daemon. The pull-request job stays stage 1; a nightly or labeled job may request deep under time and candidate caps.
  - Observable completion: fake-runner tests always run; docker tests skip-or-pass; the default CI workflow still invokes quick-only detection plus the new split-sink map gate.
  - _Requirements: 8.5, 9.1, 9.2_
  - _Depends: 6.3, 7.1_

## Implementation Notes

- `RegressConfig.images` is a sorted tuple of `(language, image)` pairs so frozen config stays hashable.
- `scan_exit_code` duck-types `worth_fixing` on verdict objects; `_run_scan` still passes no verdicts until task 6.5. Dict-shaped verdicts would not fail the gate.
- Map `top_k` default is 20 (not named in design.md); `max_hunter_hotspots=8` and `max_candidates=5` follow design.
- `collect_signals` adjacent-test detection is false unless the caller also passes `repo_files`; task 2.2 must pass enumerated repo paths.
- ToolHunter rejects JSON dumps unless a repo tool was invoked; findings are always `suspicion` with prefix `tool-hunter:`.
