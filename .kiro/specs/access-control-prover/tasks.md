# Implementation Plan

- [ ] 1. Paths from the caller index
- [ ] 1.1 Add `PathRecord` and `compose_paths` in `src/openultrasast/semantic/obligations/paths.py` (P)
  - Upward walk through a `callers(path, function)` callable, depth and fan-out bounds, stop at the first entry,
    chains kept per file, deduplicated; unreached targets returned
  - Done when `tests/test_obligation_paths.py` covers depth 1 to 3, unreached, fan-out cut and same-name files,
    and `check_obligations` accepts the records as `paths` (one test runs the checker with them)
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_
  - _Boundary: obligations.paths_

- [ ] 1.2 Checker opt-in `assume_entries_protected` and label `unguarded_path` in `semantic/obligations/check.py`
  - Default off; `_finding` receives the entry records' access by handler; evidence as the design states;
    `findings_to_static` explains the label; `LABELS` updated
  - Done when the existing checker tests pass unchanged and a new test shows: with paths, no policy, no siblings,
    the default gives no finding and the opt-in gives one `unguarded_path` finding for a non-public entry and none
    for an entry whose record access is `public`
  - _Requirements: 4.1a_
  - _Boundary: obligations.check (opt-in only)_

- [ ] 2. Entry recognisers
- [ ] 2.1 Stapler and Jetty recognisers in `mapping.py` (P)
  - Public `do[A-Z]...` methods on exposed types or with Stapler-typed or `@QueryParameter` parameters; Jetty
    `AbstractHandler`, `HttpServlet`, JAX-RS resources; evidence strings; `public` only for `UnprotectedRootAction`
  - Done when `tests/test_mapping_frameworks.py` names the entries of a fixture Descriptor, rejects a private
    helper named `doX`, and the existing mapping tests still pass
  - _Requirements: 1.1, 1.6, 1.7, 1.8_
  - _Boundary: mapping_
- [ ] 2.2 Symfony, Livewire and Laravel controller, Remix export and Tornado recognisers in `mapping.py` (P)
  - Done when fixture files of each shape yield `route` entries with evidence and the negative fixtures yield none
  - _Requirements: 1.2, 1.3, 1.4, 1.5, 1.7, 1.8_
  - _Boundary: mapping_

- [ ] 3. Enforcement witnesses and facts
- [ ] 3.1 `semantic/obligations/enforcement.py` producing router and decorator `Discharge` witnesses (P)
  - Laravel route middleware and controller `middleware`/`authorizeResource`; Symfony `IsGranted`, `Security`,
    security.yaml `access_control`; Tornado `authenticated`; names listed in the facts headers
  - Done when `tests/test_obligation_enforcement.py` shows a guarded Laravel route, a Symfony attribute and a
    Tornado decorator each produce one witness that `OrderDominance` accepts for the handler's operation
  - _Requirements: 2.1, 2.2, 2.5, 2.6_
  - _Boundary: obligations.enforcement_
- [ ] 3.2 Operation and discharger rows for the pool's shapes in `ruleset/obligations/{java,php,python,typescript}.toml` (P)
  - Java: credential lookups and outbound connection tests in `doTestConnection`-style handlers, item reads and
    writes, `checkPermission`/`checkAnyPermission` as path guards, `hasPermission` as ownership check;
    Remix: session requirements as path guards, record reads by request id as protected reads needing
    `ownership_check`; Tornado: handler `open`/`get` as entries needing `path_guard`; Jetty service start as
    privileged action. Every name checked in the clones or documentation, said in the header
  - Done when `tests/test_obligation_facts.py` loads the files and one operation and one discharger per
    language resolve
  - _Requirements: 2.3, 2.4, 2.7_
  - _Boundary: ruleset/obligations_

- [ ] 4. The prover
- [ ] 4.1 `hunt/prover.py`: `prove_change` over the hunter `Context`, `Coverage`, findings as hunt defects
  - Touched functions from head lines, build output left out, targets include direct callees holding operations,
    IRs of hop files passed to the checker, extra witnesses from enforcement, coverage counts by reason, no model
  - Done when `tests/test_hunt_prover.py` shows: an unguarded Stapler handler calling `lookupCredentials` gives
    one finding with entry, hops and missing `path_guard`; a `checkPermission` above the call gives none; a
    guarded Laravel route gives none; an unrecognised framework gives coverage only; the finding dict has
    `path`, `line`, `family`, `function`, `evidence`, `id`
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 6.2, 7.1, 8.1, 8.2_
  - _Depends: 1.1, 2.1, 3.1, 3.2_

- [ ] 5. The arm
- [ ] 5.1 `benchmarks/valid/prover_arm.py`: run over a pool slice with checkpoints, summarise with the valid metrics
  - Record envelope copied from `hunter_arm`; instrument fields; resume; `summary.json` with recall (pushes and
    locations, Wilson), false alarms per 100, precision, instrument failures, seconds per change and the list
    over 120 s, per-repository and per-framework coverage, `uncovered` repositories; refuse on zero-byte reads
  - Done when `tests/test_prover_arm.py` runs a two-change fixture pool end to end and the summary carries
    every field above; a record with zero bytes read makes `summarize` refuse
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 6.1, 7.2_
  - _Depends: 4.1_

- [ ] 6. Measurement (maintainer, not Codex)
- [ ] 6.1 Run the arm on `benchmarks/valid/train/pool-train.toml` over the training clones; write
  `benchmarks/measurements/<date>-access-control-prover/` with NOTES, summary, coverage table; compare with the
  DSPy and hunter arms of the same pool
  - _Requirements: 5.2, 5.3, 7.2_
