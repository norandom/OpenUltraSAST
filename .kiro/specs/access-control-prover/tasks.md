# Implementation Plan

- [x] 1. Paths from the caller index
- [x] 1.1 Add `PathRecord` and `compose_paths` in `src/openultrasast/semantic/obligations/paths.py` (P)
  - Upward walk through a `callers(path, function)` callable, depth and fan-out bounds, stop at the first entry,
    chains kept per file, deduplicated; unreached targets returned
  - Done when `tests/test_obligation_paths.py` covers depth 1 to 3, unreached, fan-out cut and same-name files,
    and `check_obligations` accepts the records as `paths` (one test runs the checker with them)
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_
  - _Boundary: obligations.paths_

- [x] 1.2 Checker opt-in `assume_entries_protected` and label `unguarded_path` in `semantic/obligations/check.py`
  - Default off; `_finding` receives the entry records' access by handler; evidence as the design states;
    `findings_to_static` explains the label; `LABELS` updated
  - Done when the existing checker tests pass unchanged and a new test shows: with paths, no policy, no siblings,
    the default gives no finding and the opt-in gives one `unguarded_path` finding for a non-public entry and none
    for an entry whose record access is `public`
  - _Requirements: 4.1a_
  - _Boundary: obligations.check (opt-in only)_

- [x] 2. Entry recognisers
- [x] 2.1 Stapler and Jetty recognisers in `mapping.py` (P)
  - Public `do[A-Z]...` methods on exposed types or with Stapler-typed or `@QueryParameter` parameters; Jetty
    `AbstractHandler`, `HttpServlet`, JAX-RS resources; evidence strings; `public` only for `UnprotectedRootAction`
  - Done when `tests/test_mapping_frameworks.py` names the entries of a fixture Descriptor, rejects a private
    helper named `doX`, and the existing mapping tests still pass
  - _Requirements: 1.1, 1.6, 1.7, 1.8_
  - _Boundary: mapping_
- [x] 2.2 Symfony, Livewire and Laravel controller, Remix export and Tornado recognisers in `mapping.py` (P)
  - Done when fixture files of each shape yield `route` entries with evidence and the negative fixtures yield none
  - _Requirements: 1.2, 1.3, 1.4, 1.5, 1.7, 1.8_
  - _Boundary: mapping_

- [ ] 3. Enforcement witnesses and facts
- [x] 3.1 `semantic/obligations/enforcement.py` producing router and decorator `Discharge` witnesses (P)
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

- [x] 3.3 Handler-named operations: `handlers` and `framework` fields in the facts loader, `find_operations(..., handlers_of=)`, Stapler form-validation rows in `java.toml`, Tornado handler rows in `python.toml`, Remix action rows in `typescript.toml`
  - Done when `tests/test_obligation_facts.py` loads a handler-named row, `tests/test_obligation_operations.py`
    (or the existing operations test file) yields the operation at the declaration line only for listed
    handlers, and the prover smoke on the 23 fixes reaches and checks the Jenkins form-validation methods
  - _Requirements: 2.8_
  - _Boundary: obligations.facts, obligations.operations_

- [x] 4. The prover
- [x] 4.1 `hunt/prover.py`: `prove_change` over the hunter `Context`, `Coverage`, findings as hunt defects
  - Touched functions from head lines, build output left out, targets include direct callees holding operations,
    IRs of hop files passed to the checker, extra witnesses from enforcement, coverage counts by reason, no model
  - Done when `tests/test_hunt_prover.py` shows: an unguarded Stapler handler calling `lookupCredentials` gives
    one finding with entry, hops and missing `path_guard`; a `checkPermission` above the call gives none; a
    guarded Laravel route gives none; an unrecognised framework gives coverage only; the finding dict has
    `path`, `line`, `family`, `function`, `evidence`, `id`
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 6.2, 7.1, 8.1, 8.2_
  - _Depends: 1.1, 2.1, 3.1, 3.2_

- [ ] 5. The arm
- [x] 5.1 `benchmarks/valid/prover_arm.py`: run over a pool slice with checkpoints, summarise with the valid metrics
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


## Implementation Notes

- Delivery A (2026-10-14) implements paths, the opt-in checker premise, Stapler/Jetty/Servlet/JAX-RS
  entries, the Java facts, the deterministic prover and the checkpointed arm. No commit was made.
- Task 3.2 stays open for the PHP, Python and TypeScript facts. Task 4.1's delivery A core is delivered;
  its full-spec checkbox stays open for delivery B's enforcement witnesses and guarded Laravel acceptance
  case. This delivery intentionally passes `extra_witnesses=()` as required by the maintainer's brief.
- Default checker behavior is preserved. Only opt-in checking includes a caller's statement witness,
  using the existing dominance contract at the outgoing call site. The prover checks each complete path
  independently so a guarded chain cannot hide an unguarded chain to the same operation.
- Java additions were checked against actual Git HEAD source objects in the sparse training clones;
  checked call sites are named in the Java TOML header. No network or model call was made.
- Mapping accepts cached source texts and an opt-out from external manifest scanning. Default callers
  retain their previous behavior; the delivery A prover uses source entries and its Context caches.
- Delivery A review was performed in the main context because the brief forbids model calls. The exact
  requested static gate passed (format, Ruff and mypy); the exact pytest gate passed with 112 passed,
  zero failed, exit 0. UV_NO_SYNC=1 was set; UV_CACHE_DIR was placed under /tmp because the default
  cache is outside the writable sandbox. The unchanged unjustified-path checker test remains intact.

- Delivery B (2026-10-14) implements task 2.2's Symfony, Livewire/Laravel, Remix and Tornado
  entries, task 3.1's scoped enforcement witnesses, task 3.3's handler facts and operation discovery,
  and task 4.1's integration. Changes remain uncommitted as the brief requires.
- Handler facts are explicitly opt-in through file-qualified handler maps in the checker. The prover
  uses handler obligations where a Stapler or Tornado entry reaches no listed call operation; existing
  call-site findings and Delivery A tests remain unchanged. Remix retains its handler operation even
  when listed calls exist, and independently requires a path guard and an ownership check. Public
  access waives only the path guard for these handler facts. The checker default is unchanged.
- The prover supplies a local dominance adapter for handler facts: it checks guards within the handler
  body while reporting the operation at its declaration. A final ordinary return does not turn a bare
  permission predicate into a guard. OrderDominance and the existing producers and arms are unchanged.
- Remix arrow exports are named locally in the prover's IR copy, including TSX route modules. Symfony
  recognises positional and named route paths and class prefixes. Tornado recognises local subclasses
  and the pool terminal's terminado base when it explicitly invokes Tornado's WebSocketHandler method.
- PHP CST Point.row access crashed on the larger Kimai controller with the installed native parser.
  New recognisers derive line numbers from byte offsets instead; a fixture past line 320 and the
  23-change source smoke complete without a crash. Existing CST code was not modified.
- Task 3.2 remains partially complete: TypeScript adds clone-verified requireUserId and
  authenticateApiRequest, retaining requireUser and authorize; PHP rows are retained and their header
  records enforcement sources. Python retains the existing authenticated decorator and gains the
  Tornado handler operation. No get_current_user fact was added: Git searches of Mage HEAD, the pool
  revision and websocket fix 66440e4d3 found neither that API nor an authenticated decorator use, and
  local framework documentation was unavailable. The brief forbids network access and unsourced names.
- Review used the main-context fallback because the brief prohibits model calls. Verdict: APPROVED
  for tasks 2.2, 3.1, 3.3 and 4.1; task 3.2 remains open for its source-verification gap. No new
  placeholder markers, credentials, dependencies, producer edits or arm edits were introduced.
- Fresh verification: UV_NO_SYNC=1 and UV_CACHE_DIR=/tmp/ousast-uv. The exact static gate passed:
  ruff format --check ., ruff check ., mypy src/openultrasast (178 source files). The exact requested
  pytest gate plus test_obligation_operations.py passed with 145 passed, zero failed, exit 0.
  Initial missing-feature tests produced 24 failed and 14 passed; integration tests initially produced
  eight failed and 20 passed. No test_search_* test was run.
- A separate file-scoped smoke read immutable Git source objects for all 23 access-control changes,
  validated their commit objects and source digests, and recorded nonzero input bytes for every change.
  All 23 executions completed, zero errors; 16 changes checked operations and seven remained unchecked.
  It materialised only changed source files in temporary directories, so it is not a full-repository
  recall measurement. The maintainer-owned task 6.1 and release readiness remain unclaimed.
