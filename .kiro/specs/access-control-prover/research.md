# Research & Design Decisions

## Summary
- **Feature**: `access-control-prover`
- **Discovery Scope**: Extension of `authorization-obligations` (checker, facts, dominance) and the hunter's
  per-change context; gap analysis against the code on 2026-10-14 (commit 9feb8f1).
- **Key Findings**:
  - The checker already takes `paths` and `entries` and already decides reached-ness and along-path dominance
    (`semantic/obligations/check.py::_reached`, `dominance.py::_dominates_along`); nothing supplies paths today,
    so every operation outside an entry handler is invisible to it.
  - The entry-point mapper (`mapping.py`) recognises Flask, Django, Express, Laravel routes, WordPress hooks,
    Next and Remix route modules partially, and nothing for Java: no Stapler `doXxx` web method, no Servlet or
    Jetty handler, no JAX-RS resource. Seventeen of the pool's 23 fixes are Stapler web methods.
  - The hunter's `Context` (hunt/producers.py) caches product files, texts, file IR, a call index and the
    repository's entry points per change; `source.callers_of` gives one hop of callers from the index. A bounded
    upward walk from a function to an entry point is a loop over that, no new index.
  - Enforcement outside the function fits the existing `Discharge` scopes `router` and `decorator`, which
    `OrderDominance.dominates` accepts without a line, through the checker's `extra_witnesses` parameter. No
    schema change to the facts loader is needed for them; the facts files gain operation rows only.
  - `benchmarks/valid/metrics.py` scores replay-shaped records with `benchmarks.unseen.score`; the hunter arm
    (`benchmarks/valid/hunter_arm.py`) writes that shape. A prover arm writing the same shape is scored by the
    same code, so its recall and false alarms per 100 stand beside the hunter arms.
  - The pool's fixes by shape: 17 Jenkins web methods (`doTestConnection`, `doFill...Items`, `doCheck...`,
    `doValidate...`, `doChangeSubmit`, `doNotifyCommit`, `doPython`, `persistValue`, `create`) missing
    `checkPermission`; one Jetty service without authentication (CWE-306); one Tornado terminal websocket open
    without authentication (CWE-306); one Laravel Livewire `store` without authorization (CWE-285); one Symfony
    controller action (CWE-284); one Remix action deactivating a schedule by id without an ownership check
    (CWE-639); one Flarum JavaScript extension (CWE-863, out of reach for this prover: client-side permission
    gating, counted as uncovered).

## Research Log

### Which checker parameters exist and what they expect
- **Context**: avoid a second checker.
- **Sources Consulted**: `src/openultrasast/semantic/obligations/check.py` (`check_obligations`, `_reached`,
  `_relevant`), `dominance.py` (`OrderDominance`, `_dominates_along`, `_hop_index`), the approved design of
  `authorization-obligations` (Dominance, Checker, EntryPoints sections).
- **Findings**: `paths` is a sequence of objects with a `hops` attribute; each hop is `"path::function"` or a
  `(node, line)` pair; a path reaches an operation when its last hop equals `f"{op.path}::{op.function}"`. With
  no paths, only operations inside entry handlers (`entries`) are reached. A witness of scope `hop` on an
  earlier hop dominates along the path. Witness scopes `decorator` and `router` dominate without a line.
- **Implications**: the prover produces `PathRecord(hops=(...))` objects ending at the operation's function and
  passes them as `paths`; it produces router and decorator witnesses as `extra_witnesses`; it needs no change to
  the checker's logic. One gap: the checker builds `operations` from the IRs it is given, so the prover passes the
  IR of every file on a path, not only the touched file.

### Where entry points come from
- **Sources Consulted**: `src/openultrasast/mapping.py` (`analyze_entry_points`, `_entry`, the per-framework
  recognisers around lines 260-930), `EntryPointRecord` fields.
- **Findings**: recognisers are code, one block per framework, each calling `_entry(target, start, end, handler,
  name, kind, access, trust_boundary, evidence, conditions, ...)`. No Java recogniser exists. `frameworks.toml` is
  a lexicon for priors and stratification, not for entry recognition.
- **Implications**: add recognisers in `mapping.py` following the existing block pattern (Stapler, Jetty,
  Symfony attributes, Livewire, Tornado, Remix exports where missing). Each names its evidence.

### How a rule arm is scored
- **Sources Consulted**: `benchmarks/valid/metrics.py` (`summarize`, `scoring_records`), `benchmarks/unseen/score.py`
  (`catches`, `location_match`, `false_alarm`, `coverage`), `benchmarks/valid/hunter_arm.py` (`run`, record
  writing), `src/openultrasast/hunt/metric.py::search_outcome`.
- **Findings**: a record needs `id`, `kind`, `repo`, `family`, the change's `path`/`function_lines` (copied from
  the pool), `findings` with `path`, `line`, `family`, and `coverage` fields the scorer reads; a push is caught
  when a finding of the change's family lands within the tolerance of a verified location.
- **Implications**: the prover arm copies the hunter arm's record envelope and instrument fields (bytes read per
  changed file, head verified), writes per-change files, and calls `benchmarks.valid.metrics.summarize`.

### Budget
- **Findings**: the second screen's feature table took 53 minutes for 483 changes with every producer, 7 seconds
  per change on average and 117 seconds for the slowest seatunnel change; the caller index is the dominant cost
  and is already cached per change. A depth-3 upward walk adds a few index lookups per function.
- **Implications**: the 120-second bound of Requirement 6 is realistic; the runner measures it per change.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|---|---|---|---|---|
| Extend the checker's inputs (chosen) | Supply paths, entries and witnesses to `check_obligations` from the hunter's context | One checker, one dominance rule, facts stay closed data | Order dominance is textual inside a function; nesting-aware dominance (`guard-dominance-regime`) never existed | Honest for "check present before operation"; the Jenkins shape |
| New prover module with its own graph | Build a call graph and CFG per change | Precise dominance | Weeks of work, duplicates the checker, no CFG for Java or PHP in the tree | Rejected for this increment |
| Joern engine | Dataflow and call graph from the engine | Precise | 225 s per batch, pilot produced no findings, no PHP in the budget | Rejected as the gate; usable later as a proof backend |

## Design Decisions

### Decision: paths from the caller index, not a call graph
- **Context**: Requirement 3.
- **Alternatives Considered**: a per-change call graph over all product files; the engine's call graph.
- **Selected Approach**: an upward walk from the function through `source.callers_of` on the cached index,
  bounded by depth and fan-out, stopping at the first entry point of each chain.
- **Rationale**: the index exists, is cached per change, and the pool's shapes are shallow (the operation is in the
  web method or one helper below it).
- **Trade-offs**: name-based caller resolution conflates same-named functions across files; chains are kept per
  file but a caller of `save` in another class may be a false hop. Accepted and visible in the evidence.
- **Follow-up**: measure how many positives are reached at depth 1, 2 and 3 on the pool.

### Decision: framework enforcement as router and decorator witnesses
- **Context**: Requirement 2.
- **Selected Approach**: a small recogniser per framework reads route registrations and attributes and emits
  `Discharge` witnesses with scope `router` or `decorator` for the handlers they cover; passed through
  `extra_witnesses`.
- **Rationale**: the dominance rule already accepts those scopes; the facts files stay about calls.
- **Trade-offs**: coverage is as wide as the recognisers; an unrecognised middleware name means a finding on a
  guarded route. Every recogniser lists its names in the facts header and the coverage statement counts routes
  with unrecognised middleware.

### Decision: no model call inside the prover
- **Context**: Requirement 4.4; the maintainer's direction after the engine pilot: the model's job is the trust
  boundary question the static side cannot answer, asked after a static result exists.
- **Selected Approach**: the prover is deterministic; the intent adjudication hook of the checker stays off in
  the arm; a later increment may wire it as a separate, measured arm.

## Risks & Mitigations
- Jenkins web methods whose protected operation is an outbound connection test with stored secrets
  (`doTestConnection`) call no listed operation name — mitigate by adding operation rows for credential
  lookups and HTTP client calls used in those handlers, checked in the clones, and by counting the handlers the
  facts do not cover.
- Textual order dominance inside a function misses a check in an `else` branch — accepted for this increment;
  recorded as a degradation when a witness exists but does not dominate.
- Same-name conflation in callers — chains kept per file; evidence names the hop files.
- Over-wide entry recognition (every `doXxx`) raises false alarms on helper methods — the Stapler recogniser
  requires a public method on an exposed type or a Stapler-typed parameter; the pool's ordinary pushes measure
  the rate.

## References
- Jenkins AccessControlled: https://javadoc.jenkins.io/hudson/security/AccessControlled.html
- Stapler web methods: https://www.jenkins.io/doc/developer/security/form-validation/ and
  https://www.jenkins.io/doc/developer/security/secrets-and-credentials/
- Laravel authorization and route middleware: https://laravel.com/docs/authorization, https://laravel.com/docs/middleware
- Symfony security: https://symfony.com/doc/current/security.html
- Remix route module API: https://remix.run/docs/en/main/route/action
- Tornado authentication: https://www.tornadoweb.org/en/stable/guide/security.html
