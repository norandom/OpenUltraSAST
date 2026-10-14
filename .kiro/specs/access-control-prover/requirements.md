# Requirements Document

## Project Description (Input)
An access-control prover: a deterministic check that an operation needing authorization is reachable from an
entry point without a check dominating the path, modelled per framework, built from the existing obligation facts,
caller index and entry-point mapper, scored as a rule on the access-control training pool (recall on 23 fix
changes, false alarms per 100 ordinary pushes) and feeding the proof arm.

## Introduction
The maintainer's finding of 2026-10-14: the hunter's features (diff shape, function size, callers, entry-point
counts, name roles, textual obligation order) describe the shape of code around a change and cannot decide that
code is unsafe. Unsafety for access control is a property: an operation that needs authorization is reachable by a
caller that no check has constrained. The access-control training pool (23 fix changes, 93 verified locations,
460 ordinary pushes, 23 application repositories) holds exactly that shape: a permission check added before a
protected operation in a web-exposed method. Seventeen of the 23 fixes are Jenkins plugin web methods.

This spec delivers the prover for that one family, as a deterministic rule with no model call, measured on the
pool with the standard metrics, and emitting findings that carry the unguarded path so the proof arm can act on
them. It is the increment that follows the annotation ablation in `hunter-learning-loop`.

## Boundary Context
- **In scope**: entry-point recognition for the pool's frameworks; reachability paths from entry points to
  touched functions through the existing caller index; framework enforcement points that discharge an obligation
  outside the function (route middleware, controller attributes, declared public routes); the verdict per change;
  a runner that scores the verdict as an arm on the pool; a coverage statement per repository.
- **Out of scope**: taint flow, the Joern engine, any model call inside the prover, new families beyond access
  control, a project-owned declared policy file (exists in `authorization-obligations` and is consumed as is),
  the unseen pilot measurement (G1 exit, run by the maintainer after this arm exists), the pre-push hook wiring
  (`pre-push-safety-net`).
- **Adjacent expectations**: `authorization-obligations` owns the facts schema, the checker and the dominance
  protocol; this spec extends facts and supplies paths and witnesses through the checker's existing parameters.
  `hunter-learning-loop` owns the feature table and the hunter arms; the prover is scored beside them with the
  same metric functions. `search-with-proof` consumes the finding's path and operation to build a demonstration.

## Requirements

### Requirement 1: Entry points of the pool's frameworks
**Objective:** As a maintainer, I want the entry-point mapper to name the web-exposed methods of the frameworks
the pool uses, so that reachability starts where an attacker starts.

#### Acceptance Criteria
1. When a Java file declares a public method whose name starts with `do` in a class that extends or implements
   a Jenkins or Stapler exposed type (Descriptor, Action, RootAction, Plugin, UnprotectedRootAction,
   AbstractDescribableImpl, or a parameter typed StaplerRequest, StaplerResponse or annotated QueryParameter),
   the mapper shall record an entry point of kind `route` with trust boundary `http_request` and the method's
   line range, with access `public` when the class implements UnprotectedRootAction and `unknown` otherwise.
2. When a PHP file declares a Symfony controller action (a method carrying a `Route` attribute or annotation, or
   a class extending AbstractController with public methods named by a routes file), the mapper shall record it
   as a `route` entry with the attribute's path as evidence.
3. When a PHP Livewire component or Laravel controller method is registered by a route file, a `Route::` call, a
   `wire:` binding or a public method on a class extending Livewire Component, the mapper shall record it as a
   `route` entry, and shall carry a declared access of `public` only when the route file names no middleware.
4. When a TypeScript or JavaScript file under a Remix or React Router routes directory exports `action` or
   `loader`, the mapper shall record each export as a `route` entry with trust boundary `http_request`.
5. When a Python class extends a Tornado RequestHandler or WebSocketHandler, the mapper shall record its `get`,
   `post`, `put`, `delete`, `patch` and `open` methods as `route` entries.
6. When a Java class extends a Servlet, a Jetty handler or a JAX-RS resource, the mapper shall record the
   request methods as `route` entries (existing Servlet and JAX-RS rows are kept; Jetty handlers are added).
7. The mapper shall record every recogniser's evidence strings so a finding can name why a method is an entry.
8. If a file's framework is not recognised, then the mapper shall record nothing for it and the coverage
   statement (Requirement 7) shall count the file as unchecked; silence is never a pass.

### Requirement 2: Enforcement points outside the function
**Objective:** As a maintainer, I want checks that frameworks apply outside the handler to count as discharges,
so that a guarded route is not reported because its handler body shows no check.

#### Acceptance Criteria
1. When a Laravel route registration attaches `auth`, `can:`, `role` or `permission` middleware, or a controller
   calls `authorizeResource` or `middleware` in its constructor, the prover shall supply a discharge witness of
   scope `router` for every handler the registration covers.
2. When a Symfony action carries `IsGranted`, `Security` or a `denyAccessUnlessGranted` call, or security.yaml's
   `access_control` covers its path with a role, the prover shall supply a `decorator` or `router` witness.
3. When a Jenkins web method, or a method it calls on its own path, calls `checkPermission`,
   `checkAnyPermission` or guards on `hasPermission` with an exit, the existing statement witnesses shall apply;
   `RequirePOST`, `POST` and `Interceptor` annotations shall not count as authorization.
4. When a Remix action or loader calls a session requirement (`requireUser`, `requireUserId`,
   `requireAuthentication`, `authenticateApiRequest`, `authorize`) before the operation, the prover shall treat
   that call as a path guard, and when the operation reads a record by an identifier from the request without an
   ownership constraint bound to the authenticated principal the prover shall report the missing
   `ownership_check` (the pool's CWE-639 case).
5. When a Tornado handler is decorated with `authenticated` or `tornado.web.authenticated`, or the class
   overrides `get_current_user` and checks it before the operation, the prover shall treat that as a path guard.
6. Where a declared policy marks a route public, the prover shall suppress `path_guard` findings for it and
   keep `ownership_check` findings, as the checker already does.
8. Where a framework's security model makes the web method itself the protected operation (Jenkins form
   validation and list-filling methods `doCheck*`, `doFill*Items`, `doTest*`, `doValidate*`, `doVerify*`, which
   Jenkins requires to check a permission; Tornado handler methods; a Remix action), the facts shall be able to
   name the obligation by handler name pattern and framework, and the prover shall apply such an operation only
   to functions the mapper recognised as entries of that framework, at the method's declaration line.
7. The prover shall write every enforcement fact as closed data in the obligation facts files, with the header
   naming the clones and references checked, and shall never add a name that does not occur in the checked code
   or the framework's documentation.

### Requirement 3: Reachability paths through the caller index
**Objective:** As a maintainer, I want a path from an entry point to each touched function, so that an
obligation inside a helper is judged by the checks on the way to it.

#### Acceptance Criteria
1. When a change is checked out at head, the prover shall build, for every touched function and every function
   that holds a protected operation it calls, the caller chains that end at an entry point, through the
   per-change caller index, up to a configurable depth with default 3 and a configurable fan-out with default 25
   callers per step.
2. The prover shall emit each chain as a path record whose hops are `path::function` strings from the entry to
   the operation's function, in the shape `check_obligations` and `OrderDominance` already consume.
3. If a touched function is itself an entry point, then the prover shall emit the one-hop path.
4. If no chain reaches an entry point within the depth, then the prover shall record the function as
   `unreached` in the coverage statement and shall produce no finding for it.
5. The prover shall deduplicate chains, shall stop at the first entry point on a chain, and shall bound the work
   so a change of the pool's largest repositories finishes within the budget of Requirement 6.
6. When two functions share a name in different files, the prover shall keep the chains separate by file.

### Requirement 4: The verdict
**Objective:** As a developer about to push, I want a finding only when the tool can show an unguarded path to a
protected operation, so that every alarm names what to add and where.

#### Acceptance Criteria
1. When a protected operation is reached by a path record and no witness of a required discharger kind
   dominates it along that path or inside its function, the prover shall emit one finding per operation and
   missing kind with family `access_control`, the operation's path and line, the entry point, the hops, the
   missing kind and the evidence strings.
1a. The prover's premise shall be explicit: a recognised entry point is protected unless the framework or a
   declared policy marks it public. The checker shall apply that premise only when the caller opts in, shall
   label such findings `unguarded_path` (distinct from `declared_policy_violation` and
   `consistency_violation`), and shall say in the evidence that no policy clause and no sibling norm backed it.
   The checker's default behaviour with path records (no clause, no sibling norm, no finding) is unchanged.
2. When every required discharger kind is dominated, the prover shall emit no finding and shall count the
   operation as `discharged` in the coverage statement.
3. The prover shall never emit a finding for a function whose file failed to parse, whose language has no
   obligation facts, or whose framework is unrecognised; each such case shall be counted under its reason.
4. The prover shall make no model call.
5. The prover shall report findings in the hunt defect shape (`path`, `line`, `family`, `evidence`,
   `function`), so the existing scoring, the proof arm and the pre-push admission consume them unchanged.
6. When a touched function holds no protected operation and reaches none, the prover shall emit nothing for it.

### Requirement 5: Scoring as a rule arm on the pool
**Objective:** As a maintainer, I want the prover scored on the training pool with the standard metrics, so that
its number stands beside the hunter arms and decides whether it becomes a G1 arm.

#### Acceptance Criteria
1. The runner shall run the prover over every change of a pool slice on the training clones, one checkout per
   change, and shall write one record per change in the replay record shape that `benchmarks.valid.metrics`
   scores (id, kind, repo, status, findings, bytes read, seconds).
2. The runner shall report recall on fix changes and on verified locations with Wilson intervals, false alarms
   per 100 ordinary pushes, precision, instrument failures, and seconds per change, and shall refuse to
   summarise when any record read zero bytes of a tree git holds.
3. The runner shall report a per-framework and per-repository coverage table: entry points found, touched
   functions reached, operations checked, functions unchecked by reason.
4. The runner shall checkpoint records per change and resume by skipping finished ones.
5. The record of a run shall carry counts, digests and framework names, never repository names of reserved
   populations, as the reserved-repository guard requires.

### Requirement 6: Budget
**Objective:** As a developer, I want the prover to finish inside the pre-push window, so that it can run on
every push.

#### Acceptance Criteria
1. The prover shall finish a change of the pool within 120 seconds on the development host, measured by the
   runner, and the runner shall list every change over that bound.
2. The prover shall reuse the per-change context caches (product files, texts, call index, file IR, entry
   points) and shall not walk or read the product tree more than once per change.

### Requirement 7: Coverage statement
**Objective:** As a developer, I want the tool to say what it did not check, so that no finding count reads as a
clean bill.

#### Acceptance Criteria
1. The prover shall return, with its findings, the counts of files by language, files whose framework was
   recognised, entry points found, touched functions reached and unreached, operations checked and discharged,
   and functions unchecked by reason (`parse_failed`, `language_unsupported`, `framework_unrecognised`,
   `unreached`, `no_facts`).
2. When the coverage statement shows zero recognised frameworks for a repository, the runner shall mark the
   repository `uncovered` in its summary, and recall for that repository shall be reported separately from the
   covered recall.

### Requirement 8: Proof-arm feed
**Objective:** As the proof arm, I want each finding to carry what a demonstration needs, so that a finding
can be proved or dismissed without re-deriving it.

#### Acceptance Criteria
1. Each finding shall carry the entry point record (kind, path, line, evidence), the hop list, the operation
   (id, kind, calls matched, line) and the missing discharger kind.
2. The finding id shall be `obligation:<operation kind>:<path>:<line>:<missing>` as the checker already emits.

### Requirement 9: The ordered trace is the prover's output for every examined pair
**Objective:** As the maintainer, I want every (entry, operation) pair the prover examined serialised as an ordered
trace with its verdict, so that a decision model sees the security-relevant structure and nothing else.

#### Acceptance Criteria
1. For every path record and every protected operation at its end, the prover shall emit one trace: the entry
   (kind, trust boundary, declared access, parameter names), each hop in order (function, the call line, the
   guards that dominate the call in that function with their kind, scope, line and provenance, the entry
   parameters and request-derived values forwarded through the call), the operation (kind, fact id, line, the
   provenance of each argument: request_input, authenticated_context, constant, unknown), the guards after the
   operation, and the verdict (required kinds, dominating kinds, missing kind or discharged).
2. The prover shall emit traces for discharged pairs and for unguarded pairs alike, and shall list unreached
   targets with their reason, so that negatives carry the same structure as positives.
3. The argument provenance shall be traced within each hop's function through the IR's binds from the entry's
   parameters and the request-source facts, forwarded through the call sites on the path; a value the trace
   cannot follow shall be `unknown`, never `constant`.
4. The trace shall carry no language, framework name, repository name, file size, line count, or any count over
   the function or the repository: only the ordered components above.
5. The prover-arm record shall carry the traces, and a trace shall serialise to one canonical text form (one
   component per line, in order) and one canonical JSON form, both deterministic.
6. The hunt defect of an unguarded pair shall reference its trace, so the proof arm and the pre-push admission
   can show the path.

### Requirement 10: Control flow decides dominance, and the trace says so
**Objective:** As the maintainer, I want a guard to count only when control flow makes the operation unreachable
without it, so that a check in a branch the attacker can avoid, or one whose result is ignored, is not a discharge.

#### Acceptance Criteria
1. The prover shall build a structural control-flow graph per function on a path from the syntax tree it already
   parses: statement blocks, if and else branches, switch arms, loops, try, catch and finally, return, throw,
   break and continue, and the function's exit; with no grammar for a construct the function shall be marked
   `cfg_unavailable` and judged by order with that degradation recorded.
2. A guard shall dominate an operation when every path from the function's entry to the operation passes the
   guard's statement (dominators over the graph); the trace shall record each guard's relation to the operation
   as `all_paths`, `some_paths`, `none` or `after`.
3. The trace shall record each guard's failure effect: `throws`, `returns`, `exits` (break, continue, exit call),
   `branches` (the operation lies only inside the guard's passing branch), or `value_only` when the guard's
   result is not consumed by a branch or an exit before the operation; a `value_only` guard shall not discharge.
4. The trace shall record the operation's control context: the branch conditions it sits under in order (the
   guard's own condition when it is one), whether it is inside a loop, inside a try whose catch swallows the
   guard's exception type, or on an exception path.
5. Router and decorator witnesses shall keep their scope semantics (they dominate the handler as a whole).
6. The parameter list of a Java entry shall carry parameter names only, never annotation names; the arguments
   of a handler-named operation shall be the handler's own parameters with their provenance.
7. The existing order-based dominance shall remain the default of the checker; the prover shall select the
   control-flow dominance, and the checker's tests shall stay unchanged.

