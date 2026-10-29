# Code Standards (2026-10-29)

Applies to new code and amended code from this date. Existing modules are grandfathered
until their migration is scheduled in the breadth map; no mass renames.

## Specification level (the horizontal-capability rule)

Specifications describe the way and the concept, not per-target inventories.

- A spec defines **capabilities of the acquisition mechanism**: how recognition
  knowledge for any target is represented, proposed, verified, and promoted. It never
  enumerates a target's vocabulary (`ServletHolder`, `doNotifyCommit`,
  `voteOnAttribute`, ...) as work items or acceptance criteria.
- Per-target knowledge is **data** (fact rows, strategy registrations) produced through
  the acquisition pipeline -- an LLM can produce it per target; the engine verifies it.
- Concrete repositories and frameworks appear in specs only as **benchmark evidence**:
  named cases the acquired data must satisfy, never lists to implement.
- Litmus: if a requirement's acceptance criteria would not survive swapping the target
  repository family, the requirement is written at the wrong level. Lift it.

## Engine / target split (the anti-monolith rule)

The abstract-interpretation engine is agnostic. Target knowledge (framework names,
recognition vocabulary, WordPress/Stapler/Symfony/Jetty/Laravel specifics) never lives
inside engine modules.

- **Engine modules** (`semantic/obligations/check.py`, `dominance.py`, `cfg_dominance.py`,
  `paths.py`, `resolution.py`, `operations.py`, `trace.py`): no framework or product names.
  If a framework identifier appears in an engine module, the split has been violated.
- **Target knowledge lives in exactly two visible places:**
  1. **Data**: `ruleset/obligations/*.toml` and future fact files -- operation rows,
     discharger rows, handler-name families. Adding a framework's vocabulary is a data
     change, reviewable in one place.
  2. **Strategy modules**: one module per recognition concern under `mapping/` (registry
     pattern, see below), each file naming its target in its filename and registering
     itself in one table.
- **The system adjusts by growing data and strategies, never by editing the engine.** The
  fact-proposal lane (LLM proposes, engine verifies, repetition promotes to rows) is the
  automated path for the same rule.

## Pattern discipline (GoF)

- **Strategy + Registry** for entry recognisers: `mapping/` gains a recogniser registry;
  each framework family is one strategy module. New recognisers land there; the legacy
  blocks inside `mapping.py` migrate family by family (tracked in the breadth map).
- **Interpreter (data-driven)** for obligation facts: TOML rows are the language; the
  checker interprets them. New target vocabulary = new rows.
- **Adapter** at engine seams: `hunt/prover.py`'s callers adapter binds the IR to the
  caller index; witnesses flow into the checker through one interface
  (`check_obligations`).
- **Factory** for witnesses stays inside `obligations/enforcement.py` for now, but
  enforcement is a target-aware seam (it reads Symfony/Laravel/Tornado constructs): treat
  it as adapter territory; engine modules must not import it.

## Complexity caps

- Cyclomatic (McCabe) complexity: **<= 10 per function**.
- Logical lines of code: **<= 50 per function, <= 400 per new module**.
- A task is not done while a function it touched exceeds the caps; split the function.
- Automated gate (ruff C901 / xenon in CI) is not wired yet; caps are enforced at review
  time. Wiring the gate is tracked in the breadth map.

## Idiomatic naming

- Names state what a value semantically is, in the pipeline's vocabulary: `entry_point`,
  `trace`, `obligation`, `witness`, `discharge`, `finding`, `judgment`.
- Collections name their elements: `entry_point_records`, `judgments_by_key`,
  `findings_by_push`. Mappings use `_by_<key>`; sequences are plural. No `eps`, `recs`,
  `d2`, `tmp2`.
- Booleans are predicates: `is_public`, `has_dominating_guard`, `dominates_entry`. Avoid
  negated names (`not_unflagged`).
- Row/record destructuring uses the record's field names, not positional `a, b`.
- Renaming debt in existing modules is recorded in the breadth map, not fixed drive-by.
