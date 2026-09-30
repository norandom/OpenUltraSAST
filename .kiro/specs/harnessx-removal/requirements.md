# Requirements Document

## Introduction

HarnessX is the optional agentic plane (`openultrasast[harnessx]`): an LLM hunter pool, an LLM judge and LLM
fusion panels, each behind a capability guard with a deterministic fallback, plus a lazy bridge that hosts
deterministic stages under a HarnessX processor. The ai-service-plane increment met its gate on google/ax
(`benchmarks/independent/plane-increment-2.json`), which is the condition the maintainer set on 2026-09-29:
"goal is to remove harnessx and to shift to ax fully once we establish we have value." This feature removes
HarnessX from the product and moves every LLM capability it carried either onto the plane or into a recorded
retirement. Inventory: `brief.md` (verified 2026-09-30).

## Boundary Context

- **In scope**: the HarnessX-only modules (`harness_ext.py`, `hunter_harness.py`); the guarded branches in
  `cli.py` (scan `--llm` path, `HxScanOrchestrator`), `verify_judge.py` (judge path), `fusion.py` (LLM panels),
  `stage_processors.py` (`host_under_harnessx`), `config.py` (`HarnessxConfig`); the `harnessx` extra, its mypy
  override and lock entry; the tests that exercise HarnessX; README and docs sections; dated retirement notes in
  the specs and steering that name HarnessX.
- **Out of scope**: changing the deterministic engine, rulesets or `evolve`'s validated/gated machinery; new
  detection logic; qualification on an independent population; the plane's own precision work (judge design) --
  where a capability moves to the plane, this spec wires it, it does not improve it.
- **Adjacent expectations**: every deterministic path (quick mode, `regress`, `benchmark`, `gate`, `evolve`)
  produces byte-identical output before and after; `vulnerabilities-over-plumbing` applies, so capabilities are
  kept or retired by what they detect, reported in TP/FP terms where a measurement exists.

## Requirements

### Requirement 1: Each HarnessX capability is moved or retired by an explicit decision

**User Story:** As the maintainer, I want every LLM capability HarnessX provided to have a recorded fate, so that
nothing is lost silently.

#### Acceptance Criteria

1. The design lists each capability -- LLM hunter pool (`ousast scan --llm`), LLM judge (`verify_judge`), LLM
   fusion panels (`fusion`), deterministic stages hosted under HarnessX (`host_under_harnessx`) -- with one of:
   moved to a plane task (named), or retired (with the evidence or reason).
2. A capability moved to the plane is reachable from the CLI through the plane (`ousast plane run` with a
   documented Run, or a CLI flag that submits one), binds its own Model per task (ai-service-plane Req 7), and
   has a fixture test like the other plane tasks.
3. A retired capability's CLI flags and config keys fail with a message that names the replacement or says it
   was retired, never a silent no-op.

### Requirement 2: HarnessX code, packaging and tests are gone

**User Story:** As the maintainer, I want no HarnessX code path left to maintain.

#### Acceptance Criteria

1. `harness_ext.py` and `hunter_harness.py` are deleted; no module imports `harnessx`; `use_harnessx`
   parameters, `has_harnessx` checks and `host_under_harnessx` are removed; the deterministic fallbacks become the
   only code path where a capability is retired.
2. The `harnessx` extra, the mypy override for `harnessx.*` and the lock entry are removed; `pip install .` and
   `pip install '.[all]'` (or whatever extras remain) succeed.
3. Tests that only exercise HarnessX are deleted; tests that assert fallback behaviour are kept and renamed to
   describe the behaviour, not the absence of HarnessX; the module audit is regenerated with no orphan.
4. A search for `harnessx` (case-insensitive) in `src/`, `tests/`, `pyproject.toml` and the README returns only
   the retirement notes of Requirement 4.

### Requirement 3: Deterministic behaviour is unchanged, and proven so

**User Story:** As the maintainer, I want evidence, not assurance, that removing HarnessX changed nothing a
deterministic run produces.

#### Acceptance Criteria

1. Before any deletion, a baseline is recorded without the extra installed: the full host suite, and the outputs
   of `ousast regress` and one `ousast benchmark` replay on the development pins, stored under
   `benchmarks/measurements/`.
2. After the removal the same commands produce byte-identical outputs (timestamps and durations excluded, and
   the exclusion list is written down); any difference blocks the merge.
3. A config file that still carries a `[harnessx]` section loads with one warning that names the plane, and the
   section is otherwise ignored.

### Requirement 4: Documentation and specs tell the new story

**User Story:** As a reader of the README or a spec, I want to learn that the agentic plane is ax, not HarnessX.

#### Acceptance Criteria

1. The README sections "Configuring the HarnessX agentic plane" and "The HarnessX self-improving cycle" are
   replaced by a short section on the ax plane that points at `ops/ax/README.md`; `docs/examples.md` section 6 and
   `docs/threat-model.md` (egress and spend caps) describe the plane's egress policy and budgets instead.
2. Specs that name HarnessX (`harnessx-self-improving-rulesets`, `learning-harness`, `three-stage-scan`,
   `openrouter-sast-harness`) and `.kiro/steering/overview.md` get a dated retirement note at the top; their
   history is not rewritten.
3. Maintainer-only Kiro tooling stays out of user docs (standing rule).

### Requirement 5: The removal lands in one reviewable sequence

**User Story:** As the maintainer, I want to review the removal in steps that each leave main green.

#### Acceptance Criteria

1. Order: baseline (3.1) -> capabilities moved or retired (1) -> code and packaging removed (2) -> equality proof
   (3.2) -> docs and specs (4). Each step is a commit gated on the full suite's own exit code, ruff and mypy.
2. No step deletes code whose replacement (Requirement 1) has not landed and passed its fixture test.
