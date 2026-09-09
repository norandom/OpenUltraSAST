# Design Document: finding-feedback-loop

## Overview

Three of nine engine defects found in one session were the same bug in three matchers: a spec token matched as
a substring rather than a word. Each was fixed locally and left no trace, and the third survived until an
89k-line C library made it visible as 26 identical false positives. This feature gives a rejected finding
somewhere to live, groups rejections by what they share, and lets a model propose the cause without deciding
anything.

The design turns on one asymmetry: **two of those three bugs needed no judgement at all.** Once the first was
understood, the other two were the same fix carried across. So the automation that pays is *propagation and
memory*, and the model is confined to the one step that genuinely needs inference — naming what a group has in
common.

### Goals

- A dismissal a developer commits beside their code, which the tool reads and never writes.
- A ledger that turns every rejection into a runnable regression case.
- Grouping by shared cause, so a recurring bug is visible as one bug.
- Prompt evolution scored on a split that the holdout never leaks into.

### Non-Goals

- **Automated fact-table edits.** Not deferred — prohibited. See Boundary Commitments.
- Suppressing findings silently. A dismissal makes a finding *labelled*, never invisible.
- A general-purpose optimiser. The only surfaces evolved are two prompt constants.
- Replacing the pair corpus. It is the holdout that keeps per-repository tuning honest.

## Boundary Commitments

### This Spec Owns

- `dismissals.toml` in a target repository: its schema, its reader, and the rule that nothing writes it.
- `benchmarks/ledger/`: counter-examples, their grouping, and their regression cases.
- The review queue a proposal lands in.
- The evolution harness over `CANDIDATE_QUESTION` and `residual_question`.

### Out of Boundary

- `semantic/facts`, `semantic/obligations`, `ruleset/`, the declared policy file — **no automated writer, by
  any path, at any time.** This is the boundary the whole design exists to respect.
- The three gates. They are the invariant an adoption is measured against, not a thing this spec changes.
- `model/taint.py`, `dominance.py`, `config_value.py` — arbiters are fixed here; a proposal that would change
  one is a proposal for a human, not an edit.

### Allowed Dependencies

Standard library, `tomllib`, and the existing model/endpoint client. Core `dependencies = []` holds: an
evolution run is a maintainer operation behind an extra, never part of `ousast scan`.

### Revalidation Triggers

- A second true-positive repository appears → the evidence base changes and every adoption number is restated.
- The pair corpus splits change → every train/holdout claim is recomputed.
- An arbiter changes → the ledger's regression cases are re-run before anything is adopted.

## Architecture

### Existing Architecture Analysis

Three pieces already exist and are reused rather than rebuilt:

- **`benchmarks/repos/*.toml`** declares known vulnerabilities per checkout, with `in_scope` stating whether a
  family can decide one at all. That is the positive half of an evaluation set, already committed.
- **`pairs.py`** already carries a train/holdout split and the machinery that respects it. The leak of
  2026-09-05 was in the *lever*, not the splitter — `semantic/loo.evaluate_loo` was honest throughout.
- **`redaction.py`** is applied to every prompt and persisted trajectory, and applies here unchanged.

### Boundary Map

```
target repository                     this spec                      unchanged
──────────────────                    ──────────                     ─────────
.openultrasast/                       ledger/                        semantic/facts
  dismissals.toml  ── read ─────────▶   entries + groups             semantic/obligations
  (never written)                       regression cases             ruleset/
                                        review queue                 the three gates
benchmarks/repos/*.toml ── read ────▶   evaluation set               model/*.py arbiters
  known vulnerabilities                 (train / holdout)
                                        │
                                        └── evolves ──▶ CANDIDATE_QUESTION
                                                        residual_question
```

### Key Decisions

**A dismissal is a label, not a suppression.** A suppressed finding disappears and its reason rots; a
labelled one is reported as dismissed with its reason, and a dismissal that stops matching is reported too.
This is what turns a suppression list into the negative half of an evaluation set — the thing that makes the
rest of the feature possible.

**The tool never writes the dismissal file.** Same rule as the declared policy file, for the same reason: a
file the tool edits is a file no reviewer trusts. It is committed by a developer and reviewed like code.

**Grouping is deterministic; only the hypothesis is not.** Entries are grouped by shared spec token, matcher
clause, family and witness shape — all mechanical. The model is asked one question about a group it did not
choose, and its answer goes to a queue. This keeps the inference confined to the step that needs it.

**Evolution targets the question, never the facts.** A prompt is how we ask; a fact table is what we claim.
`CANDIDATE_QUESTION` and `residual_question` are already the LLM-facing surface and are the only mutable
targets. Enforced by a test that fails if any writer touches the fact modules, not by convention.

**The holdout is never read.** Not "should not" — the evaluation-set API has no path to it during
optimisation, and a test asserts the absence. The 2026-09-05 leak was possible because reading it was merely
discouraged.

## File Structure Plan

### New

```
src/openultrasast/feedback/
├── dismissals.py    # read a target repo's dismissals; never write
├── ledger.py        # counter-example entries, grouping, regression cases
├── evaluate.py      # per-repository evaluation set + train/holdout split
└── evolve.py        # reflective evolution over the two question constants

benchmarks/ledger/
├── README.md        # what an entry is and why it is committed evidence
└── entries/*.toml   # one counter-example per file
```

### Changed

- `cli.py` — a `feedback` subcommand: `ledger`, `groups`, `propose`, `evolve`. Maintainer surface; `scan`
  gains only the dismissal read.
- `reports.py` — a dismissed finding is rendered as dismissed with its reason.

### Unchanged and load-bearing

`semantic/facts`, `semantic/obligations`, `ruleset/`, the three gates, `model/` arbiters, `redaction`.

## Components and Interfaces

### feedback/dismissals.py

```python
@dataclass(frozen=True)
class Dismissal:
    site: str          # path:line:function, the same shape a finding's id carries
    rung: str          # the rung it was dismissed AT; a later stronger claim is not covered
    reason: str        # required; a dismissal without one is rejected at load
    author: str
    added: str

def load_dismissals(repo: Path) -> tuple[Dismissal, ...]: ...
def applied(findings, dismissals) -> tuple[list[Finding], list[Dismissal]]:
    """Findings marked dismissed, and the dismissals that matched nothing."""
```

Dismissing at a rung rather than outright is deliberate: "this is not a defect at `suspicion`" must not
silence the same site when the graph later *entails* it. That is a promotion, and it deserves a fresh look.

### feedback/ledger.py

```python
@dataclass(frozen=True)
class CounterExample:
    site: str
    rung: str
    witness: str
    tokens: tuple[str, ...]     # the spec tokens that produced it
    clause: str                 # which matcher clause fired
    family: str
    commit: str
    source: str                 # "dismissal" | "judge_contradiction" | "declared_contract"

def group(entries) -> tuple[Group, ...]:
    """Deterministic grouping by shared token, clause, family, witness shape."""
```

`tokens` and `clause` are what make the three matcher bugs one group: all three were a spec token matching by
substring, and recording *which clause fired* is what a witness alone would not have told us.

### feedback/evaluate.py

```python
def evaluation_set(recipe, dismissals, *, split: str) -> EvalSet:
    """Positives from the recipe's known vulnerabilities, negatives from dismissals.

    `split` is "train" or "holdout". There is no "all", and no argument that returns both.
    """
```

The missing "all" is the design. An API that cannot express *read everything* cannot leak the holdout by
accident, which is exactly how the last one leaked.

### feedback/evolve.py

```python
def propose(group, *, client, model) -> Proposal: ...     # to a review queue, never to disk under src/
def evolve(questions, evalset, *, rounds: int) -> Evolution: ...
def adopt(evolution) -> AdoptionRecord | None:
    """None unless: fewer dismissed sites affirmed, no known vulnerability lost, gates byte-identical."""
```

## Testing Strategy

- **The prohibition is a test, not a comment.** Assert no module under `feedback/` imports a writer for
  `semantic/facts`, `semantic/obligations` or `ruleset/`.
- **The holdout is a test.** Assert `evaluation_set` has no code path returning holdout rows during
  optimisation.
- **The model's role is a measurement.** Revert the three matcher fixes, run grouping and proposal, and record
  how many known causes it recovers. This is the acceptance test for Requirement 3.4 and it runs offline
  against committed ledger entries.
- **A dismissal without a reason fails to load**, and a dismissal that matches nothing is reported.

## Risks

**The evidence base is two repositories, one of which has never produced a true positive.** An optimiser tuned
on that is tuned on very little, and Requirement 7 exists to keep it labelled rather than to pretend
otherwise. The honest sequencing is that this feature's *ledger and dismissals* are useful immediately, while
its *evolution* should not be trusted until `contributor-scan` 2.15 or 5.2 adds a checkout that can produce a
true positive.

**Per-repository tuning is overfitting with a nicer name.** The pair corpus is the only thing standing
against it, which is why the gates are an adoption criterion rather than a report line.
