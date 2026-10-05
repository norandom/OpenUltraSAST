# Requirements Document

## Introduction

Add a search-with-proof stage: for the top-ranked candidates of a push or a labelled pair, sandboxed tool-using agents
search for a demonstration of the vulnerability, coordinated through a fact/intent board, executing primarily in the
kube-ax cluster. BLOCK becomes "demonstrated", not "scored above a threshold". Context: `brief.md`, roadmap G1-G2,
`unseen-repo-evaluation` (the pool and metric this arm is judged by).

## Boundary Context

- **In scope**: the board (facts, intents, hints) in the memory store; reason and explore steps as AX Tasks; the
  demonstration contract and its verification; triage-to-search budgeting; a pilot on known fix pairs; a G1 arm on the
  unseen pool; model access through an operator-managed scoped key.
- **Out of scope**: copying Cairn code (AGPL-3.0); network actions against anything but the code under analysis;
  changing the existing quick rules, engine or classifier (they are inputs here).
- **Adjacent expectations**: `unseen-repo-evaluation` scores this arm; the AX batch dispatcher (`benchmarks/ax/batch.py`)
  and the kube-ax constraints (2 heavy lanes, `ousast-engine-` names, egress to public HTTPS) apply;
  `learned-decision-engine` Req 6.4 BLOCK rule is superseded for this arm by "demonstrated".

## Requirements

### Requirement 1: The board

**User Story:** As the maintainer, I want each search to keep its state, so exploration builds on what is already
known instead of restarting.

#### Acceptance Criteria

1. Per search (one candidate or one push), the board holds facts (confirmed, objective, with the evidence that
   confirmed them), intents (declared directions, open or concluded, with the facts they start from) and hints (human
   input, absorbed on the next read).
2. The board lives in the memory store, versioned, and every fact and intent carries the step and the task that wrote
   it.
3. A search ends when a fact meets the goal (Requirement 3), when its budget is spent, or when the reasoner proposes no
   new intent and none is open; the end reason is recorded.

### Requirement 2: Reason and explore steps

**User Story:** As the maintainer, I want the search driven by the board's state, not by fixed roles.

#### Acceptance Criteria

1. A reason step reads the board and returns: the goal is met (citing facts), or at most N new, independent,
   non-overlapping intents, or no new intent.
2. An explore step claims one intent, works it with tools inside the sandbox (read files, search the repository,
   follow callers, build, run tests and scripts against the code under analysis), and returns exactly one new fact or
   a recorded failure.
3. Both run as AX Tasks in the kube-ax cluster by default; the VM coordinates (board, dispatch, budgets) and is a
   fallback lane only.
4. Parallel explores of one search never race on the board (claims as in the batch dispatcher).

### Requirement 3: The demonstration contract

**User Story:** As the maintainer, I want BLOCK to mean "shown", so precision does not depend on calibration.

#### Acceptance Criteria

1. A demonstration is an executable artefact (test, script or request sequence) that the system, not the agent,
   re-runs in fresh sandboxes. The **verifier observes the effect itself** through a per-family oracle it owns (for
   example a request log, a planted resource it watches, a browser execution check for XSS); the artefact's own exit
   code or output is never the oracle.
2. Each family's oracle states the attacker boundary (what the artefact may touch: only the documented external
   inputs of the code under analysis, never the verifier's fixtures, the source tree, dependencies or the runtime).
   Inputs are immutable during a run; untracked files, dependency replacement and runtime patching are refused.
3. Differential: for a labelled pair the effect is observed on the vulnerable revision and not on the fixed one; for a
   push, on head and not on base. Both sides must build and pass a readiness check independently; a side that fails
   to build or start makes the result **inconclusive**, never a pass. Each side is run at least three times from fresh
   state; inconsistent runs are rejected.
4. Only a verified demonstration counts as `demonstrated`. Outcomes: `demonstrated`, `plausible_unproven`,
   `could_not_build`, `could_not_run`, `inconclusive`, `no_oracle` (family without an owned oracle), `no_evidence`;
   none of the failure outcomes is ever reported as "not vulnerable".
5. Families without an owned oracle (for now: deserialisation, access control, configuration and secrets) can reach
   `plausible_unproven` at most until an oracle is specified and reviewed.

### Requirement 4: Triage and budget

**User Story:** As the maintainer, I want search spent where it matters, at a known cost.

#### Acceptance Criteria

1. Candidates come from the existing layers (quick rules, engine, classifier scores); only the top K per push or per
   pair side are searched; K and the per-search and per-push budgets (model spend, task count, wall time) are
   configuration, enforced by the coordinator.
2. Every search records its model spend, task count and wall time. Spend is **reserved before each model call** (the
   call's maximum cost) and released after; wall time, memory, disk and retries are capped per task and in total; a
   budget is never exceeded, including by calls in flight.
3. Paid runs need the maintainer's budget go-ahead with a ceiling, as all paid steps do.

### Requirement 5: Model access in the cluster

**User Story:** As the maintainer, I want agents in the cluster to reach a model without spreading keys.

#### Acceptance Criteria

1. The agents' model key is a scoped, budget-limited key provided by the operator inside the cluster (AX v0.3.1
   injects only `gemini-api-secret` as `GEMINI_API_KEY`; the design names the exact mechanism agreed with the
   operator). Store credentials stay out of the cluster (presigned links, as today). For this arm, model calls inside
   the cluster supersede `unseen-repo-evaluation` Req 4.4 (model calls on the VM); that boundary is unchanged for all
   other arms. *(maintainer decision 2026-10-05: scoped key in the cluster)*
2. The key never appears in a manifest, a log, a board entry or a record, and is not readable by the repository code
   the sandbox executes (the model client and the executed code are separated).

### Requirement 6: Feasibility pilot, false-proof qualification, then the unseen pool

**User Story:** As the maintainer, I want to know quickly whether search with proof works, and to admit BLOCK only on
evidence that meets the 95% precision bar.

#### Acceptance Criteria

1. **Feasibility pilot** (amended 2026-10-05 after review): about 20 known fix pairs from development corpora. It
   measures feasibility only and is reported as such: demonstrated rate on vulnerable sides, false proofs on fixed
   sides, `could_not_build` / `could_not_run` / `inconclusive` / `no_oracle` rates, spend, tasks and wall time. Its
   advantages (known location, labelled family, runnable-project bias) are stated in the record. Fixed-side searches
   never receive the vulnerable revision or its demo.
2. Before any paid search, an infrastructure probe without model calls proves each owned oracle works inside a gVisor
   AX Task (database fixture for SQL, in-sandbox listener for SSRF, headless browser for XSS, file and process
   watches), that the artefact cannot reach the observers directly, and records image size, RAM and the full
   verification cost (up to 3 demos x 2 sides x 3 runs per search). Pilot exit: at least one family with at least 5 verified demonstrations on vulnerable sides and zero false proofs;
   otherwise the result is recorded and the arm is not scaled.
3. **BLOCK admission per family** (deferred until the pilot passes; not part of the first tasks) requires a false-proof
   qualification. A **negative** is a search on code that should be safe: a fixed revision searched on its own (the
   search never sees the vulnerable revision), or an ordinary change. A **false proof** is the verifier observing the
   effect on that safe code, confirmed by adjudication (an ordinary-change alarm may be a real new bug and is
   adjudicated before it counts either way). Qualification needs zero false proofs over at least 73 negatives drawn
   from at least 73 distinct repositories, so the Wilson 95% upper bound on the false-proof rate per negative is at
   most 5%. This bounds the false-proof rate, not precision among flags; precision is reported separately from the
   pool. Repeated runs and repeated searches of one repository are one negative.
4. **Coverage ceilings**: every run reports, separately, (a) the demonstrated ceiling: the share of vulnerable changes
   with a true candidate selected, an owned oracle, both sides runnable and a genuine differential, build and run
   failures in the denominator; and (b) the advisory ceiling: the share with a true candidate selected. Families
   without an owned oracle (access control, deserialisation, configuration and secrets) have a demonstrated and BLOCK
   ceiling of zero today; their advisory ceiling need not be zero.
5. **G1 arm on the unseen pool**: scored with the pool's rules on **every visible finding** (BLOCK and advisory), with
   its family and location match; catch at the 1%, 5% and 10% false-alarm budgets; compared with the classifier arms;
   adopted only under the pool's no-regression rule on a fresh slice. No evaluation label, fixing revision or board
   from evaluation searches is ever an input to unseen search.
6. Delayed results (a search finishing after the push) reach the user through the existing background delivery and
   are scored separately from results available at push time.
