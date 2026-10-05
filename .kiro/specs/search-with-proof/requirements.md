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
   re-runs in a fresh sandbox: it fails (shows the vulnerable behaviour) on the vulnerable revision and passes on the
   fixed revision for a labelled pair; for a push it shows the behaviour on head (and not on base where the change
   introduced it).
2. Only a re-verified demonstration counts as a demonstrated finding. The agent's own claim of success is never enough.
3. Outcomes are recorded as `demonstrated`, `plausible_unproven` (evidence but no passing demonstration),
   `could_not_build` / `could_not_run` (environment failures), or `no_evidence`; none of the failure outcomes is ever
   reported as "not vulnerable".

### Requirement 4: Triage and budget

**User Story:** As the maintainer, I want search spent where it matters, at a known cost.

#### Acceptance Criteria

1. Candidates come from the existing layers (quick rules, engine, classifier scores); only the top K per push or per
   pair side are searched; K and the per-search and per-push budgets (model spend, task count, wall time) are
   configuration, enforced by the coordinator.
2. Every search records its model spend, task count and wall time; a budget is never exceeded.
3. Paid runs need the maintainer's budget go-ahead with a ceiling, as all paid steps do.

### Requirement 5: Model access in the cluster

**User Story:** As the maintainer, I want agents in the cluster to reach a model without spreading keys.

#### Acceptance Criteria

1. The agents' model key is a scoped, budget-limited key provided by the operator inside the cluster (AX v0.3.1
   injects only `gemini-api-secret` as `GEMINI_API_KEY`; the design names the exact mechanism agreed with the
   operator). Store credentials stay out of the cluster (presigned links, as today).
2. The key never appears in a manifest, a log, a board entry or a record.

### Requirement 6: Pilot, then the unseen pool

**User Story:** As the maintainer, I want to know quickly whether search with proof works before scaling it.

#### Acceptance Criteria

1. Pilot: about 20 known fix pairs across families and languages; for each, search runs on the vulnerable side and
   on the fixed side under the same budget. Reported: demonstrated rate on vulnerable sides, any demonstration on a
   fixed side (a false proof, which must be zero), environment-failure rate, spend and wall time per search.
2. Exit of the pilot: at least one family with demonstrations on vulnerable sides and zero false proofs; otherwise
   the result is recorded and the arm is not scaled.
3. Then a registered G1 arm on the unseen-repo pool: catch rate at the pool's false-alarm budgets, with BLOCK only on
   demonstrated findings, compared with the classifier arms.
