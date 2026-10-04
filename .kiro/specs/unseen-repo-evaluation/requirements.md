# Requirements Document

## Introduction

The safety net is meant for repositories it has never seen. This spec builds the instrument that measures that: a
frozen pool of unseen repositories, a push-level metric (catch rate and false-alarm rate as the hook reports them),
and an execution path that runs the replays as AX Tasks on the kube-ax cluster. Context: `brief.md`, the roadmap's
G0-G1 (`.kiro/steering/roadmap.md`).

## Boundary Context

- **In scope**: pool selection and freezing; change extraction (vulnerability-introducing and ordinary commits);
  replay of each change through `ousast pre-push` and through registered experiment arms; the metric and its
  confidence intervals; AX Task execution with kind/VM fallback; the baseline for today's hook; rotation of pool
  slices.
- **Out of scope**: any detection change; population v3 (stays reserved and unread); model calls inside the cluster.
- **Adjacent expectations**: `learned-decision-engine` experiments use this pool as their primary unseen-repo score;
  `pre-push-safety-net` owns the hook being replayed; `plane-on-kubernetes` and the AX executor
  (`benchmarks/learn/engine_trace_ax.py`) supply the execution pattern; the reserved-repository guard covers every
  population and this pool.

## Requirements

### Requirement 1: A pool no development step has touched

**User Story:** As the maintainer, I want the evaluation repositories to be ones nothing in development has seen, so a
good number means the approach generalises.

#### Acceptance Criteria

1. A repository is eligible only if it appears in no pair corpus, no population (v1, v2, v3), no harvest record, no
   memory example, no experiment unit and no measurement record. Eligibility is checked by code against every source
   before the pool is frozen; v3 is checked through the existing guard without being opened.
2. The pool is frozen (a committed manifest with repository URLs, commit SHAs, licences and the freeze digest) before
   any change in it is replayed. A frozen pool is never edited; a correction is a new pool.
3. Pool repositories are referenced only inside the pool's own directory (like `benchmarks/independent/`), and the
   reserved-repository guard is extended to them.
4. Only permissively licensed repositories are published by name; others may be used with their names kept out of
   the repository (pointers in a local, gitignored manifest), recorded as such.

### Requirement 2: Two kinds of change per repository

**User Story:** As the maintainer, I want both vulnerable and ordinary pushes from the same repositories, so the
false-alarm rate is measured on the code the catch rate is measured on.

#### Acceptance Criteria

1. Vulnerability-introducing changes: from public advisories with a linked fix, the commit range that introduced the
   vulnerable code where it can be determined, else the fix's parent compared with an earlier base; each labelled
   with family and the vulnerable function. Post-model-cutoff advisories are preferred and flagged.
2. Ordinary changes: commits from the same repositories' histories with no security fix, revert or advisory link,
   sampled across time and size; each recorded with its changed files and lines.
3. Per repository, at least one vulnerability-introducing change and several ordinary changes; the pool's totals are
   sized so the false-alarm rate's 95% interval is no wider than +/- 3 points and the catch rate's no wider than
   +/- 10 points (sizes computed in the design).

### Requirement 3: The push-level metric

**User Story:** As the maintainer, I want the score to be what a user would see, so the number means something.

#### Acceptance Criteria

1. Each change is replayed as `ousast pre-push --base <base> --head <head>` with the hook's default settings, in a
   clean checkout, with the record of every skipped check kept.
2. Catch: a vulnerability-introducing change counts as caught when the hook (or the arm) reports a finding of the
   right family on the vulnerable function or its changed lines. False alarm: an ordinary change counts as a false
   alarm when the hook reports any advisory finding.
3. Reported per family and overall: catch rate, false-alarm rate, and both with 95% Wilson intervals; plus coverage
   (changes where the hook could analyse the changed language) so a silent zero is visible.
4. Arms (decision engine, combiner, engine evidence, fix mechanisms) are scored on the same replays: catch rate at
   fixed false-alarm budgets (1%, 5%, 10%), so arms are compared at equal noise.

### Requirement 4: Execution on kube-ax, designed for AX

**User Story:** As the maintainer, I want the replays to run on the cluster, so measurements are fast and the VM is
free.

#### Acceptance Criteria

1. One replayed change is one AX Task, named with the `ousast-engine-` prefix the operator's egress watcher matches,
   using an image built `FROM ghcr.io/norandom/ax-task-runner:v0.3.1` with this package, Joern and php-cli, pinned by
   digest.
2. The task fetches the repository at the needed commits itself over HTTPS (public hosts are reachable from actors)
   and writes its record through a presigned link; no API keys or store credentials enter the cluster.
3. A generic AX batch dispatcher serves both this replay and the existing engine passes: items to Tasks, at most the
   cluster's safe concurrency (two heavy tasks per worker), retry once on sandbox death, then a VM or kind fallback
   lane; progress and resume as in the engine runner.
4. Arms that need model calls take the cluster's records and make their calls on the VM, within registered budgets.
5. kind runs the same tasks unchanged as the local fallback.

### Requirement 5: Baseline, rotation and use

**User Story:** As the maintainer, I want a baseline now and a fresh slice for each decision, so the pool is not
worn out by tuning.

#### Acceptance Criteria

1. The first use is a baseline of today's hook on the first slice; its record is committed (counts and digests only,
   no repository names outside the pool directory).
2. A slice that informed a change can no longer qualify that change; each adoption decision draws a new, untouched
   slice, recorded with its freeze digest.
3. Every learned-decision-engine experiment from now on reports its unseen-repo score from this pool next to its
   held-out-fold score.
