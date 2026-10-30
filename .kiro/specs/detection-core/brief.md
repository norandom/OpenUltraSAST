# Brief: detection-core

## Problem

Detection in this project is specified as a set of per-family, per-arm runners (prover,
hunter, hook, proof arm). Corrections patch one arm and do not compose: v1→v2 retunes
transferred 0/17 on untouched cases, and the 2026-10-30 admission run returned NO-GO
(0/12 pairs, in-family 0/3, 9/12 pilot repositories with zero framework recognition).
Learned components have nothing constraining them, so DSPy fitted a shape shortcut
(deletion count separates reversed fixes at 0.90). The root cause: the core security
object — one deterministic, checkable artifact per change that makes a defect claim
provable (with witness) and a non-claim bounded (with coverage) — was implicit, never
specified.

## Current State

- The ordered trace exists for one family: `access-control-prover` implements entry →
  hops → operation → witnesses → dominance → three-way judgment, with digests and the
  Req 12 admission workflow (dev pool + untouched admission pool). 13.3's four-arm run
  proved attribution works around the trace (analyzer_only −246 unguarded).
- Measured ceilings of the chain: entry recognition (9/12 pilot repos unrecognized),
  call resolution (11.9% complete), guard dominance coarseness, 120s pre-push budget
  (whole-repo CPGs do not fit: libpng 446s, 637-file PMPro does not load).
- `valid-detection-benchmark` provides the measurement instrument; `detection-quality.md`
  (steering, 2026-10-30) holds standing rules and pre-registered stop conditions.

## Desired Outcome

One specified core object — the security trace — with a contract that every detection arm,
fact pack, and consumer reuses: given a push (base, head) within a fixed budget, output
proven defect claims (each with its witness) plus explicit coverage of what was not
decided, on repositories never seen. No fitted component ever sees pool labels.

## Approach

Specify the trace as the core: scope (change regions, hard budget) → recognize (counted
entry/operation coverage) → resolve (every call in one completeness bucket) → trace
(entry → hops → operation → witnesses → dominance → judgment → digests) → verdict (proven
claim | bounded silence). Models are bounded to residuals: zero-shot judge on the trace,
hunter proposes trust boundaries, proof arm demonstrates (only BLOCK evidence). Admission
on an untouched population gates the trace itself.

## Scope

- **In**: trace schema and witness algebra; three-way judgment; budget/scoping contract;
  coverage accounting (funnel, resolution buckets, named incompleteness reasons); digest
  and provenance fields; admission-gate contract (Req 12 workflow generalized); the
  anti-shortcut rule for any fitted component (reversed-pair probes, per-repo holdout,
  untouched-population admission); re-parenting map of existing specs onto the core.
- **Out**: new vulnerability families; per-framework fact content (that is fact-pack work,
  e.g. recognition-coverage table task 7.1 in valid-detection-benchmark); the pre-push
  transaction itself (pre-push-safety-net consumes the core); engine internals.

## Boundary Candidates

- Core trace object and verdict contract (this spec).
- Fact packs: per-family recognition/operation/guard facts, admission-gated (extension
  point, starting with access_control from access-control-prover).
- Consumers: pre-push-safety-net (push transaction), search-with-proof (BLOCK evidence),
  hunter-learning-loop (proposal lane only).

## Out of Boundary

- The pre-push hook transaction and rollout policy.
- New detection families beyond what the trace contract enables.
- Fitted models of any kind in the core path.
- Engine/CPG internals (contributor-scan owns those).

## Upstream / Downstream

- **Upstream**: `valid-detection-benchmark` (measurement instrument, dev + admission
  pools), `access-control-prover` (trace implemented for access_control), steering
  `detection-quality.md` (standing rules and stop conditions).
- **Downstream**: `pre-push-safety-net` (M-series milestones), `search-with-proof`,
  `hunter-learning-loop`, future fact-pack specs per family/ecosystem.

## Existing Spec Touchpoints

- **Extends**: `access-control-prover` — its trace schema, judgment vocabulary and
  admission workflow become the core contract, generalized across families.
- **Adjacent**: `pre-push-safety-net`, `search-with-proof`, `hunter-learning-loop`,
  `valid-detection-benchmark`, `contributor-scan` — consumers/instruments; must not
  duplicate the trace contract.

## Constraints

- Pool measures, never trains: no fitted prompt/threshold/model on pool labels
  (detection-quality.md rules 4-5, 13-proposal).
- Fixed measurement schema: population + freeze digests, judgment vocabulary, rates with
  n and Wilson 95%, coverage, instrument failures, runtime.
- Budget is measured, not static: per-change reply time and complexity are recorded, and
  the budget is derived from the measured distribution per workload class (sample, percentile,
  hardware disclosed); scoping to the change is part of the core contract.
- Instrument rule: prove nonzero input reads before interpreting any zero.
- Plain English in all documents; standard metrics only.
