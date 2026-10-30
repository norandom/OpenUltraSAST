# Requirements Document

## Project Description (Input)

**Who has the problem:** the maintainer of OpenUltraSAST. Every detection arm built so far
(prover, hunter, push hook, proof arm) is corrected link by link, and corrections do not
compose — v1→v2 retunes transferred 0/17 on untouched cases, and the 2026-10-30 admission
run on the untouched pilot population returned NO-GO (0/12 pairs, in-family 0/3, 9/12
repositories with zero framework recognition).

**Current situation:** detection is specified as per-family, per-arm runners around an
implicit core. The ordered trace exists for one family (access-control-prover), learned
components fit pool shortcuts (deletion count separates reversed fixes at 0.90), and
misses concentrate in unmeasured links: entry recognition, call resolution (11.9%
complete), guard dominance, and the 120s pre-push budget.

**What should change:** one specified core object — the security trace — with a contract
every arm, fact pack, and consumer reuses: given a push (base, head) within a fixed budget,
output proven defect claims (each with its witness) plus explicit coverage of what was not
decided, on repositories never seen. Models are bounded to residuals; admission on an
untouched population gates the trace itself; no fitted component ever sees pool labels.

## Requirements

### Requirement 1: Canonical trace object
The detection core shall define one canonical trace object per analyzed change as the
shared security object for all detection arms.
1. When a change is analyzed, the detection core shall produce a canonical trace carrying
   entry identity, ordered hops with call-target completeness, operation kind with resource
   and authority, witnesses with provenance and match relations, guard effects, completeness
   reasons, a final judgment, and the input digests of the analysis.
2. The detection core shall serialize every trace deterministically, so that identical
   inputs produce byte-identical traces.

### Requirement 2: Three-way judgment vocabulary
The detection core shall judge every analyzed operation as exactly one of unguarded,
discharged, or indeterminate.
1. The detection core shall never convert an indeterminate judgment into a clean
   (discharged or unguarded-free) result.
2. When evidence for a judgment is incomplete, the detection core shall return
   indeterminate with the named incompleteness reasons.

### Requirement 3: Coverage accounting
The detection core shall account for every input it did or did not use, so a zero result is
never indistinguishable from an unread input.
1. When a change is analyzed, the detection core shall report entry-recognition coverage,
   per-call resolution outcomes with exactly one outcome bucket per call, and named
   reasons for every unchecked operation.
2. If any input file is read as zero bytes, the detection core shall fail the run as an
   instrument failure rather than reporting a clean result.

### Requirement 4: Measured budget and change scoping
The detection core shall derive its time budget from measurement, not from a fixed constant.
1. When a change is analyzed, the detection core shall measure and record reply time and
   change complexity (changed regions, call count, changed size) for every change.
2. The detection core shall derive the per-change budget from the measured distribution
   (sample count, percentile, reference workload and hardware disclosed) and shall publish
   that derivation under the fixed measurement schema; the budget shall be configurable per
   workload class, never a single static constant.
3. When a change exceeds the measured budget, the detection core shall fail the budget gate
   naming the change, the elapsed time, and the budget derivation exceeded.
4. While a push is analyzed, the detection core shall limit analysis to regions affected by
   the change and shall record the scope it used.

### Requirement 5: Verdict contract
The detection core shall distinguish proven defect claims from bounded silence.
1. When the detection core reports a defect, the claim shall carry its witness evidence and
   an exact location tied to the change.
2. When the detection core cannot decide a site, it shall report that site as undecided
   with its coverage reason, and shall never present an undecided site as a clean result.

### Requirement 6: Provenance and digests
The detection core shall stamp every trace and verdict with the identities of its inputs.
1. The detection core shall record, for every analysis, the analyzer revision, fact-set
   digest, acquisition-record digest, configuration digest, population digest, and
   per-change input digest.
2. If any recorded digest cannot be re-derived from the named inputs, the detection core
   shall refuse the result rather than accept it.

### Requirement 7: Admission gate contract
The detection core shall gate any generalization claim on an untouched population.
1. When an arm is proposed for pre-push use, the detection core shall require a reviewed
   manifest naming the frozen analyzer, facts, acquisition, configuration, and an untouched
   admission population before any admission label is opened.
2. The detection core shall consume admission manifests without producing, mutating, or
   re-labeling them, and shall refuse manifests that are unreviewed, label-exposing,
   acquisition-changed, or spent.
3. When admission evidence is scored, the detection core shall report paired
   vulnerable/fixed behavior, ordinary false alarms, and every gate (budget, instrument,
   pre-registered criteria) as an evidence-backed GO or NO-GO.

### Requirement 8: No fitting on evaluation labels
The detection core shall not allow any fitted component to train on evaluation labels.
1. The detection core shall prohibit tuned prompts, thresholds, or fitted models whose
   training data includes pool or admission labels.
2. When a fitted component is proposed, the detection core shall require it to pass
   reversed-pair probes (a fix and its reversed fix shall not be separable by the
   component's decision features), per-repository holdout, and admission on an untouched
   population before any claim is made.

### Requirement 9: Bounded role for models
The detection core shall bound every model to residual questions over the trace.
1. Where a model judges a trace, the detection core shall present the deterministic trace
   and require the judgment to be zero-shot over that trace.
2. The detection core shall not allow a model to propose-and-adjudicate the same claim, and
   shall reserve blocking verdicts for demonstrated proofs with a differential witness.

### Requirement 10: Family fact packs as the extension point
The detection core shall admit new vulnerability families only as fact packs over the core
trace contract.
1. When a new family is added, the detection core shall require the family's entry,
   operation, and guard knowledge as reviewed fact packs stamped into the trace's
   provenance, without changing the trace schema or judgment vocabulary.
2. The detection core shall report, per arm, the vulnerability families the arm claims, so
   admission and rollout numbers are never read across families the arm does not cover.

### Requirement 11: Consumer and re-parenting contract
The detection core shall be the single contract that existing detection specs reuse.
1. The detection core shall define the interface through which the pre-push transaction
   consumes traces and verdicts within its deadline.
2. The detection core shall define the interface through which proof-based blocking evidence
   attaches to a trace verdict.
3. When an existing arm's behavior is described, the detection core shall require that
   description to be expressed over the core contract rather than as a separate runner
   contract.

### Requirement 12: Fixed measurement schema
The detection core shall require one fixed measurement schema for every detection number.
1. When any detection result is reported, the detection core shall require population and
   freeze digests, judgment vocabulary, every rate with its sample count and uncertainty
   interval, coverage, instrument failures, and runtime.
2. When a measurement changes population or judgment vocabulary, the detection core shall
   treat the result as a new baseline and shall not present it as a trend against the
   previous baseline.

## Out of Scope
- The pre-push hook transaction, rollout policy, and capability registry (pre-push-safety-net).
- New vulnerability families and their fact content (fact-pack specs).
- Fitted models of any kind in the core path.
- Engine and graph internals (contributor-scan).
