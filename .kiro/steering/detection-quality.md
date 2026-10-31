# Detection quality: standing rules (2026-10-30)

Detection on unseen repositories is the binding constraint of this project. The rules below
extend the 2026-10-28 gate-5 decision and the Req 12 admission workflow to every spec that
touches detection. Where this file disagrees with older spec text, this file wins for
detection claims.

## Ordering

1. Recognition, then resolution, then judgment. No new fact families, no judge-prompt
   tuning, and no per-framework patching cycles until entry recognition and call resolution
   are measured on the valid pool's ecosystems.
2. The injection-family spec stays deferred: its gate-5 condition (the post-fix pilot holds
   recall with false alarms moving toward the gate) is **not met**. The 2026-10-30 admission
   run on the untouched pilot population returned NO-GO: 0/12 pairs, in-family 0/3, 9 of 12
   repositories with zero framework recognition (`benchmarks/measurements/2026-10-30-access-control-admission/`).

## Comparability

3. Every detection measurement publishes one fixed schema: population digest and freeze
   digest, judgment vocabulary, recall / false alarms per 100 / precision / pair
   correctness each with n and Wilson 95%, coverage, instrument failures, runtime. A change
   of population or vocabulary starts a **new baseline**; "worse than last turn" claims
   across vocabularies are invalid. The 2026-10-28 baseline used a binary vocabulary and the
   2026-10-30 amended prover uses the strict three-way lane: 65.2% and 34.8% recall are
   different instruments, not a regression line.

## Admission before generalization

4. Any detection arm that will feed a pre-push claim must have a development population and a
   separate untouched admission population, consumed through the Req 12.1-12.9 workflow
   (freeze before labels, manifest validation, paired scoring, gates, GO/NO-GO).
5. No tuning of facts, strategies, thresholds, prompts or judges on admission labels.
   Observing labels during acquisition marks the population spent (Req 12.3).
6. Admission and rollout reports state the vulnerability families the arm claims (the prover
   claims access_control only; the pilot population holds 3 of 12 in-family).
7. Retired and spent populations stay retired: no number from the SZZ pool or the
   independent v1/v2 populations is quoted anywhere.

## Instrument and honesty

8. A zero from an unread input is a failed run. Every measurement artifact proves nonzero
   input reads (hook bytes, record counts) before any clean or zero result is interpreted.

## Rollout shape

9. Rollout is per capability, per ecosystem, advisory first (M5 already permits this). BLOCK
   only on a demonstrated proof (search-with-proof), never on a confidence score.

## Failure modes and stop conditions

A self-correcting plan can still converge to failure; correction without a stopping rule is
slower failure. These conditions are pre-registered now, before the next workstream starts:

10. **Two consecutive admission NO-GOs on the same arm against the same pre-registered
    criteria park that arm.** Parked arms are not patched incrementally; they go to a
    strategy review with the maintainer (the 2026-09-28 strategy-review pattern).
11. **If the entry-recognition + resolution workstream does not move admission past the
    pre-registered criteria on the untouched pilot, the fallback is not another fact
    round:** it is a narrowed product (one ecosystem, advisory-only -- option C of the
    2026-09-28 strategy review) plus hunter-with-proof for BLOCK-grade findings.
12. **Every correction turn names its lever and its measurement before it starts** --
    recognition / resolution / judgment / facts / judge, and the number that will show the
    lever moved. A turn that cannot name both is not started.

### Strategy-review outcome (maintainer decision, 2026-10-31)

Rule 10 fired for the access-control arm on 2026-10-30 (second consecutive admission
NO-GO, `benchmarks/measurements/2026-10-30-access-control-admission-express-pack/`).
The maintainer reviewed the two diagnoses -- NO-GO #1 recognition starvation (fixed:
coverage 4/12 -> 8/12), NO-GO #2 operation-facts/resolution starvation (new lever) --
and authorized **exactly one further gated round on operation facts and call resolution
for the recognized entry shapes**. This is the final incremental round for this arm:
a third admission NO-GO parks it permanently regardless of diagnosis, and the rule-11
fallback (narrowed one-ecosystem advisory product plus proof-based BLOCK) applies.
