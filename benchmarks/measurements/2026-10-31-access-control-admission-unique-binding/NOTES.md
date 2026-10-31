# 2026-10-31 access-control admission: unique-declaration member-call binding (final gated round)

Round authorization: maintainer strategy-review 2026-10-31 (commit 1481bb3) -- exactly one
further gated round on operation facts and call resolution; a third admission NO-GO parks the
arm permanently and the rule-11 fallback applies.

Lever (rule 12): resolution -- unique-declaration member-call binding in
`src/openultrasast/semantic/obligations/resolution.py` (commit dc28325): `x.method()` binds
complete iff exactly one same-name method declaration exists repository-wide; collisions stay
finite candidate sets; module-level functions never bind. RED->GREEN with reviewer approval;
keyword regression 856 passed (selection: obligation/prover/symbol/call_resolution/... entry/
core/handler union).

## Measurement 1: in-family site funnel (before/after, frozen ac-admission-2 records)

Re-proved the three recognized (in-family) vulnerable sites with the binding at dc28325,
same changes, same repos, same facts:

| site | complete | incomplete | unresolved (before -> after) |
|---|---|---|---|
| matrix-org/matrix-appservice-bridge 3a80 | 1 | 0 | 75 -> 75 |
| fastapi-users/fastapi-users 178f | 15 | 0 | 286 -> 286 |
| bytebase/dbhub f262 | 160 | 0 | 1173 -> 1173 |

Zero movement on every coverage and judgment field. Instrument proof per site: fresh runs,
`hook_bytes_read` 301065 / 100846 / 677782 (nonzero), head+base verified, no failures.

Root cause (classifier replicating the prove pipeline over each whole product tree):

- matrix: variable-receiver calls with exactly-one same-name method = 0 (methods_named=0: 687)
- fastapi-users: 0 (methods_named=0: 146)
- dbhub: 0 (methods_named=0: 1182)
- dominant unresolved mass: member calls to framework/stdlib names with no repository
  declaration (variable:methods_named=0 total 2015) and bare calls whose name has no
  declaration in the calling module (207/134/818) -- imported or framework names.

Conclusion: the authorized resolution lever is disconnected from the recognized admission
sites. The unresolved mass is a recognition/facts problem (callee names absent from the
repository), not a member-call binding problem.

## Screen: whole admission population (exact)

Re-proved all 264 admission records at dc28325 (fresh instrument run per record, nonzero
`hook_bytes_read` asserted, 0 zero-reads):

- vulnerable: 0/12 records changed
- fixed: 0/12 records changed
- ordinary: 0/240 records changed

Therefore the formal admission run with the binding is byte-determined to reproduce run 2's
report (numbers identical; only the stamped analyzer revision differs). Measurement 3 executes
that run for the record.

(Fixed-side screen note: the first fixed-side screen attempt double-applied
`_fixed_side_change` to already-swapped frozen records -- proving vulnerable trees -- and was
discarded; the corrected screen strips stamped fields and proves the frozen fixed changes
as-is. Control re-proves at pre-binding 1481bb3 confirmed the drift was the reconstruction
bug, not the binding.)

## Screen: dev pool (23 repos, classifier at HEAD worktrees)

The binding fires 23,112 times across the dev-pool repositories
(variable-receiver calls with exactly one same-name method; largest: apache/seatunnel 14,198,
kimai/kimai 3,182, shopperlabs/shopper 1,296). The dev funnel moves; measurement 2 is live.

(Two earlier dev-screen attempts were discarded as failed instruments under rule 8: the hist
clones are bare and carry a sparse-checkout config, so passing them directly -- or worktree
add without `_verify_checkout` -- reads zero bytes and silently reports plausible empty
buckets. The discarded runs produced no numbers; the screen above proves nonzero bytes_read
per repository.)

## Measurement 2: dev-pool arm re-run

Bundle: HEAD code dc28325 + the 13.3 candidate facts (digest 3eb5bf699434, NO express entry
pack -- the pack is a run-2 admission-gated delta, excluded here so the dev comparison
isolates exactly the binding; the only fact delta vs HEAD is entries/express.json, verified).
Configuration digest be6d0f688598 == 13.3. Output: ~/ousast-results/prover/ac-four-arm-2/cacfon.

RESULTS (483/483 records, 2 shards, 67.2 + 76.3 min, 0 instrument failures, all 483 records
with nonzero instrument.hook_bytes_read):

- Lever's number: complete-calls share 11.9% -> **19.2%** (589,520 -> 949,998 complete;
  incomplete 1,451,325 -> 1,090,847 -- an exact 360,478-call conservation, unresolved
  unchanged 2,908,559; 441/483 records moved resolution counts).
- Gates (must not regress vs 13.3): recall on fix changes 8/23 = 34.8% (identical);
  location recall 25/93 = 26.9% (identical); false alarms 5.2/100 pushes (identical,
  24 flags on 460 ordinary in both arms); unguarded judgments 32 -> 32; instrument
  failures 0 -> 0.
- Judgment movement: 5 ordinary records none -> indeterminate (jenkinsci/database-plugin x2,
  jenkinsci/dependency-track-plugin x2, kimai/kimai x1); indeterminate 33 -> 38. No new
  alarms, no recall movement; the moved records are visible bounded silence, not flags.

Verdict: PASS -- the resolution lever moves the dev funnel materially without regressing
dev recall or false alarms.

## Measurement 3: fresh freeze + admission run ac-admission-3

Freeze: facts == HEAD == run 2 facts (digest equality asserted), population pool-valid
(freeze guard 0), criteria byte-identical to runs 1-2 (asserted), analyzer dc28325.
Output: ~/ousast-results/prover/ac-admission-3.

RESULTS (264/264 records fresh: all stamped dc28325, all nonzero hook reads, none stale;
report 2026-10-31-access-control-admission-unique-binding/report.json):

- decision NO-GO; failed gates identical to run 2: min_fix_recall 0.0 < 0.5,
  min_pair_correctness 0/12 < 0.5, min_precision 0.0 < 0.25, min_verified_location_recall
  not measured (n=0); instrument failures 0.
- Per-repo comparison vs ac-admission-2: all 12 repositories identical on recognition,
  unguarded, indeterminate and findings (same table as the screen predicted).
- Elapsed 260 s for the full population.

## Round verdict

Third admission NO-GO on the same pre-registered criteria. Under the maintainer's
2026-10-31 strategy-review decision (recorded in .kiro/steering/detection-quality.md) the
access-control arm is PARKED PERMANENTLY: no further incremental rounds. The rule-11
fallback applies -- narrowed one-ecosystem advisory product (option C) plus proof-based
BLOCK for demonstrated findings.

What the round established, for the parking record:

1. The authorized resolution lever is real where repository-defined names exist: dev-pool
   complete-calls share 11.9% -> 19.2% with dev recall/FA exactly unchanged
   (measurement 2). The binding ships (commit dc28325).
2. The lever is disconnected from the admission population: zero member calls with a
   unique repository declaration exist across all 12 admission repositories (screens +
   ac-admission-3 identical to run 2). The admission funnel dies on framework callee names
   with no repository declaration and on unrecognized entries -- a facts/recognition
   problem that the authorized levers could not reach, confirmed by three independent
   instruments (site classifier, whole-population re-prove screen, formal admission run).
3. Diagnosis for any future strategy review: the remaining admission gap is NOT call
   resolution. It is (a) entry recognition on 4/12 repositories (zero frameworks
   recognised; coverage 8/12) and (b) operation facts for framework-defined operations
   (orm-read exists but the checked-operation count is 0 everywhere because entries are
   unreached or frameworks unrecognised).
