# Zero-shot judge over prover traces -- training pool (gate 2)

Date: 2026-10-28. Roadmap: `.kiro/steering/roadmap.md`, "measure the trace first", gate 2.
Input: gate 1 prover findings (`~/ousast-results/prover/ac-train-1/`, measurements in
`../2026-10-28-access-control-prover/`).

## Setup

- Judge: `benchmarks/valid/judge_pass.py` (run + summarize). One zero-shot judgment per
  prover finding (340 findings on 84 flagged pushes: 15 true + 69 false).
- Question, fixed before any answer was seen: "is this entry meant to be public?" with a
  strict JSON answer `{public: bool, confidence, reason}` and the statement that
  `public: true` means the flag is a false alarm. Payload per judgment: repository, entry
  metadata, the embedded trace, evidence lines, operation, missing obligation. No
  examples, no tuning -- the pool measures, never trains (roadmap rule 3).
- Model: `openai/deepseek-flash`, temperature 0, per-run dspy cache. 340/340 judgments,
  **0 failures**, 34.4 min (~7 s per judgment), no provider errors (the hunt arm's
  `LMInvalidRequestError` mode did not appear).
- Rollup rule: a push is dropped only when ALL its findings are judged public.
  Raw judgments: `~/ousast-results/prover/ac-judge-1/judgments.jsonl`; summary and run
  metadata copied here.

## Instrument notes

Two checks before believing the numbers. First, a 2-judgment dry run on one vuln and one
ordinary finding: parse worked, reasons were real. Second, the harness fired a
"run complete" notification while the process was still writing (340 claimed, 319-333 on
disk); a summarize in that window produced partial numbers and was discarded. Final
numbers below are from the completed run only: 340 lines, 340 unique keys, run.json
`judged: 340`, `failures: 0`.

## Result

Headline (from `summary.json`): judge over prover findings: keeps 15/15 true flags, drops
5/69 false flags (recall 65.2%, FA 13.9/100).

| metric | before judge (gate 1) | after judge |
|---|---|---|
| recall (fix pushes) | 15/23 = 65.2% | 15/23 = 65.2% (no true flag lost) |
| false alarms per 100 pushes | 15.0 (69/460) | 13.9 (64/460) |
| precision (push level) | 15/84 = 17.9% | 15/79 = 19.0% |

Finding-level verdicts (340 judgments): on the 15 true pushes the judge voted
`protected` 90 times and `public` once -- it almost never argues with the prover on a
real vulnerability. On the 69 false pushes it voted `protected` 216 times and `public`
33 times: it calls only about 14% of the false-alarm findings "meant to be public".

## Reading

Lane 2 is safe but nearly inert on this pool. It costs no recall, but the public-entry
question does not separate the prover's false alarms: 64 of 69 false pushes survive
because at least one of their findings looks genuinely protected (internal endpoints,
admin-adjacent code -- exactly the code the prover was built to flag). The judge cannot
see why the flag is wrong; the wrongness lives in the trace (an unchecked operation that
is in fact guarded by a mechanism the trace does not model, or an entry that is not
attacker-reachable), which is lane 1 territory.

Decision input for gate 5: do not spend effort tuning this judge prompt. The FA lever is
trace and fact coverage -- measure it in gate 3 (ablation over the 8 prover misses and a
sample of the 64 judge-kept false pushes) before considering any judge changes.
