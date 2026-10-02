# Evaluation

What has been measured on code the tool was not tuned on, and how. State as of 2026-10-02.
Every number below is quoted from a committed record; the path is given with it.

## Instruments

| Instrument | Measures | Where |
| --- | --- | --- |
| Detection gate | per-language recall/FP on the bundled cheat-sheet corpora (goal: >= 90% recall, < 10% FP) | `python -m openultrasast.gate`, `benchmarks/manifests/` |
| Pair corpus | fire on the vulnerable function, stay silent on its fix | `ousast pairs`, `benchmarks/pairs/` |
| Independent populations | real repositories at vulnerable, fixed and benign pins, scored under a pre-registered protocol | `benchmarks/independent/` |

The detection gate and the local pairs are CI gates. They catch regressions; they do not
estimate recall on real code, because the rules were written against them.

## Pair corpora

`benchmarks/pairs/catalog.toml` and the slice directories (`local`, `github`, `sast`, `vfc`,
`vibe-py`, `vfc-js`, `agent-vfc`, `owasp`) are runnable with `ousast pairs --slice <name>`; each
pair carries a provenance profile and a train/holdout split (`--profile`, `--split`). Pointer
pairs are not vendored: `--pointers` fetches them into `~/.cache/openultrasast/pairs/`.
`benchmarks/pairs/README.md` documents the schema and the review tiers.

**`advisory-fixes`** (`benchmarks/pairs/advisory-fixes/`, 2026-10-01) holds 97 pointer pairs,
one per repository: a public CVE/GHSA fix commit whose advisory-named function is declared on
both sides and changed by the fix. It was assembled to give the decision engine real negatives
for families the corpus had few of (access control, deserialization, output encoding, path,
untrusted destination). It is a label source of the decision engine
(`src/openultrasast/learn/sources.toml`), not an `ousast pairs` slice; the research log and
every rejection are in `research-2026-10-01.md`.

## Independent populations and the M4 gates

The pre-push safety net's qualification milestone (M4) requires, together: at least 95%
actionable precision, at least 90% supported recall, at least 95% supported-check completion,
the runtime gates, and zero fixed-side or benign false alerts. A population is frozen before
any of its cases is scanned, scored once under a pre-registered protocol, and then **spent**:
it may inform changes, but it can no longer qualify anything.

| Population | Status | Result | Record |
| --- | --- | --- | --- |
| v1 (11 cases) | spent | engine: recall 1/11, precision 1/12, 4 fixed-side and 1 benign false alert; every M4 gate failed. Eight of eleven cases completed no question at the vulnerable pin. | `benchmarks/independent/results-v1.json` |
| v2 (17 cases) | spent | engine: recall 0/17, 3 benign alerts, completion 13,206 of 108,374. Tool hunter: recall 1/17, precision 2/14, 1 fixed-side and 16 benign alerts, $8.88. No M4 gate met by either. | `results-v2.json`, `results-v2-hunter.json` |
| v2, model-driven pipeline | exploratory (v2 already spent) | stopped after 7 of 17 cases when the account emptied: recall 4/7; precision not adjudicated; no gate measurable | `results-v2-model-pipeline.json` |
| v3 (PHP, 15 cases; one SSRF slot left empty by the selection rule) | frozen, untouched | none: it is the one-time final check, run once under `protocol-v3.md` after a prediction is committed | `population-v3-php.toml`, `freeze-v3-php.json` |

v3 is reserved: development and analysis work never reads its cases, and
`tests/test_independent_population.py` fails when anything in the development tree (a recipe,
catalog, manifest or measurement) names one of its repositories.

## The plane increment

The first increment of the agentic plane ran the model-driven pipeline's validation set (46
candidates in 15 cases of v2, 20 declared vulnerable sites) on google/ax and compared it with
the script pipeline on the same cases, candidates, pins and recorded triage. The pre-registered
gate: at least 16 of 20 declared sites agreed, at a cost per candidate under $0.022.

- **Increment 1** (2026-09-29, `benchmarks/independent/plane-increment-1.json`): 14 of 20
  declared sites agreed against the reference's 16; $0.0194 per candidate with recorded triage.
  **NOT MET** on recall.
  *Correction (2026-09-30, in the record):* the first version read agree's
  `declared_sites_matched` (coverage by candidates, 19) as "found in either pass" and concluded
  detection was unchanged. Recounted from the agreed rows, the plane's passes flagged 17 of 20
  declared sites in at least one pass against the reference's 19.
- **Increment 2** (2026-09-30, `benchmarks/independent/plane-increment-2.json`): after the design
  revisit, a tie-break pass c on the 10 disputed candidates with 2-of-3 agreement. 16 of 20
  declared sites agreed (reference 16) at $0.0205 per candidate over 46 ($0.02195 over the 43
  after triage, against the reference's $0.022). **MET**, with two caveats the record carries:
  the tie-break was chosen after seeing the first measurement on the same validation set, so
  this compares plane with script and qualifies nothing on an independent population; and the
  plane's passes still flag fewer declared sites than the reference (17 vs 19). Precision is
  not part of this gate and remains the open problem.

## The decision engine

The first measured slice of the learned decision engine (injection family, out-of-repository
evaluation) is described with its numbers in [decision-engine.md](decision-engine.md).

## Removal of the earlier agentic extra

The removal of the earlier agentic extra (2026-09-30) was checked for byte-identical
deterministic outputs (pair replay, quick benchmark, standard scan, `improve --dry-run`):
`benchmarks/measurements/2026-09-30-harnessx-removal-baseline/` and `-equality/`.
