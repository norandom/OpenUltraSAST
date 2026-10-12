# Design: valid detection benchmark

Builds the benchmark in R1-R8. New code lives under `benchmarks/valid/`. It reuses the sourcing,
labelling, negative-drawing, replay, and scoring that already exist, and drops the SZZ layer.

## What is reused and what is new

Reused as-is:
- Sourcing advisories to repos and fix commits: `benchmarks/unseen/source.py`, `draft.py`,
  `eligibility.py` (the used-set held-out guard).
- Fix-site labelling: `benchmarks/unseen/extract.py:fix_sites()` and the pair builder in
  `benchmarks/pairs/advisory-fixes/` (`materialize.py`, `catalog.toml`, `verification.json`).
- Function cutting: `openultrasast.learn.excerpt.function_bounds`.
- Ordinary negatives: `extract.py:ordinary_history()` and `draw_ordinary()`.
- Replay: `benchmarks/unseen/replay.py` and `replay_entry.py` (whole tool via the push hook).
- Scoring base: `benchmarks/unseen/score.py` (catch, false alarm, Wilson, repo-clustered interval,
  required_n, McNemar gate).

New:
1. `benchmarks/valid/catalog.py` - sourcing to a fix-site positive catalog, SZZ paths excluded.
2. `benchmarks/valid/verify.py` - the committed LLM verification driver (replaces the scratchpad
   `label_audit.py`). One call per case confirms vulnerable / fix-addresses / reachable-in-repo. This is
   also the app-shaped filter: reachability is answered here, not by a separate classifier.
3. `benchmarks/valid/metrics.py` - precision, false alarms per 100 pushes, and exploit-verified rate,
   layered on `score.py` output.
4. `benchmarks/valid/assemble.py` - freezes the verified positives plus the negative draw into a
   replay manifest with a digest and the held-out guard.

## Data flow

```
advisories (OSV/GHSA)
  -> source.py / draft.py            resolve repo + fix commit + parent   [reuse]
  -> catalog.py                      fix-site label (no SZZ); emit candidate cases  [new, wraps extract.fix_sites + pairs materialize]
  -> verify.py                       LLM: vulnerable? fix addresses it? reachable in-repo? + confidence  [new]
  -> human spot-check                record decision, reviewer, date       [manual, recorded in verification.json]
  -> draw_ordinary()                 negatives from the same repos          [reuse]
  -> assemble.py                     freeze positives+negatives -> manifest + digest, held-out guard  [new, wraps eligibility.normalize]
  -> replay.py (docker lane)         arm (a): the push hook as shipped (quick + engine)      [reuse]
  -> hunter arm runner               arm (b): the hunter over the same changes, off-cluster  [new, group 6]
  -> combine                         (a) and (b) joined per change id                        [new, group 6]
  -> score.py + metrics.py           recall, precision, FP/100, exploit-verified, intervals  [reuse + new]
```

## Schemas

### Positive case (catalog.py output, extends `advisory-fixes/catalog.toml`)
```
[[case]]
id            = "owner-repo-cve"
repo          = "owner/repo"
url           = "https://github.com/owner/repo"
advisory      = "GHSA-xxxx / CVE-xxxx"
cwe           = "CWE-89"
family        = "sql_injection"
language      = "python"
commit        = "<fix sha>"      # post-fix (safe) side
parent        = "<parent sha>"   # pre-fix (vulnerable) side
path          = "app/db.py"
function       = "get_member_by_code"
function_lines = [[40, 58]]
method        = "fix_site"       # never introducing/last_touch
```

### Verification record (verify.py output, extends `advisory-fixes/verification.json`)
```
{ "id": "...", "vulnerable_pre_fix": true, "fix_addresses_it": true,
  "reachable_in_repo": true, "entry_point": "flask route /member/<code>",
  "confidence": 0.86, "model": "deepseek-...", "advisory_cited": true,
  "human_spot_check": {"decision": "accept", "reviewer": "<initials>", "date": "2026-10-13"},
  "verdict": "accepted" }   # accepted only if all three true AND human accept
```

### Replay manifest (assemble.py output)
A `pool.toml`-shaped file so `replay.py` consumes it unchanged: `[[repository]]` rows with `changes`,
each change `kind = "vulnerability"` (positives, label from fix) or `kind = "ordinary"` (negatives),
with `base`/`head`/`files`/`function`. A `freeze-valid.json` carries the freeze digest and the held-out
guard result, matching the SZZ pool's freeze format so the ledger and replay flow are identical.

## Metrics (metrics.py)

Input is the scored records from `score.py`. New outputs:
- **precision** = flagged-and-real / all-flagged, over positives and negatives together, with Wilson 95%.
- **false alarms per 100 pushes** = false-positive rate x 100, the presentation of `score.py`'s
  `false_alarm` rate. This is a presentation layer, not a new measurement.
- **exploit-verified rate** = of flagged positives, the share the search-with-proof arm
  (`src/openultrasast/search/`) demonstrates on the vulnerable side and not the fixed side. Joined by
  case `id` from a proof-arm run; absent where the arm has not run (reported as "not yet proved", not as
  a failure).

Headline string, built here:
> "On unseen app repos: recall X% (Wilson A-B), false alarms Y per 100 pushes, precision Z%; exploit-verified N of M."

## Verification driver (verify.py) details

- Model: DeepSeek via the shipped provider, off-cluster (cheap, ~$0.0002/call). The brain tier runs
  locally in research; it does not need the kube engine.
- Prompt inputs per case: the advisory text, the pre-fix function, the post-fix function, and the file
  context around the function (for the entry-point question). No repo-wide context in the first version.
- Output is the verification record above. Reachability uses the same entry-point and source concepts the
  taint engine already models (`src/openultrasast/ruleset/frameworks.py`, framework routes/handlers), so
  the LLM is asked a concrete question, not an open one.
- Instrument rule: the driver prints bytes read for each side's function before it calls the model, and
  fails loudly on an empty read. A verdict on an unread case is rejected. (AGENTS.md instrument rule.)

## First increment (pilot)

1. Source Python and JS advisories with a clean fix link, held out from the tool's training/mining sets.
2. `catalog.py` builds candidate cases by fix site. Target ~25 candidates to land ~12 verified.
3. `verify.py` runs the LLM check; human spot-checks all of them (dozens, so full review is cheap).
4. `draw_ordinary()` draws >=20x negatives from the same repos.
5. `assemble.py` freezes the manifest + digest + held-out guard.
6. `replay.py` on the Docker lane runs the push hook as shipped (arm a). The hunter arm runner adds arm
   (b) over the same changes, off-cluster, and the two are combined per change.
7. `score.py` + `metrics.py` produce the four metrics with intervals and the headline, for (a) and for
   (a)+(b). (b) is the number the tool is held to; the difference is the product gap on pre-push.

Wiring the hunter into the pre-push hook itself is product work in `pre-push-safety-net`. This spec
measures the push path with and without it; it does not change the hook.

The pilot proves the pipeline and gives the first real numbers. Then grow positives to ~40 (set exactly
by `required_n`) and, where the proof arm has run, fill in the exploit-verified rate.

## Risks
- Harvesting is rate-bound (GitHub 5k/hr) and infra is operator-owned; the sourcing step runs
  deliberately, not in a tight loop, and reuses the banked resolver.
- The LLM verifier can be wrong; the human spot-check is the backstop, and the proof arm is the
  label-free check above it.
- App-shaped is a judgement call; record the entry point the verifier names so a human can audit it.
