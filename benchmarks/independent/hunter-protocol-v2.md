# Hunter experiment on population v2 (pre-registered)

Written and committed on 2026-09-28, BEFORE the tool hunter is run on any v2 pin. It is the deciding experiment
of the strategy review (`.kiro/specs/pre-push-safety-net/strategy-review-2026-09-28.md`): does a model with
repository tools find what the static engine did not (v2: recall 0/17, precision 0/17)?

## What is under test

- `tool_hunter.run_tool_hunter` as it stands: default system prompt, default tools (`read_file`, `grep_repo`,
  `find_refs`), `DEFAULT_MAX_STEPS` (4), the final-answer turn. Its prompt, tools and parsing are unchanged since
  the 2026-09-06 measurement; the only changes today are transport (cf57995 and this commit: the client reaches
  DeepSeek, and the endpoint is priced so the budget can see spending).
- Model: `deepseek-flash` (DeepSeek, the project's chat provider), through `resolve_hunter_client()`.
- Runner: `benchmarks/independent/hunt.py` at the commit that introduces this file.

## Scope handed to the model, per pin

The regions the static scan's discovery and ranker produce for the case's family (`regions_for` over
`analyze_entry_points`, the same as `finding_dump.py`), sorted by rank, top 20, as hunter hotspots in four groups
of five: one bounded hunt per group. Nothing else: not the fix diff, not the advisory, not the case's declared
sites, not the case id.

## Pins

Protocol v2's six per case: vulnerable a/b, fixed a/b, benign base and tip. Each is a `git archive` of the pin.

## Turning a hunter answer into a scoreable finding

- `site` = `path:line:function`, with the function the model reported, or empty.
- `family` = the model's own family and title mapped by the fixed keyword table in `hunt.py` (`FAMILY_WORDS`,
  checked in that order: untrusted_destination, config_secrets, injection; anything else is `other`).

## Scoring

Exactly protocol v2 (`protocol-v2.md`), via `evaluate.score_v2` over the hunter's results: the same matching
(v1's changed-line rule or a declared `path::function` site), detection in BOTH vulnerable runs, a fixed-side
alert in EITHER fixed run, benign alerts, stability, and the precision sample (every third stable
vulnerable-pin finding) adjudicated to v1's standard. A finding with no function can match only by the
changed-line rule. A pin whose four hunts all fail is an instrument failure, reported as such.

"Questions" for the hunter are its hunts (4 per pin), so completion is hunts completed / hunts run; it is not
comparable to the engine's question completion and is reported only as an instrument check.

## Cost

Hard ceiling $10 of recorded model spend, enforced by the runner; a pilot on a v1 development case
(mongo-express, 4 hunts) cost $0.031 and 57 s. If the ceiling stops the run, the unscanned pins are reported
as not run.

## What may not happen

- No change to the hunter's prompt, tools, step budget, parsing, scope rule or family table before this result
  is committed.
- Whatever is learned here is a finding about the hunter as it is; tuning it on v2 afterwards is a retune and
  needs a new population to qualify.
