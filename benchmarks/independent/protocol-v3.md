# Evaluation protocol v3 for the independent PHP population v3 (pre-registered)

Written and committed on 2026-09-30, AFTER `population-v3-php.toml` was frozen and BEFORE any scanner, quick rule,
engine, plane task or model has been run on any v3 repository. It fixes what is measured, how a result is scored
and what is reported, so that no rule of the scoring can be chosen after seeing an outcome. Changing it after the
first scan makes the run exploratory, and it must then be reported as such.

Differences from protocol v2, each decided by the maintainer on 2026-09-30 before any v3 case was scanned:

- **Six families.** v2 scored `injection`, `untrusted_destination` and `config_secrets`. v3 pre-registers matching
  for `injection`, `output_encoding`, `path`, `untrusted_destination`, `access_control` and `deserialization`
  ("Extend protocol v3 to all six"), with one rule for all of them (below).
- **Resolved sites.** Where an advisory names only a file, freeze read that file's diff at the fix commit and
  declared the changed function(s) as the site ("Resolve the function at freeze"). `site_basis` in the population
  says which sites the advisory named and which were resolved from the fix diff; both are declared sites and are
  credited alike. A file the fix does not change was not resolved (`site_files_unresolved`) and is not a site.
- **Three instruments**, each scored on its own (below).

## The population

`population-v3-php.toml`, status `frozen`, record `freeze-v3-php.json`: 15 cases (injection 5, output_encoding 3,
path 3, untrusted_destination 1, access_control 2, deserialization 1). The second untrusted_destination slot is
empty by the selection rule and stays empty; recall is over the 15 cases.

## What is under test

All three instruments at ONE analyzer commit: the commit that introduces the v3 evaluation runner, exported with
`benchmarks/push/freeze_source.sh`; its hash, the runner image digest and the model ids are recorded in the result.
No instrument's configuration may be changed between instruments or between cases.

1. **Quick PHP rules** -- `src/openultrasast/ruleset/php/rules.toml` through the production quick scan
   (`ousast scan <checkout> --mode quick`, default configuration: `min_emit_priority` and `min_emit_precision`
   0.0). Scored: the ENABLED rules. The shadow rules (`shadow_findings.json`) are scored the same way and reported
   separately as exploratory; they do not enter any gate. A quick finding's family is fixed by this table, and a
   rule not in it has no family and never matches:

   | family | rules |
   |---|---|
   | injection | `wpdb-sql-composition`, `sql-unquoted-concat`, `sql-unquoted-interpolation`, `sql-sprintf-unescaped`, `command-injection`; shadow `sql-call-composition`, `code-eval` |
   | path | `file-inclusion-input`, `path-input` |
   | untrusted_destination | `ssrf-input`, `open-redirect` |
   | deserialization | shadow `unserialize` |
   | output_encoding | shadow `xss-echo-input` |
   | access_control | none |

   A finding's site is `path:line:function` from the finding's `path`, `line` and `function_name`.
2. **The Joern engine** -- the production discovery and scan (`benchmarks/push/finding_dump.py`) inside the
   shipped image, per case only the case's own family (`--families <family>`), 5,000 regions, a 2,400 s deadline
   per scan, one engine container at a time, `--network none --memory 3g`, as `evaluate.py run` does.
3. **The plane pipeline** -- the ai-service plane as implemented at that commit: candidates -> triage -> verify
   pass a and pass b -> tie-break pass c on the candidates a and b dispute -> agreement. A candidate is a finding
   when a and b both flag it, or, for a disputed candidate only, when at least 2 of the 3 passes flag it; pass c
   alone never decides. Model: `deepseek-flash` (DeepSeek) for triage and all three verify passes, as in
   `plane/models/deepseek-flash.yaml`. Site: the candidate's anchor `path:line:function` (line 0 when the model
   names another file); family: the case's family.

Per case and instrument, six pins, protocol v2's: the vulnerable pin twice (runs a, b), the fixed pin twice (a,
b), the benign base and the benign tip once each. Each checkout is a `git archive` of the pin. For the plane,
"run a" and "run b" are two complete, independent executions of the whole pipeline (each with its own a/b/c
passes). The quick rules are deterministic: their two runs must be identical, and a difference is an instrument
failure.

## Instrument checks (before any number is believed)

- Every scan records the files and bytes it read. A scan that read no file of the checkout, asked no question
  (engine), or completed no task (plane) is an instrument failure: it is rerun once, and if it fails again it is
  reported as a failure, never as a clean result.
- A scan finishing implausibly fast for its instrument (an engine scan under the JVM start time) is treated as a
  failed launch and checked before it is scored.
- The plane is smoke-tested once, before the run, on a development case (never a v3 case), to show that model
  calls succeed and are priced; the smoke test's cost counts against the budget.

## Scoring, per case (all six families, all three instruments)

A finding MATCHES the case when its family is the case family (exact string) and either
1. its file is one the fix changes (`git diff --name-only vulnerable fixed`) and either its function is one the
   record names in `sites`, or its line lies within 10 lines of a hunk the fix changes on that side; or
2. its `path::function` equals one of the record's declared `sites` (`<global>` for file scope), whatever the
   site's basis.

This is `evaluate.matches_v2` unchanged; `evaluate.py --population population-v3-php.toml` selects the six-pin
protocol and `score_v2`. There is no cross-family credit: a finding of another family never matches, even at a
declared site.

What a match means, per family (for the adjudicator and the report; the matching rule above is the same):

- **injection** -- the interpreter call (SQL, OS command, code evaluation, template compilation) or the function
  that builds its argument.
- **output_encoding** -- the rendering or sanitizing point (an echo/print of the value, a response body, a
  sanitizer configuration) at a declared site or in the fix's range. families.toml's limits hold: a clean result
  says nothing about template-mediated escaping.
- **path** -- the filesystem operation, the inclusion, or the containment check the fix changes.
- **untrusted_destination** -- the outbound request or redirect, or the destination guard the fix changes.
- **access_control** -- an absence bug: the finding names the protected operation that lacks its guard, at the
  declared function where the guard belongs or in the fix's changed lines, where the fix adds it.
- **deserialization** -- the deserializing call, the entry that feeds it, or the gadget method the advisory
  names.

Outcomes, as protocol v2:

- **Detected** (recall): a matching finding in BOTH vulnerable runs.
- **Unstable detection**: a matching finding in exactly one vulnerable run. Reported; counts as NOT detected.
- **Fixed-side false alert**: a matching finding in EITHER fixed run.
- **Benign false alert**: any finding of the case family at the benign tip whose (file, function) has no finding
  at the benign base. Some benign pairs precede the vulnerable pin (`how` in the population says so); they are
  scored the same way.
- **Unanswered**: neither vulnerable run completed a question, rule pass or task covering a file the fix changes
  or a declared site file. Counts as NOT detected, with the reason.
- **Not covered**: the instrument has no rule or query for the case family (quick rules: access_control; any
  family the engine or plane cannot emit). Counts as NOT detected, reported separately from misses.
- **Not run**: a pin the budget ceiling stopped. Counts as NOT detected and as not completed.

## Stability and precision

Stability: per pin with two runs, findings in exactly one run over findings in either, per case and pooled. Not a
gate.

Precision, per instrument: all findings of the case family present in BOTH vulnerable runs, across the
population, pooled and sorted by (case, site); every third one, starting from the first, is adjudicated against
the source, or all of them if the pool holds 15 or fewer. Findings in only one run are counted, not adjudicated.
The standard is v1's: True; True, privileged; False, guarded; False, not attacker. Matched case findings are part
of the pool.

## Gates

These are reported against the M4 profile: at least 95% precision, at least 90% recall, at least 95% completion,
and zero fixed or benign false alerts. A gate that is not met is reported as not met.

- The gates apply to EACH instrument separately, on its own findings: the quick rules (enabled rules only), the
  Joern engine, and the plane pipeline. The plane pipeline is the product's decision path; its result is the
  M4 answer for PHP. The quick rules and the engine are reported against the same gates as components.
- Completion is, per instrument: quick rules -- files scanned over PHP files in the checkout; engine -- questions
  completed over questions asked (v2); plane -- tasks completed over tasks run, with budget-stopped pins counted
  as not completed.
- Recall is detected cases over 15, with a Wilson 95% interval; precision is the sampled fraction True (either
  kind), with a Wilson 95% interval. With 15 cases, 90% recall needs 14 detections.

## Budget

Model spend (the plane only; the quick rules and the engine call no model) is metered by the plane's
`MeteredClient` (`OUSAST_BUDGET_USD`, `OUSAST_BUDGET_CALLS`) and recorded per task.

- Hard ceiling for the whole v3 evaluation: **$60** of recorded spend, smoke test and triage included.
- Per case: **$6** across its six pins; per pass, the plane's own per-pass ceiling at the runner commit.
- Reference: $0.02 per candidate for two verify passes with triage (plane-increment-2.json); the largest v2 case
  cost $8.91 in the earlier script pipeline.
- When a ceiling stops a case, its remaining pins are "not run"; the run continues with the next case until the
  total ceiling. The ceilings are not raised after the first v3 task has started.

## What is reported

Per case and instrument: detected / unstable / unanswered / not covered / not run, fixed-side and benign false
alerts, completion for each of the six scans, stability, seconds and (plane) dollars. Overall, per instrument:
recall and precision with Wilson intervals, total fixed-side and benign false alerts, completion, pooled
stability, spend. Shadow quick rules are reported separately as exploratory.

## What may not happen

- No rule, fact, query, prompt, model, budget or scoring change informed by these results before the result is
  committed.
- Any analyzer change made after a v3 result -- to rules, queries, facts, prompts, models, the plane's tasks or
  the pipeline's agreement rule -- is a retune. v3 cannot qualify it; a retune can only be qualified on a NEW
  untouched population.
- No v3 repository may be named by a test, fixture, rule or measurement outside `benchmarks/independent/`
  (`tests/test_independent_population.py`).
- No result of a case whose licence is marked "verify" is published until the licence is checked. Kirby is not
  OSI-licensed: its results are unpublishable without the licensor's permission.

## Maintainer confirmation (2026-09-30, before any scan)

The maintainer confirmed the two choices made while drafting: the model-spend ceiling of $60 in total and $6 per
case (a case stopped by its cap counts as not detected), and shadow quick rules reported as exploratory only,
outside every gate. No v3 repository had been scanned when this was confirmed.
