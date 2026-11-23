# Evaluation protocol v4 for the independent population v4 (pre-registered)

Written on 2026-11-23, AFTER `population-v4.toml` was frozen (commit c975643) and BEFORE any scanner, quick rule,
engine, hook, plane task or model has run on any v4 repository (docs/evaluation.md:63). It fixes what is measured,
how a result is scored and what is reported, so that no rule of the scoring can be chosen after seeing an outcome.
Changing it after the first scan makes the run exploratory, and it must then be reported as such.

Differences from protocols v2 and v3. D1 to D5 are maintainer decisions of 2026-11-23; Ca to Cj are drafting
choices awaiting confirmation; the last section lists each.
- D1: v4 waits for the candidate frozen after M3 and is scored once, over PHP, TypeScript and Python where v3
  covered PHP (protocol-v3.md:19-22).
- D2: the hook, `ousast pre-push`, replaces the plane pipeline as third instrument. D2, D5: no instrument calls a
  model; spend is $0.
- D3: `<global>`, `<module>` and an empty function name are one scope. D4: recall is over 11 cases.
- Ca: runtime gates on the hook. Cb: the hook's candidate alerts are the product's own advisory set, read as
  defined here.
- Cc: one rule -> family table for three languages. Cd: a cell with zero cases cannot be admitted.
- Ce: every `site_basis` is credited, and each instrument gets outcomes its own output satisfies.
- Cf, Cg: two identical runs; the analyzer's identities recorded by hand.
- Ch: the hook's instrument checks, its product-result rule and its completion definition.
- Ci: an empty precision pool or an empty completion is not a pass; alerts of other scope families are not gated.
- Cj: one trial of each instrument on a development case before the run; a missing scan counts as not detected.

## The population

`benchmarks/independent/population-v4.toml`, status `frozen` (:97), record `freeze-v4.json` (:99), commit c975643:
11 cases, four PHP with JavaScript, four TypeScript, three Python; families injection 6, untrusted_destination 3,
config_secrets 2 (:90-91). The vulnerable pin is the parent of the fixed pin (:79-80) and every case declares a
benign pair (:137 to :439). Cases are named by population id only. Run status (D1): v4 is the one-time M4
population: it stays frozen and unscanned until the candidate is frozen after M3 ("evaluation follows the frozen
candidate", .kiro/specs/pre-push-safety-net/release-milestones.md:223-224), is scored once under this protocol and
is then spent (docs/evaluation.md:53-55).

Positive controls per capability (language x family), in cases (each case's `family`: population-v4.toml:113-416):

| language | injection | untrusted_destination | config_secrets | cases |
|---|---|---|---|---|
| PHP | 3 | 1 | 0 | 4 |
| TypeScript | 2 | 1 | 1 | 4 |
| Python | 1 | 1 | 1 | 3 |
| all | 6 | 3 | 2 | 11 |

Capability statement (Cd): a capability is one cell, and a cell with zero cases has no positive control and cannot
be admitted on v4 evidence whatever the pooled numbers are (.kiro/specs/pre-push-safety-net/requirements.md:200-201).
PHP configuration -- `config_secrets`, labelled "configuration" (src/openultrasast/push/advisory-scope.json:17-18)
-- is that cell; the other two configuration cells hold one case each, so a detection there is one sample.

## What is under test

All three instruments at ONE analyzer commit (D2): the commit that introduces the v4 runner and this protocol,
exported with `benchmarks/push/freeze_source.sh`, as v2 (protocol-v2.md:20-21). No instrument's configuration may
be changed between instruments or between cases (protocol-v3.md:29). The quick and hook stages run in the engine's
image, or the hook artifact's `provenance.engine` and `engine_runtime` (src/openultrasast/push/runner.py:141-148)
equal that image's; a difference is an instrument failure.

Owed by the runner before the first scan (this protocol implements nothing):
- `benchmarks/independent/evaluate.py` stamps `"protocol": "protocol-v2.md"` for every version other than v1
  (evaluate.py:314, :344) and has no quick-rule or hook stage (:88-105); the v4 runner stamps this protocol, adds
  the two stages, applies D3 before matching, times each hook process, and counts a case with a missing scan as not
  detected instead of dropping it as `incomplete` (evaluate.py:263-265, :311).
- `src/openultrasast/learn/sources.toml:124-142` lists the v3 files under `[[excluded]]` and no v4 file: the v4
  population, freeze record, research record, protocol and results are to be listed.
- The result header records by hand (Cg) the analyzer commit, the runner image digest and the frontend versions,
  which `score_v2` does not record (evaluate.py:313-325).
- Each hook artifact path lies outside the repository and is writable, checked before the run, so that a missing
  artifact is never the runner's doing.
- The first scan starts only after the runner changes and this protocol are committed.

**The Joern engine** (D2): through `benchmarks/push/finding_dump.py` on full checkouts, as v1 and v2: one container
per pin (`docker run --rm --init --network none --memory 3g`, image `openultrasast:dev`, evaluate.py:90-97), per
case only the case's family, `--deadline 2400 --max-regions 5000` (:96), no model calls (finding_dump.py:53-62),
one at a time. Six pins per case (evaluate.py:54-64): the vulnerable pin twice (runs a, b), the fixed pin twice
(a, b), the benign base and tip once each, each checkout a `git archive` of the pin (:73-80).

**Quick rules** (D2): the quick pattern rules, enabled rules only, of PHP, JavaScript/TypeScript and Python, on each
of the six exported pins: `ousast scan <export> --mode quick`, default configuration (protocol-v3.md:31-32). Each
scan runs on a fresh export holding no `.openultrasast/` directory, from a working directory without
`openultrasast.toml` and without a `.env` (src/openultrasast/cli.py:131-132; src/openultrasast/config.py:74-79),
and with `OPENULTRASAST_RUNS_DIR` unset: the scan writes its run directory and a calibration ledger into the
checkout (src/openultrasast/run.py:18-26; src/openultrasast/cli.py:87, 632-635, 884-895;
src/openultrasast/calibration.py:143-145), and a later scan on the same checkout reads that ledger and a rule
ledger from it and recalibrates its rankings (cli.py:222, 543, 554-556, 581-582; src/openultrasast/config.py:235).
Each rule runs on the files of its own languages (src/openultrasast/findings.py:66-67). A quick finding has no
family (findings.py:15-36): this table (Cc) fixes it as the family whose CWE list holds the rule's `cwe`
(src/openultrasast/ruleset/families.toml:12, :19, :26, :46, :54, :68-84), and a rule not in it never matches. Ids
and status: src/openultrasast/ruleset/php/rules.toml:20-261, javascript/rules.toml:2-142, python/rules.toml:2-131;
v3's table (protocol-v3.md:37-44) gives the PHP rules the same families under ids without the `php-` prefix.

| ruleset | family | enabled rules |
|---|---|---|
| PHP | injection | `php-wpdb-sql-composition`, `php-sql-unquoted-concat`, `php-sql-unquoted-concat-language`, `php-sql-unquoted-interpolation`, `php-sql-unquoted-interpolation-language`, `php-sql-sprintf-unescaped`, `php-sql-sprintf-unescaped-language`, `php-command-injection` |
| PHP | untrusted_destination | `php-ssrf-input`, `php-open-redirect` |
| PHP | path (not a v4 family) | `php-file-inclusion-input`, `php-path-input` |
| JavaScript/TypeScript | injection | `js-command-exec`, `js-spawn-shell`, `js-eval`, `js-function-constructor`, `js-sql-injection` |
| JavaScript/TypeScript | untrusted_destination | `js-ssrf`, `js-ssrf-language` |
| JavaScript/TypeScript | config_secrets | `js-weak-hash` |
| JavaScript/TypeScript | not v4 families | `output_encoding`: `js-dom-xss`, `js-xss-response`; `path`: `js-path-traversal`; `deserialization`: `js-deserialize` |
| Python | injection | `python-os-command`, `python-shell-true`, `python-unsafe-eval`, `python-ssti`, `python-sql-injection` |
| Python | untrusted_destination | `python-ssrf` |
| Python | config_secrets | `python-flask-debug`, `python-weak-hash` |
| Python | not v4 families | `deserialization`: `python-unsafe-deserialization`, `python-unsafe-deserialization-language`; `path`: `python-path-traversal` |

The three PHP fallback rules (`php-sql-unquoted-concat-language`, `php-sql-unquoted-interpolation-language`,
`php-sql-sprintf-unescaped-language`; php/rules.toml:63-72, :90-99, :119-128), `js-ssrf-language`
(javascript/rules.toml:112-121) and `python-unsafe-deserialization-language` (python/rules.toml:101-110) carry
`fallback_for` and `status = "enabled"`. Under the loader's default, `priors = "all"`
(src/openultrasast/ruleset/store.py:44, :51-53, :70-71), a fallback is active exactly when its tagged rule is
dropped; v4 drops none, so the five are inactive and should emit nothing. They keep their tagged rule's family in
the table, and a finding of theirs is an instrument failure. Findings of rules outside the v4 families are
reported, not scored, as are the six PHP shadow rules (`shadow_findings.json`, src/openultrasast/cli.py:607-612):
injection `php-sql-call-composition`, `php-code-eval`; `deserialization` `php-unserialize`,
`php-maybe-unserialize`; `output_encoding` `php-xss-echo-input`, `php-xss-echo-input-language`
(php/rules.toml:33, :146, :160, :172, :189, :203).

**The hook** (D2): `ousast pre-push <repo> --base <rev> --head <rev> --artifact <path outside the repository>`
(src/openultrasast/cli.py:136-145, :160) with the product's default profile: `--deadline 30`,
`--cancellation-allowance 2`, `--max-regions 500`, `--engine inline` (cli.py:165-199), advisory mode and no
`--model-config` (a model is called only with one, docs/scanning.md:154). Three push pairs per case: reintroduce
(base = fixed pin, head = vulnerable pin), fix (base = vulnerable pin, head = fixed pin) and benign (base =
benign.base, head = benign.tip), each run against a repository whose object database holds both revisions: the
hook materialises the revisions from it into scratch space outside the repository
(src/openultrasast/push/snapshot.py:113-122, 462-559) and refuses an artifact inside it
(src/openultrasast/push/runner.py:560-563).

Candidate alerts (Cb; reading A of D-a). The shipped registry verdict is NO-GO
(src/openultrasast/push/eligibility.json:12), so "no normal alert is emitted today" (docs/scanning.md:151-152). For
scoring, the hook's candidate alerts are the product's own advisory set: its quick matches (the `quick_tier`
findings, pattern matches on head's changed lines or inside changed functions, src/openultrasast/push/quick.py:90-110,
122-130) and its engine candidates in the advisory scope families, `admission.dispositions[*].candidate.delta` with
`novelty` `new` or `worsened` (src/openultrasast/push/policy.py:60-74, 847-853), from which the product shows its
advisory engine findings (src/openultrasast/push/report.py:252-269; docs/scanning.md:151-153); every other head
finding in `scans` is reported beside them and not scored (src/openultrasast/push/runner.py:408). A quick match's
family is its rule's in the table and its site is `path:line:function` (rule, path, line, function:
quick.py:99-110); an engine candidate's family and site are its delta's (policy.py:60-74). This is the evaluation's
reading of the alerts the hook would raise if the capability were enabled; the product itself emits none. M5
eligibility is bound to the passing identities: what M5 may enable is the analyzer as the result header
identifies it.

The hook path is the product's decision path; its result is the M4 answer for every language (D2). The engine and
the quick rules are reported against the same gates as components.

## Instrument checks (before any number is believed)

- Every scan records the files and bytes it read. A scan that read no file of the checkout, asked no question
  (engine), or, for the hook, shows no file of the pair read (next bullet) is an instrument failure, unless the
  product itself stopped the run (third bullet): it is rerun once, and if it fails again it is reported as a
  failure, never as a clean result (protocol-v3.md:65-67). A scan finishing implausibly fast for its instrument (an
  engine scan under the JVM start time) is a failed launch, checked before it is scored (protocol-v3.md:68-69;
  AGENTS.md:72-76).
- The hook adds three checks per run. Artifact present: the file named by `--artifact` exists and parses; a missing
  or unparsable artifact is an instrument failure unless the next bullet applies. Exit status: advisory mode exits 0
  unless it blocks (cli.py:140; src/openultrasast/push/report.py:114-115); any other status is an instrument
  failure. Files read: the quick tier lists the files it read and their bytes
  (quick.py:26-27, :39-40) and still says `completed` when it read none (quick.py:76-85, 111-119), so a run whose
  records show no file of the pair read is an instrument failure.
- A run the product itself stopped is a product result, not an instrument failure, for the artifact and files-read
  checks: an artifact whose coverage reasons (`coverage_reasons`) in its `admission`
  (src/openultrasast/push/policy.py:871-874; src/openultrasast/contracts.py:80-81;
  src/openultrasast/push/runner.py:479; src/openultrasast/push/report.py:144) hold `deadline` or `_failed`, or a
  `snapshot:` boundary (src/openultrasast/push/runner.py:341, 460-466; the product materialises at most 10,000
  files, 128 MiB in all, 8 MiB per blob: src/openultrasast/push/snapshot.py:613-621) whether or not a file was
  read. Its check counts as not completed. Its candidate alerts count like those of any other run (the product
  shows quick matches and new or worsened candidates from such a run: src/openultrasast/push/report.py:387-389); a
  run that read no file of the pair, or whose artifact is missing, holds none and is not detected. A missing
  artifact with exit status 0 is such a run when the product's text on stdout says its details could not be saved
  and to retry with a writable artifact path (src/openultrasast/push/report.py:169-194, 418-421; printed by
  src/openultrasast/cli.py:518); the codes `report_deadline_exhausted` and `artifact_writer_failed` are in the
  product's return value, not on stdout.
- A scan or pair still an instrument failure after its rerun counts as NOT detected and as not completed and is
  never left out of a denominator.
- Before the run, each instrument is tried once on a development case that is not a v4 case (protocol-v3.md:70-71;
  AGENTS.md:72-76).

## Scoring, per case (three instruments)

A finding MATCHES the case when its family is the case family (exact string) and either
1. its file is one the fix changes (`git diff --name-only vulnerable fixed`) and either its function is one the
   record names in `sites`, or its line lies within 10 lines of a hunk the fix changes on that side; or
2. its `path::function` equals one of the record's declared `sites` (`<global>` for file scope), whatever the
   site's basis (protocol-v3.md:75-79; `evaluate.matches_v2`, evaluate.py:234-248).

Three rules are added (Ce, D3). Every `site_basis` is credited alike: `research-named`, `resolved-from-fix-diff` and
`freeze-review-named` (population-v4.toml:44-47) are declared sites. A case with several declared sites is
credited by any one of them, and the report names the sites that were hit (three cases declare two: :122, :213,
:272). There is no cross-family credit: a finding of another family never matches, even at a declared site
(protocol-v3.md:82-83). `<global>`, `<module>` and an empty function name are the same scope: the engine says
`<module>` (src/openultrasast/model/regions.py:48), the population says `<global>` (population-v4.toml:364), a
quick finding names a function only when a reachability hint covers its line (src/openultrasast/findings.py:143-154),
and `matches_v2` compares the literal (evaluate.py:240-242). The runner normalises before matching, so a quick
finding without a function name matches by its line, or by its file at a file-scope site.

Outcomes, per case and instrument; "both runs" means the two runs of the vulnerable pin (engine, quick rules) or of
the reintroduce pair (hook):

- **Detected** (recall): a matching finding in both runs.
- **Unstable detection**: a matching finding in exactly one run. Reported; counts as NOT detected.
- **Instrument failure**: a scan or pair still an instrument failure after its rerun. Reported as such, with its
  reason; counts as NOT detected and as not completed, in every denominator.
- **Fixed-side false alert**: a matching finding in EITHER run of the fixed pin, or of the fix pair.
- **Benign false alert**: any finding of the case family at the benign tip whose (file, function) has no finding at
  the benign base; for the hook, any candidate alert of the case family in EITHER benign run (it keeps only new or
  worsened defects, docs/scanning.md:123-124). Alerts of other scope families are counted and reported, not gated.
- **Unanswered**: when the case is not detected, neither run completed a question (engine), a file read (quick
  rules) or, for the hook, a `completed` outcome of the head scan record whose identity names a file the fix
  changes or a declared site file (engine: evaluate.py:280-284). A case is therefore never both Detected and
  Unanswered: the scoring code sets `unanswered = not detected and not answered` (evaluate.py:209). Counts as NOT
  detected, with the reason.
- **Not covered**: the instrument has no rule or query for the case family in the case's languages (quick rules: the
  table; hook: `language_not_covered`, src/openultrasast/push/runner.py:212-233; engine: no frontend,
  src/openultrasast/cpg/backend.py:73-81). Counts as NOT detected, reported separately from misses.
- **Not run**: a scan or pair the runner did not execute. Counts as NOT detected and as not completed.

## Stability and precision

Stability (Cf): two identical runs per instrument and pin (per push pair for the hook), as v2 and v3. Per pin with
two runs, findings in exactly one run over findings in either, per case and pooled. Not a gate. The quick rules are
deterministic: their two runs must be identical, and a difference is an instrument failure that is rerun once
(protocol-v3.md:60-61).

Precision, per instrument: all findings of the case family present in BOTH runs, across the population, pooled and
sorted by (case, site); every third one, starting from the first, is adjudicated against the source, or all of
them if the pool holds 15 or fewer. Findings in only one run are counted, not adjudicated
(protocol-v3.md:118-120; evaluate.py:306-310). The standard is v1's (protocol-v2.md:58-61): **True**; **True,
privileged**; **False, guarded**; **False, not attacker**. Matched case findings are part of the pool and are
adjudicated like any other.

## Gates

Reported against the M4 profile, per instrument, pooled over all cases (D4): at least 95% precision, at least 90%
recall, at least 95% completion, and zero fixed or benign false alerts. A gate that is not met is reported as not
met (protocol-v3.md:126-127).

- Precision is the sampled fraction True (either kind) and recall is detected cases over 11, both with a Wilson
  95% interval; 90% recall needs 10 detections. A precision over an empty pool is not a pass. A completion over
  zero questions, files or checks is not a pass either. Per-language and per-capability counts are reported, not
  gated (D4).
- Completion, engine: questions completed over questions asked (evaluate.py:320).
- Completion, quick rules: files read over files of the three languages in the checkout. The numerator is the run's
  `preprocess/file_targets.json` (src/openultrasast/cli.py:578; src/openultrasast/preprocess.py:90-93); the
  denominator is the runner's own count of files with those extensions in the export. The analyzer leaves out
  `node_modules`, `venv`, `.venv`, vendored trees and what the root `.gitignore` matches
  (src/openultrasast/preprocess.py:9, 96-111, 201-226, 251-270), with no tracked-file exemption in a `git archive`
  export (:237-243); a fix-changed or site file it left out is reported; with none of them read, the case is
  Unanswered when it is not detected.
- Completion, hook: checks completed over checks run. A check counts as run when its process started; a check
  without a parsable artifact is never completed. Its questions, in its head and base scan records, are
  `scope.selected` plus every `scope.deferred` entry whose reason is not `tier_zero` (an exact exclusion, not
  work: src/openultrasast/model/scan.py:89-93, 813-833). It is completed when every one has a `completed` outcome
  and no coverage reason holds `deadline`, `_failed` or `snapshot:`; a check that asked none is completed only when
  its quick tier read a file of the pair, and is counted and reported. `coverage_status` is not used: it is
  `incomplete` whenever a question is deferred, `tier_zero` included (src/openultrasast/push/report.py:118-127;
  src/openultrasast/push/runner.py:475-476), and whenever there is a candidate, because the NO-GO registry's
  reasons are then added to coverage as `eligibility:` reasons (runner.py:169-177;
  src/openultrasast/push/policy.py:1021-1027).
- Silence on everything fails: "a policy that achieves silence by examining or alerting on nothing shall fail that
  evaluation" (requirement 6.5, requirements.md:115-117; release-milestones.md:235).

Runtime gates of the hook (Ca): "Warm latency p95 <= 30 seconds, cancellation/report allowance <= 2 seconds; cold
latency reported separately" (requirements.md:194; src/openultrasast/push_scoring.py:57), measured over the hook
runs of the population. A latency sample is one hook run's elapsed seconds, the wall-clock time of the
`ousast pre-push` process as the runner measures it. Each push pair's two identical runs give a first execution
(run a) and a repeated one (run b). Run b is the population's warm sample (same repository, same machine, image
loaded) and is warm in that sense only, because the default profile requests no analyzer cache; run a is the cold
sample, reported separately. Warm p95 is the nearest-rank 95th percentile of the warm samples
(benchmarks/push/feasibility.py:49), over the b runs, 33 planned: every hook run that starts is a latency sample
whatever its exit status or artifact, and a pair without two timed runs fails the runtime gates
(feasibility.py:61-62, 173). It must be <= 30 s. A rerun's elapsed seconds are the sample of the run it repeats.
Cancellation and report: for every hook run, warm or cold, elapsed seconds minus the 30 s deadline must be <= 2 s
(feasibility.py:56-58, :65-67). Plainly, the population is a set of whole repositories, each pair one real change
to one of them. It is not the profile's "declared representative push workload" (requirements.md:195); these
numbers say what the population measures, not the latency or completion of that workload.

## Budget

- Model spend: **$0** (D5). No instrument calls a model: every hook scan record's scan must show `model_calls` 0
  and the artifact's `provenance.model` must be `disabled` (src/openultrasast/model/scan.py:111-112;
  src/openultrasast/push/runner.py:163); anything else is reported as a protocol violation.
- Engine scans: 2,400 s and 5,000 regions per scan, as v2 (evaluate.py:35, :96); 66 scans planned (11 cases x 6
  pins), plus the one rerun an instrument failure earns.
- Hook runs: the product's own limits, `--deadline 30` and `--max-regions 500` (cli.py:165-170, :177-179); 66 runs
  planned (11 cases x 3 pairs x 2 runs). No ceiling is raised after the first v4 task has started (D5).
- The maintainer deferred the choice of a model instrument (D5; maintainer note of 2026-11-23):
  - If one is added, it is added only by an amendment to this protocol committed before the first scan. The
    amendment fixes the exact model and version, the provider, the date window of the run, the ceiling in dollars
    and in calls, and the rule for a case stopped by a ceiling.
  - Candidates named by the maintainer on 2026-11-23: the configured plane model (deepseek-flash,
    plane/models/deepseek-flash.yaml) and GLM-5.4 or GLM-5.3. No choice has been made.
  - Model performance varies between providers and over time (maintainer note). A result that involves a model is
    therefore bound to the exact model and version recorded in the amendment and in the result header. Changing
    the model, or its version, after a result exists is a retune, which only a NEW untouched population can
    qualify.
  - Whether the plane's model client can be pointed at a GLM endpoint has not been verified; the amendment must
    state it.

## What is reported

Per case and instrument: detected / unstable / instrument failure / fixed-side false alert / benign false alert /
unanswered / not covered / not run, the declared sites that were hit, completion of each scan or push pair,
stability, seconds and, for the hook, each run's elapsed seconds. Every product stop and every instrument failure
is reported with its reason, as are the head findings the hook did not take as candidates and the candidate alerts
of other scope families. Per language and per capability: the same counts beside the cell's number of cases.
Overall, per instrument: recall and precision with Wilson 95% intervals, completion, total fixed-side and benign
false alerts, pooled stability and, for the hook, warm p95, cold p95 and largest overrun; each gate marked met or
not met. Shadow quick rules and rules outside the v4 families are exploratory, outside every gate. Results go to
`~/ousast-results/independent-v4` (evaluate.py:47-51) and are copied, without repository URLs, to
`benchmarks/independent/results-v4*.json`, with the result header of Cg.

## What may not happen

- No rule, fact, query, prompt, model, hook or scoring change informed by these results before the result is
  committed (protocol-v2.md:81).
- Any analyzer change made after a v4 result -- to rules, queries, facts, prompts, models, the hook's path or its
  limits, or the scoring -- is a retune. v4 cannot qualify it; a retune can only be qualified on a NEW untouched
  population (population-v4.toml:25-26; protocol-v2.md:82).
- No v4 repository may be named by a test, fixture, rule or measurement outside `benchmarks/independent/`
  (population-v4.toml:27-29; `tests/test_independent_population.py`).
- No live instance of a v4 project is probed: the evaluation reads the pinned revisions and nothing else, and the
  engine containers run with `--network none` (evaluate.py:90).
- Results name cases by population id and no source of a v4 repository is redistributed (v3's licence item,
  protocol-v3.md:166-167, in v4's form). The population header records the licences as cleared at the freeze and
  one open question, a licence not yet checked against a licence list (population-v4.toml:63-68); the result of
  the case that question concerns is not published until it is answered. The licences stated there are not
  extended by this protocol.

## Maintainer confirmation (2026-11-23, before any scan)

Decided by the maintainer on 2026-11-23, recorded here as decided:

1. Run status: v4 is the one-time M4 population; frozen and unscanned until the candidate is frozen after M3;
   scored once under this protocol, then spent.
2. Instruments at ONE analyzer commit: the engine (`finding_dump.py`, six pins, 2,400 s and 5,000 regions per
   scan), the quick rules (enabled only, PHP, JavaScript/TypeScript and Python, each exported pin) and the hook
   (`ousast pre-push`, default profile, three push pairs per case). No model instrument; the hook is the M4 answer
   for every language.
3. File scope: `<global>`, `<module>` and an empty function name are the same scope.
4. Gates as v3: >= 95% precision, >= 90% recall (10 of 11), >= 95% completion, zero fixed-side or benign false
   alerts; per instrument, pooled over all cases; per-language and per-capability counts reported, not gated.
5. Budget: $0 of model spend; the model question deferred to an amendment committed before the first scan
   (Budget); engine 2,400 s and 5,000 regions per scan; hook: the product's own limits; no ceiling raised after the
   first v4 task has started.
6. D-a: the hook's candidate alerts are the product's own set, reading A: its quick matches plus the engine
   candidates that are new or worsened (What is under test).
7. D-c: the warm latency definition. Each pair is run twice with the identical instrument; run a is the first run
   on that pair and run b the second; warm p95 is taken over the 33 b runs, and run a is reported as cold (Gates).

Decided by the controller while drafting, recorded here for the maintainer, who confirms each or changes it before
the first scan:

8. D-b: the wrap width. Prose is wrapped at 140 characters or less, table rows may exceed it, and there is no line
   cap.
9. D-d: v3's licence item is carried in v4's form: results name cases by id and no source of a v4 repository is
   redistributed (What may not happen).
10. A finding from an inactive fallback rule is an instrument failure (What is under test).
11. A consequence of reading A: a product-stopped run keeps its candidate alerts, which count like those of any
    other run; only a run that read no file of the pair, or whose artifact is missing, holds none (Instrument
    checks).

Drafting choices, awaiting the maintainer's confirmation before the first scan:

- a. Runtime gates on the hook beyond D-c: the warm p95 limit and its nearest-rank percentile, the 2 s bound on
  every run's overrun, and the statement that the population is not the declared representative push workload
  (Gates).
- b. The hook's candidate alerts read as the product's own advisory set; M5 eligibility bound to the passing
  identities (What is under test).
- c. The rule -> family table, the five inactive fallbacks, shadow rules outside every gate (What is under test).
- d. The capability statement: PHP configuration has no positive control (The population).
- e. Matching (`site_basis`, several sites, no cross-family credit) and the per-instrument outcomes (Scoring).
- f. Two identical runs per instrument; the quick rules must agree (Stability and precision).
- g. The frozen analyzer tree and the result header written by hand; the quick stage's isolation; the runner's
  other obligations (What is under test).
- h. The hook's instrument checks, the product-result rule and the hook completion definition (Instrument checks;
  Gates).
- i. An empty precision pool or an empty completion is not a pass; alerts of other scope families are reported,
  not gated (Gates; Scoring).
- j. One trial of each instrument on a development case before the run; a missing scan counts as not detected
  (What is under test; Instrument checks).

Maintainer note of 2026-11-23 on a model instrument, recorded with decision 5 (full text in Budget): the choice is
deferred. If one is added, it is only by an amendment to this protocol committed before the first scan, fixing the
exact model and version, the provider, the date window of the run, the ceiling in dollars and in calls, and the
rule for a case stopped by a ceiling. Candidates named on 2026-11-23: the configured plane model (deepseek-flash,
plane/models/deepseek-flash.yaml) and GLM-5.4 or GLM-5.3; no choice has been made. Model performance varies between
providers and over time (maintainer note), so a result that involves a model is bound to the exact model and
version recorded in the amendment and in the result header; changing the model, or its version, after a result
exists is a retune, which only a NEW untouched population can qualify. Whether the plane's model client can be
pointed at a GLM endpoint has not been verified; the amendment must state it.

No v4 repository had been scanned when this was written.
