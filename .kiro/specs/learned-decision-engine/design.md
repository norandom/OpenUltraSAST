# Design Document

## Overview

Detection decisions move out of hand edits and into a trained, calibrated model. The instruments stay and emit
signals. A model-free feature builder turns those signals into one record per candidate. A label builder attaches
ground truth from sources we can defend. A small logistic model, evaluated only on repositories it never saw,
turns a record into a probability, and two thresholds on that probability (BLOCK, ADVISORY) are what `pre-push`,
`scan` and plane Runs report. Pipeline changes are variants in pre-registered, paired experiments.

Six facts from the repository and the recorded results shape the design:

- **The deployment target is a repository nobody trained on.** Maintainer: "the tool will never run against the
  test cases it's being trained with. it's purpose is a repo safety net." (Req 7). The primary unit is a candidate
  in changed code (`ousast pre-push`, base..head), and whole-repository `scan` is the secondary mode. Every
  reported number therefore comes from folds grouped by repository across all corpora. Features are
  repository-agnostic by an allow-list. Fit to a user's own repository is an opt-in layer outside the reported
  numbers.
- **Labels are scarce, and full plane signals exist on 43 rows.** The only recorded plane run with
  verify/agree/tie-break is `validation-46`: 15 cases, 43 candidates after triage, 19 of them with
  `site_match` true, all from population v2
  (`~/ousast-results/plane/validation-46/*-final/agreed.json`). The pair corpus is larger (427 pairs and 452
  labelled findings in the catalog today, 317/342 in the 2026-09-30 baseline
  `benchmarks/measurements/2026-09-30-harnessx-removal-baseline/pairs.json` `overall`). Measured by
  repository rather than by row, it is 146 groups, and two families are nearly single-repository (section 3). A
  model over verify signals cannot be trained today. The design trains on the signals every labelled row can
  have, and harvests the rest at a stated cost.
- **The core install is PyYAML only** (`pyproject.toml:11`). numpy, scipy and scikit-learn are not installed in
  `.venv`. Inference must be pure Python, and training should be too (section 4).
- **`pre-push` already has the decision seam.** `admit_candidates` (`push/policy.py:879`) applies one evidence
  bar to `CandidateDelta`s with `novelty` (`push/policy.py:61-74`). Its capability registry is empty by design
  (`push/policy.py:802-823`: "No shipped declaration is enabled"), so `pre-push` blocks nothing today. The
  engine's operating point replaces the capability-eligibility reasons, and the structural reasons stay.
- **The memory store is the system of record and has the needed shape.** Rows are keyed by repository and pin,
  with a closed `KINDS` tuple (`plane/memory.py:52`). There are two backends (FileStore, MinioStore) behind one
  interface (`plane/memory.py:176-291`), content-addressed blobs (`put_facts`, `plane/memory.py:249-255`), and a
  train-on-test `Guard` (`improve/memory.py:95-133`). Features, labels, decisions, model artifacts and experiment
  outcomes become new row kinds and blob prefixes. No second store is added.
- **Hand-written framework knowledge is embedded in the detectors** (Req 8). Examples are WordPress `$wpdb`,
  hooks and `maybe_unserialize` in `ruleset/semantic/php.toml` and `ruleset/php/rules.toml`, and Flask and
  Django names in `ruleset/semantic/python.toml`. Section 2 tags each entry. Priors become optional features
  that are off by default. Framework roles are inferred per repository instead.

Decisions in one place:

| Question | Decision |
| --- | --- |
| Candidate key | `(repo, pin, path, function, family)` in the row envelope only; `pin` is the head for a delta |
| Features | allow-listed, typed, repository-agnostic; explicit `null` + instrument state for missing; two profiles (`static`, `plane`) |
| Where features are built | plane task `features` (no model) after `agree`/`final` and `alerts`; host path `learn.features.build_for_scan` for `scan`/`pre-push` |
| Labels | host-only `ousast learn labels`; site/fix-range matcher for populations, vulnerable/fixed side for pairs, benign deltas, adjudications; fail-closed source allow-list keeps v3 out |
| Model | L2-regularised logistic regression, pure Python (Newton/IRLS), per family at >= 20 positive and >= 20 negative repositories, pooled at >= 10, otherwise "insufficient data" |
| Calibration | Platt scaling on inner grouped out-of-fold scores; checked per outer fold (reliability, slope, intercept); if it fails, ADVISORY only |
| Folds | outer grouped K-fold by repository (repeated), plus leave-one-source-out and leave-one-framework-out; nested inner folds for lambda, calibration, thresholds |
| Operating points | BLOCK: lowest threshold whose inner-fold Wilson lower bound on precision is >= 0.95; ADVISORY: threshold reaching 0.90 inner-fold recall; reported with repository-bootstrap intervals |
| Artifacts | content-addressed JSON under `models/` in the store; adopted version exported into the package by a maintainer commit |
| Experiments | manifest `plane/experiments/<id>.yaml` + Run annotation `openultrasast.io/experiment`; paired; repository-cluster bootstrap CI (primary), exact McNemar (secondary); O'Brien-Fleming two-look stopping |
| First experiment | `exp-001-known-callers`: callers line on vs off, development corpus (v1, pmpro, MediaWiki, WP Statistics, full-repository pointer pairs), about $8 expected, $15 ceiling |
| Framework knowledge | tagged `framework`/`library` priors, off by default; roles inferred by a `roles` plane task (model) + deterministic wrapper inference; leave-one-framework-out evaluation |

## Architecture

```
                    instruments (signal producers, unchanged as standalone tools)
  quick rules      Joern engine        repo-facts        roles (new)          verify a/b/c + agree
  alerts task      engine_alerts /     callers, entry     model role labels    (plane only, Model-bound)
                   pre-push scan       distance           + wrapper inference
        \               |                  |                   |                     /
         +--------------+------------------+-------------------+--------------------+
                                           |
                         features (new, no model): allow-listed record per candidate
                         plane: task after final + alerts     host: learn.features.build_for_scan
                                           |
                     +---------------------+----------------------+
                     |                                            |
   labels (new, host only, never in a sandbox)                decide (new, no model)
   populations: matches_v2 / fix ranges                       load adopted model -> p, operating point,
   pairs: vulnerable vs fixed side                            top features -> decision rows / report fields
   benign deltas, adjudications                                  ^
   source allow-list: v3 absent                                   |
                     |                                            |
   learn train/evaluate (host, pure Python) ---- model artifact (models/<sha>.json) ---- adopt (maintainer)
   grouped folds, Platt, thresholds, curves                       |
                     |                                    packaged: ruleset/decision/<family>-<profile>.json
   experiments (plane Runs with arms) -> arm_outcome rows -> analysis -> adopt | reject | inconclusive
```

A plane Run per case becomes `facts -> va, vb -> agree -> vc -> final -> alerts -> roles? -> features -> decide
-> remember`. `roles` is optional and Model-bound. `features` and `decide` are model-free with budget
`{usd: 0, calls: 0}`, as `remember` and the loop steps are (`plane/tasks/loop.py:1-5`). `remember` ingests the new
`features` and `decision` rows. Labels are never computed in a Run. They are built on the host from ground-truth
files the sandbox never receives, so no task that produces a feature can read a label.

New code: `src/openultrasast/learn/` (`schema.py`, `features.py`, `roles.py`, `labels.py`, `folds.py`,
`train.py`, `calibrate.py`, `evaluate.py`, `decide.py`, `experiments.py`, `sources.toml`),
`src/openultrasast/plane/tasks/{features,decide,roles}.py`, `ruleset/frameworks.toml`,
`ruleset/decision/`, and CLI groups `ousast learn ...` and `ousast plane experiment ...`. The reconciler is not
touched. Its 500-line budget stays (`tests/test_plane_reconciler.py`).

## Components and Interfaces

### 1. Candidate key and feature record (Requirements 1, 7.2)

**Candidate.** A candidate is `(repo, pin, path, function, family)`. `repo` is `memory.repo_key`
(`plane/memory.py:69`), `function` is the enclosing declaration by the `repo-facts` patterns
(`plane/tasks/repo_facts.py:131`, `<global>` outside any function), and `family` is a `families.toml` id. It is the
key that already joins `alert` and `verdict` rows (`improve/memory.py:7`: "repo, pin and `path::function`"). For a
delta the pin is the head, and the record carries `base` beside it. The key lives in the row **envelope**, for
joining labels and grouping folds. It is never a feature.

A candidate exists when at least one instrument emitted a signal of that family in that function: a quick-rule
alert, an engine finding, a `roles` sink, or a verify candidate. A labelled positive with no candidate is a
**reach miss**. It counts against recall and is reported separately as `reach`, so the engine is never credited
for sites no instrument surfaced.

**Delta mapping (Req 7.3).** For base..head, changed hunks (`git diff -U0 base head`) map to the head functions
that enclose a changed line. Functions whose engine operation `compare_evidence` marks `new`/`worsened`
(`push/policy.py:489`, `CandidateDelta.novelty`) are added. Each such function yields one candidate per family
that has a signal there. The base side of the same function supplies the `delta.*` features. A whole-repository
scan is the same with no base (`delta.*` is `not_applicable`).

**Features.** The feature set is closed and listed in `learn/schema.py` as `FEATURES: tuple[FeatureSpec, ...]`.
Each spec has a name, a source instrument, a type (`bool`, `int` with a cap, `float`, or `enum` with a closed
vocabulary), a profile (`static` or `plane`), and whether it is a prior. There are no free-text values, no
identifiers and no raw counts of repository-specific tokens.

| Feature | Source (file) | Type | Profile |
| --- | --- | --- | --- |
| `lang.*` | `preprocess.detect_language` | one-hot over the languages the engine or quick mode covers | static |
| `qr.enabled_hits`, `qr.shadow_hits` | quick scan (`plane/tasks/alerts.py:117`, `findings.quick_scan_findings`) | int, cap 20 | static |
| `qr.mechanism.<m>` | the hit rules' `tags` mapped to the closed mechanism vocabulary (`benchmarks/pairs/mechanisms.toml` ids) | int, cap 10 | static |
| `qr.max_precision_estimate` | `PatternRule.precision_estimate` (`ruleset/store.py:33`) | float | static |
| `qr.prior_hits` | hits of rules tagged `framework`/`library` (section 2) | int, cap 10 | static, **prior** |
| `eng.findings` | engine findings in the function (`engine_alerts.engine_rows`, `plane/engine_alerts.py:160`; pre-push scan) | int, cap 10 | static |
| `eng.rung_max` | finding rung | enum `suspicion, model_entailed, entailed` | static |
| `eng.witness_steps_min` | witness path length | int, cap 50 | static |
| `eng.sink_kind` | sink entry id mapped to an operation kind | enum (sql, command, code_eval, deserialize, file_path, file_inclusion, outbound_request, redirect, html_output, other) | static |
| `eng.source_kind` | source entry kind | enum (request, server, raw_body, argv_stdin, inferred_role, prior, other) | static |
| `eng.sink_origin`, `eng.source_origin` | where the vocabulary entry came from | enum (language, inferred_wrapper, model_role, prior) | static |
| `eng.sanitizer_on_path` | discharge seen but not accepted | bool | static |
| `eng.completion` | questions completed / total for the file | float | static |
| `eng.degraded`, `eng.unstable` | degradations; present in only one of two runs | bool | static |
| `facts.callers` | `repo-facts` call sites (`repo_facts.py:151`, cap 40) | int, cap 40 | static |
| `facts.caller_files` | distinct caller files | int, cap 20 | static |
| `facts.entry_distance` | caller-graph hops to an entry point (`mapping.analyze_entry_points`, `mapping.py:123`) | int, cap 6 | static |
| `facts.is_global` | candidate is `<global>` | bool | static |
| `facts.function_lines` | declaration span | int, cap 500 | static |
| `roles.sink_confidence`, `roles.source_in_function` | `roles` task (section 2) | float / bool | static (deterministic part), plane (model part) |
| `delta.novelty` | `CandidateDelta.novelty` or diff of base/head signals | enum `new, worsened, unchanged, unknown, not_applicable` | static |
| `delta.changed_lines` | changed lines inside the function | int, cap 200 | static |
| `delta.sanitizer_removed` | a sanitizer call present at base is absent at head | bool | static |
| `verify.flag_a`, `verify.flag_b` | pass verdicts (`units.jsonl`, `plane/tasks/verify.py`) | bool | plane |
| `verify.flag_c` | tie-break pass (asked only when a/b disagree) | bool | plane |
| `verify.votes` | flags over the passes asked | int 0-3 | plane |
| `verify.turns_mean`, `verify.site_offset` | tool turns; lines between the model's reported site and the candidate line | float / int cap 200 | plane |
| `agree.final` | `agreed, disputed, rejected` (`plane/tasks/remember.py:73`) | enum | plane |
| `ms.flagged`, `ms.operation` | model sink classification (`benchmarks/independent/model_sinks.py`, moved into `roles`) | bool / enum | plane |

**Deliberately excluded from features** (each is label information or an identity):

- `site_match` (`plane/tasks/agree.py:200`) and `in_fix_range` (`plane/tasks/alerts.py:137`). Both are computed
  from declared sites and fix ranges.
- Every fixed-pin alert. A deployed scan has no fixed pin.
- Declared-site counts and `case.json`.
- Costs (`usd`), which vary with provider pricing, not with the code.
- Rule ids, paths, file and function names, commit ids and repository names.

Rule ids enter only through closed mechanism buckets and the prior count. A rule written after one case's miss
would otherwise identify that case.

**Missing is not negative (Req 1.2).** Each record carries `instruments: {name: {state, version}}` with `state` in
`ran | none | failed | not_applicable`, and `x: {feature: value | null}`. `none` means no coverage for the language
(`plane/tasks/alerts.py` `coverage`, `remember.coverage_rows`, `plane/tasks/remember.py:79-96`). `failed` means
the instrument broke or did not read its input: the engine-alert rule "no result file, no `read N files` line, or
`questions == 0` fails the case loudly" (`plane/engine_alerts.py` docstring) maps here, never to zero findings.
`not_applicable` covers two cases: `delta.*` on a whole-repository scan, and `facts.*` on a pair excerpt, where no
repository exists. Every feature of an instrument whose state is not `ran` is `null`. At training time a `null`
becomes 0 plus a per-instrument indicator `missing.<instrument>` (one indicator per instrument, not per feature,
to keep the parameter count down).

**Profiles.** `static` is what `pre-push` and `scan` can compute locally without a model: quick rules, engine,
facts, deterministic roles and delta. `plane` adds verify, agree and model roles. A model is trained per
(family, profile). A `static` model never sees verify features, so it cannot learn to lean on an instrument that
is absent in deployment.

**Enforcement (Req 7.2).** The builder emits only `FEATURES` names. `validate_record` rejects any other key, any
string value outside an enum's vocabulary, and any number outside its type. Tests:

- `test_learn_schema.py::test_features_are_allow_listed`: every emitted key is in `FEATURES`, and no spec's type
  is free text.
- `::test_record_is_name_invariant`: two fixture repositories that differ only in repository name, paths, file
  names, function names and commit ids give byte-identical `x`.
- `::test_label_fields_never_reach_features`: `site_match`, `in_fix_range`, fixed-pin rows and `case.json`
  fields in the inputs change nothing in `x`.
- `::test_missing_is_not_zero`: `coverage: none` gives `null` + `state: none`, and a covered language with no hit
  gives `0` + `state: ran`.

**Versioning.** `schema_version` (an integer, bumped on any spec change) and `feature_set_digest` (sha256 of the
canonical `FEATURES` list). `instruments.*.version` records the ruleset digest, the engine image id
(`engine_alerts._image_id`, `plane/engine_alerts.py:177`), the runner image digest (`memory.image_digest`), the
verify model id and a prompt digest, and the `roles` model id. That makes every record rebuildable (Req 1.3).

**Where records live.** A new memory row kind `features` (`KINDS` at `plane/memory.py:52`), per repository and
pin like every other row:
`{candidate, family, language, profile, schema_version, feature_set_digest, x, instruments, unit: "pin"|"delta",
base?}`. The row id is `row_id("features", run, task, candidate+family)`.

**Who builds them.**

- *Plane*: task `features` (`plane/tasks/features.py`), no Model, one per case, after `final` and `alerts` (and
  `roles` when present). Inputs are `facts.json`, the pass `units.jsonl`, `agreed.json` (with `site_match` dropped
  on read), `alerts.jsonl` (vulnerable pin only, `in_fix_range` dropped), the alerts `summary.json` coverage, and
  `roles.json`. It writes `features.jsonl`, which `remember` turns into rows (one more input in
  `remember.rows_for`, `plane/tasks/remember.py:99`).
- *Host*: `learn.features.build_for_scan(root, findings, engine_result, *, base=None)`, called by `scan` and
  `pre-push` (section 8) and by `ousast learn features <corpus>` to build records for the pair corpus and the
  development corpus without a Run.

### 2. Framework knowledge: tagged priors and inferred roles (Requirement 8)

**Rule.** Hand-written knowledge stays at the language level: superglobals, built-ins, process execution, raw
database drivers (DB-API `execute`, `mysqli_*`, `pg_*`, JDBC), deserialisers and the standard library.
Framework and application roles (request objects, query builders, hooks, sanitisers, guards) are either
**inferred per repository** or kept as **tagged priors**, which are features that are off by default.

**Tagging.** Every `[[source]]`, `[[sink]]`, `[[sanitizer]]` and `[[dispatch]]` entry in `ruleset/semantic/*.toml`
and every quick `[[rule]]` gains an optional `framework = "<id>"` or `library = "<id>"`. An entry that mixes
language-level and framework calls is split, so a tag always covers a whole entry. `ruleset/frameworks.toml`
lists the ids and, per id, a lexicon of symbols. The lexicon has two uses only: the lint test, which fails on an
untagged entry containing a lexicon symbol, and repository stratification (below). It never feeds detection.
Loaders take `priors: Literal["off", "all"] | frozenset[str]`. The default for the engine model is `off`. Today's
`scan` behaviour (fallback, Req 6.2) keeps `all`.

Current framework-specific entries and their disposition:

| Entry | Where | Tag / action |
| --- | --- | --- |
| `wpdb` sink (`$wpdb->get_var`, ...) | `ruleset/semantic/php.toml:47-58` | `framework = "wordpress"` |
| `unserialize` sink: `unserialize` + `maybe_unserialize` | `php.toml:136-138` | split: `unserialize` language; `maybe_unserialize` wordpress |
| `sql_escape`: `mysqli_real_escape_string`, ..., `esc_sql` | `php.toml:169-170` | split: `esc_sql` wordpress |
| `wpdb_prepare` sanitizer | `php.toml:194-196` | wordpress |
| `coerce`: `intval`, ..., `absint` | `php.toml:207-208` | split: `absint` wordpress |
| `wordpress_hooks` dispatch (`add_action`, `apply_filters`, ...) | `php.toml:225-242` | wordpress |
| layout `php_composer_and_wordpress` | `php.toml:244-247` | product filter (vendored/test paths), not detection; renamed `php_layout`, untagged |
| rule `php-wpdb-sql-composition` | `ruleset/php/rules.toml:20-29` | wordpress |
| rule `php-unserialize` (pattern includes `maybe_unserialize`) | `php/rules.toml:114-125` | split into `php-unserialize` (language) and `php-maybe-unserialize` (wordpress) |
| Flask `request` source (`request.args`, `.form`, `.json`, ...) | `ruleset/semantic/python.toml:5-17` | flask |
| `django-request` source | `python.toml:24-30` | django |
| `orm.raw` (`objects.raw`, `RawSQL`, `extra`; `text`, `from_statement`) | `python.toml:102-104` | split: django / sqlalchemy (library) |
| `path.open` (`open`, `os.*`, `shutil.*`; `send_file`, `send_from_directory`; `FileResponse`) | `python.toml:110-112` | split: language / flask / django |
| `html.unescaped` (`render_template_string`, `Markup`; `mark_safe`, `format_html`, `HttpResponse`) | `python.toml:119-121` | flask / django |
| `outbound.request` (`requests.*`, `httpx.*`; `urlopen`, `urlretrieve`) | `python.toml:127-129` | split: library requests/httpx / language |
| `redirect` (`redirect`, `HttpResponseRedirect`, `url_for`) | `python.toml:134-136` | flask / django |
| `url_allowlist` (`url_has_allowed_host_and_scheme`, `is_safe_url`) | `python.toml:145-146` | django |
| `pickle.loads` entry incl. `yaml.load` | `python.toml:55-57` | split: `yaml.load` library pyyaml |
| Express `req` source (`req.query`, `req.body`, ...) | `ruleset/semantic/javascript.toml:5-6` | express |
| `html.response` (`res.send`; `res.write`/`res.end`) | `javascript.toml:80-82` | split: express / language (Node core) |
| `path.open` (`sendFile`; `readFile`, ...) | `javascript.toml:87-89` | split: express / language |
| `redirect` (`redirect`; `location.*`) | `javascript.toml:129-131` | split: express / language (DOM) |
| `prototype.merge`, `outbound.request`, `html.escape` | `javascript.toml:57-59, 109-111, 148-149` | library (lodash, axios/needle, escape-html/DOMPurify) |
| `servlet` source, `response.write` | `ruleset/semantic/java.toml:5-6, 47-49` | `jakarta-servlet` |
| `outbound.request` (`getForObject`, `exchange`; `sendRedirect`; `openConnection`) | `java.toml:54-56` | split: spring / jakarta-servlet / language |
| `java.escape` (`ESAPI.encoder`, `StringEscapeUtils`; `getCanonicalPath`, `normalize`) | `java.toml:61-62` | split: library / language |
| hook-as-source rule | `cpg/queries/taint.sc:918-949`, `semantic/facts.py:73-90` | general code driven by the dispatch fact ("The registry's vocabulary arrives as a FACT", `taint.sc:921`); with priors off it is inert unless `roles` infers a registry |

The maintainer's term counts (php.toml 24, php rules 9, python 16, javascript 5, java 3, 15 WordPress mentions
in `semantic/*.py` and `cpg/queries/*.sc`) are covered by these entries. The remaining mentions in `.sc` and
`.py` are comments (`taint.sc:161, 249, 322-327, 588, 911, 1296`; `dominance.sc:130`; `census.sc:9`;
`facts.py:345`). The tagging commit's lint test, not this table, is the authority.

**Role inference (Req 8.1).** Two parts, both producing per-repository vocabulary with provenance:

1. *Wrapper inference* (deterministic, `learn/roles.py`, no model). A function whose parameter reaches, within its
   body, a call already in the role set becomes a derived sink or sanitizer of the same operation kind, with
   `depth + 1`. The role set starts from language-level entries plus any inferred roles. Derivation iterates over
   the `repo-facts` caller map to depth 3. When dependency source is present (`vendor/`, `node_modules/`,
   site-packages in the checkout), it is scanned the same way, so `$wpdb->query` becomes a sink because
   WordPress's own `wpdb::query` reaches `mysqli_query`, not because a table says so. That holds only when WordPress
   core is present. A plugin checkout usually lacks it, which is why part 2 exists.
2. *Model roles* (plane task `roles`, Model-bound, `deepseek-flash`). The source-only classification of
   `benchmarks/independent/model_sinks.py` moves into the package: per product file chunk, which functions and
   call sites perform an operation of a closed kind on non-constant data. The v2 record: declared site among the
   candidates in 15/17 cases, fix or site file in 16/17, $14.42 for 17 repositories
   (`selection-v2-model-sinks.json`). The output extends to all roles: `sink`, `source`, `sanitizer`, `guard`,
   `dispatch` (a register/apply pair such as a hook registry), with `operation`, line and a one-line evidence
   quote. A chunk whose call fails is `unclassified`, never "no roles" (the `model_sinks.py` rule). In `pre-push`
   only the changed files and the definitions they call are classified.

Roles reach the engine as a per-scan vocabulary overlay in the shape of `ruleset/semantic/<lang>.toml` entries
with `origin = "inferred_wrapper" | "model_role"`. The engine already takes vocabulary as facts
(`taint.sc:921`). They also reach the feature record as `eng.*_origin` and `roles.*`. Roles are signals. A
model-labelled sink alone is not a finding.

**Stratification metadata.** Each repository gets `frameworks: [ids]` from its dependency manifests
(`composer.json`, a WordPress plugin header, `requirements*.txt`/`pyproject.toml`, `package.json`,
`pom.xml`/`build.gradle`) matched against `frameworks.toml`. This is envelope metadata for folds and reports,
never a feature.

**Evaluation (Req 8.2-8.4).** The engine is always trained and reported with `priors=off`. A prior group (one
framework id) is kept only through an engine-level A/B (section 6): priors on vs off, paired on the same outer
folds, metric recall at the BLOCK operating point. It is adopted only if the repository-bootstrap CI excludes zero.
Every report carries, per family, the metric with priors off, with the adopted priors, and the difference: the
share of the result that depends on priors. Leave-one-framework-out folds (section 4) give the "framework unseen
in training" row.

### 3. Label builder (Requirement 2)

`ousast learn labels` (`learn/labels.py`) runs on the host only. It writes `label` rows (a new kind) and
`labels/<digest>.jsonl` snapshots.

**Sources are an allow-list, fail-closed.** `learn/sources.toml` names each usable source, the file that proves
its evaluation was recorded, and the date. A population not listed cannot produce a label. The builder never
opens a population file that is not listed, so population v3 (`population-v3-php.toml`, reserved) is excluded
without being read. It becomes usable only when a later commit adds it after the v3 result is recorded
(Req 2.3).

| Source | Evaluation record | Status |
| --- | --- | --- |
| `population-v1` | `benchmarks/independent/results-v1.json` | spent (retuned on, `population-v2.toml:9-11`) |
| `population-v2` | `results-v2.json`, `results-v2-hunter.json`, `plane-increment-2.json` | spent for tuning (`model_sinks.py`: "v2 is spent for tuning"); its fold is marked *design-informed* (section 4) |
| `dev-php` | `benchmarks/push/inputs.json` (pmpro introduce/repair/benign), MediaWiki and WP Statistics checkouts | development |
| `pairs` | `benchmarks/pairs/**/catalog.toml` via `load_pair_catalog` (`pairs.py:229`) | development; catalog split recorded, not used for folds |
| `adjudications` | `results-v1.json` `precision_review`, `results-v2.json` / `results-v2-hunter.json` `precision_sample`, `verifier-check-2026-09-29.json` | recorded verdicts |

**Rules per source.**

- *Populations.* Positive: a candidate on the vulnerable pin that matches the case. Matching uses v2 declared sites
  through `agree.matches_declared` (`plane/tasks/agree.py:45`, the parity-proven copy of `evaluate.matches_v2`).
  v1 has no declared sites (0 in `population-v1.toml`), so it uses the fix-range rule `evaluate.matches`
  (`benchmarks/independent/evaluate.py:162`). Negative: the same `(path, function)` on the fixed pin when the fix
  changed that function (inside the new-side `fixed_ranges`, `plane/generate.py:106, 227-229`). A function the fix
  did not touch is the same code at both pins and is not a negative. Benign: a candidate in a function changed
  between the benign base and tip pins that has a finding at the tip and none at the base. It is negative
  **by protocol assumption** (protocol v2 "Benign false alert"), with source `benign_control`. A candidate on a
  vulnerable pin that matches no site is **unlabelled**, never negative.
- *Pairs.* Positive: the labelled function (`ExpectedFinding.function`/`line`, `benchmark.py:20-30`; 407 of 452
  labels name a function) on the vulnerable side. Negative: the same function on the fixed side. Pairs marked
  `unscorable` (identical twins, known limits, `pairs.py:130`; 7 today) give no labels. Tier `title`
  (`agent-vfc`, 59 pairs, labels read from advisory titles; labelled recall 3.6% in the baseline) is excluded by
  default and used only as a sensitivity arm.
- *Deltas.* Every population case and every pair also gives delta units. fixed..vulnerable is the introducing
  direction, and its labelled function is a positive delta candidate. vulnerable..fixed is a repair, whose
  candidates are negative for BLOCK. benign base..tip is a benign push. These are the primary units for the
  safety net (Req 7.3).
- *Benign history (optional, flagged).* Non-security commits from the history of each training repository at
  least 90 days away from any fix date give benign deltas at no model cost. They are negative by assumption, carry
  source `benign_history` and a weight of 0.5, and every metric is reported with and without them. This is the
  only cheap way to estimate false blocks per benign push.
- *Adjudications.* `True` and `True, privileged` are positive (privileged is kept as a label attribute), and
  `False, *` is negative. Each keeps the adjudicator (maintainer, or a judge task with its evidence) and the
  recorded text.
- A plane verdict (`agreed`, `rejected`, `disputed`) is never a label (Req 2.2). It enters only as `agree.final`.

**Label row.** `{candidate, family, label: 1|0, source, source_ref (case id / pair name / adjudication index),
unit: pin|delta, direction?, weight, split (catalog split or population split), group (repository group key),
frameworks, created, evidence}`. `group` is the normalised repository, the lower-cased `owner/name` as the guard
uses (`improve/memory.py:89-92`). Candidates that share an advisory id (CVE/GHSA) across corpora are merged into
one group, so a repository mirrored under two names cannot straddle folds.

**What exists today** (counted 2026-09-30 with a scratch script over `load_pair_catalog` +
`split_by_repository`; the label-snapshot commit makes the count reproducible):

| Family | Pair repos (positive) | Pairs | Population repos (v1 + v2 + dev) | Adjudicated | Per-family model? |
| --- | --- | --- | --- | --- | --- |
| injection | 43 | 56 | 7 + 10 + 3 | most of the 43 (per-family split not counted) | yes |
| untrusted_destination | 41 | 41 | 3 + 6 + 0 | some | yes |
| path | 24 | 24 | 0 | 0 | yes (Python-heavy) |
| config_secrets | 23 | 24 | 1 + 1 | some | yes, borderline |
| deserialization | 23 | 23 | 0 | 0 | yes (all Python) |
| access_control | 21 | 24 | 0 | 0 | yes, borderline |
| output_encoding | 17 | 58 (40 from one repository, OWASP BenchmarkJava) | 0 | 0 | pooled |
| memory | 7 | 176 (132 openssl, 40 curl) | 0 | 0 | **insufficient** |
| prototype | 6 | 7 | 0 | 0 | **insufficient** |

Totals: 427 pairs and 452 labels in 146 repository groups (142 named). Tiers: advisory 250, seeded 115, title 59,
reviewed 3. Provenance: human 237, agent 139, synthetic 51. 59 repositories straddle the catalog's train/holdout
split (`split_by_repository` report). The engine ignores that split for folds and records it on the label.

By language, the strata with at least 10 positive repositories are Python (untrusted_destination 30, injection
23, deserialization 23, path 17, access_control 15, output_encoding 15) and JavaScript injection (16). **PHP has
no pairs.** Its labels are v1 (4 repositories), v2 (6) and dev-php (3): about 9 injection and 4
untrusted_destination repositories.

Plane-profile rows (verify/agree present) exist for 43 candidates in 15 repositories, all v2. The adjudicated
rows are mostly negative: v1 1/12 true, v2 0/17, v2 hunter 2/14 (`results-v1.json` `summary.precision`,
`results-v2*.json` `precision`).

What this means:

- The `static` profile can be trained for six families, pooled for output_encoding, and not at all for memory or
  prototype.
- The `plane` profile cannot be trained until verify has run on labelled units. The harvest Run in the commit
  sequence (step 5) runs passes a and b on the 78 scorable, non-title pairs in the verify families (injection,
  untrusted_destination, config_secrets; `verify.OPERATIONS`, `plane/tasks/verify.py:38-50`) on both sides, and on
  the development cases. That is about 312 + 110 hunts at $0.014 each (validation-46: $0.8567 over 61 hunts),
  **about $6**.
- PHP is reported as its own stratum only where it reaches 10 positive repositories. Today that is injection at
  the boundary, and untrusted_destination is "insufficient data".

### 4. The decision engine (Requirements 3, 7.1, 7.3, 7.4)

**Model family.** L2-regularised logistic regression on standardised features plus the instrument-missing
indicators. There are about 40 parameters per model. Reasons:

- With 20-60 repositories per family, a shallow gradient-boosted model fits interactions the folds cannot
  validate and calibrates worse on small data.
- A linear model's contributions are its explanation (Req 3.5).
- Inference is a dot product, so `scan` and `pre-push` need no dependency.

Gradient-boosted trees stay a possible future arm of an engine-level experiment, not a default.

**Dependency trade-off.**

- *scikit-learn as an optional extra* (`openultrasast[learn]`) brings numpy, scipy and joblib, about 100 MB in
  the runner image, and a second numerical stack whose version changes model bytes.
- *Pure Python (chosen)*: `learn/train.py` fits by Newton/IRLS with a dense solve of a matrix of about 40x40
  (Gaussian elimination with partial pivoting). At about 2,000 rows that is milliseconds. It is deterministic with
  no seeds inside the fit, and it is about 200 lines.

scikit-learn is a **test-only** extra: `test_learn_train.py::test_matches_sklearn` (skipped unless installed)
checks coefficients against `LogisticRegression(penalty="l2", solver="lbfgs")` to 1e-6. Training and inference
stay pure Python in core.

**Per family vs pooled.** A (family, profile) model is trained when the training data holds at least 20
repositories with a positive and 20 with a negative in that family. A pooled model (all families, with a family
one-hot) serves families with 10-19. Below 10 the family is "insufficient data": no engine decision, and the
fallback applies (section 8). The same 10-repository floor applies to any reported stratum (family x language,
family x framework).

**Weights.** One repository must not dominate (openssl has 132 pairs, OWASP BenchmarkJava 43). A row weighs
`w_source * min(1, 5 / n_rows(repo, family, label))`, so each repository contributes at most 5 effective positives
and 5 effective negatives per family. `benign_history` has `w_source = 0.5`.

**Folds (Req 3.3, 7.1).** Every split is by `group` (repository), across all corpora at once. A repository in an
evaluation fold contributes no row, from any corpus, to training.

- *Outer*: grouped K-fold with K = min(10, repositories in the family), stratified by family and label, repeated 5
  times with seeds 0-4. This gives the reported out-of-repository numbers.
- *Leave-one-source-out*: each population (v1, v2, dev-php) and each pair slice (vfc, vibe-py, owasp, vfc-js,
  agent-vfc, sast, github, local) held out whole, with its repositories removed from training. This is the
  "population-level fold" of Req 3.3 and the data behind the learning curve over the number of sources.
- *Leave-one-framework-out*: all repositories tagged with framework F held out, including WordPress, Django,
  Flask and Express wherever that framework has at least 10 repositories. This gives the "framework unseen" row of
  Req 8.3.
- *Inner* (inside each outer training set): grouped 5-fold. It selects lambda from {0.01, 0.1, 1, 10} by grouped
  log-loss, produces the out-of-fold scores for calibration, and picks thresholds. Nothing is tuned on an outer
  fold.
- The v2 fold is marked *design-informed*: the tie-break and the callers line were chosen after seeing v2
  (`plane-increment-2.json` `reading`). Plane-profile numbers are reported with and without it.

**Calibration (Req 3.1, 7.4).** Platt scaling (a two-parameter logistic on the model's logit) is fit on the inner
out-of-fold logits. Isotonic regression is not used: too few positives per family. The check is per outer fold
and pooled:

- a reliability table with 5 quantile bins;
- calibration slope and intercept (a logistic of the label on the calibrated logit), with repository-bootstrap
  95% CIs;
- the expected calibration error.

Calibration **holds** for a family when the slope CI contains 1, the intercept CI contains 0, and the pooled
out-of-fold expected calibration error is at most 0.05. If it fails, the model is recalibrated once on grouped
out-of-fold scores of the full training set. If it still fails, the family gets **ADVISORY only**, the artifact
records `block.offered = false, reason = "calibration"`, and the report says so.

**Prevalence.** Training mixes are enriched: pairs are 1:1, and validation-46 is 19/43. In a push, real
vulnerabilities are rare: v2 has 25 declared sites among 4,757 model-sink candidates. So the probability is
reported as calibrated **on the labelled mix**. The safety-net figures that do not depend on the mix are primary:

- recall at an operating point, and
- false BLOCKs per 100 benign deltas (population benign pins, pmpro-benign, benign history).

Precision at BLOCK is also reported at the benign-delta false-alarm rate, as `precision(pi) = pi*TPR /
(pi*TPR + (1-pi)*FPR)` for pi in {0.01, 0.05}.

**Operating points (Req 3.4, 7.3).** Both are chosen on inner out-of-fold scores only:

- **BLOCK**: the lowest threshold whose inner-fold precision has a Wilson 95% lower bound of at least 0.95, among
  delta units. If none exists (expected today for most families), `block.offered = false, reason =
  "precision_unreachable"`.
- **ADVISORY**: the highest threshold whose inner-fold recall is at least 0.90 (the M4 recall target). Its
  precision is reported, not assumed.
- **DROP**: below ADVISORY.

Both points are reported on outer folds with recall, precision and false BLOCKs per 100 benign deltas. Each has a
repository-cluster bootstrap 95% interval (2,000 resamples of repositories) and a Wilson interval as a
cross-check when each repository gives one unit.

**Explanations (Req 3.5).** A feature's contribution is `coef_i * (x_i - mean_i) / sd_i`, and a missing
instrument contributes through its indicator. The top 5 by absolute contribution, with sign and the feature's
display value, are stored in the `decision` row and on the finding. Missing-instrument indicators are shown as,
for example, "engine: no coverage".

### 5. Model artifacts and versioning (Requirement 3.2)

A trained model is one canonical JSON (sorted keys, floats rendered with `repr`), stored as a content-addressed
blob `models/<sha256>.json`. The store gains `put_blob(prefix, data) -> sha` and `get_blob(prefix, sha)`,
generalising `put_facts`/`get_facts` (`plane/memory.py:219-255`). Both backends get it unchanged. On MinIO the
object has tags `kind=model`, `family` and `profile`, and bucket versioning records the version id.
`models/index.jsonl` lists every version. `models/adopted.json` maps (family, profile) to a sha: a single
overwritten object (a new version under MinIO versioning, and history kept in `index.jsonl` on FileStore).

```
{"model_id": "<sha256>", "schema_version": 1, "feature_set_digest": "...", "family": "injection" | "pooled",
 "profile": "static" | "plane", "kind": "logistic-l2", "lambda": 1.0, "features": [{"name", "mean", "sd"}],
 "coef": {...}, "intercept": ..., "calibration": {"method": "platt", "a": ..., "b": ..., "check": {...}},
 "operating_points": {"block": {"threshold", "offered", "reason", "target_precision": 0.95},
                      "advisory": {"threshold", "target_recall": 0.90}},
 "priors": "off" | ["wordpress", ...], "roles": "off" | "deterministic" | "model",
 "data": {"store_index_digest", "label_set_digest", "sources": [...], "excluded": {...}, "rows", "repositories"},
 "evaluation": {"folds_digest", "outer": {...}, "leave_one_source_out": {...}, "leave_one_framework_out": {...},
                "strata": {...}, "curves": "curves/<sha>.json"},
 "instruments": {"ruleset_digest", "engine_image", "runner_image", "verify_model", "prompt_digest", "roles_model"},
 "seed": 0, "code_commit": "<git sha>", "created": "<iso>"}
```

`store_index_digest` is `improve.memory.index_digest` (`improve/memory.py:351`), and `label_set_digest` is the
sha256 of the sorted label rows used. Training reads rows through the store, so the same digests with the same
code commit give the same bytes (Req 3.2). `test_learn_train.py::test_reproducible` asserts this on both
backends, with the MinIO contract test gated as today.

**Adoption** is a maintainer commit. `ousast learn adopt <model_id>` writes `models/adopted.json` and exports the
artifact to `src/openultrasast/ruleset/decision/<family>-<profile>.json`, the copy that ships to users who have no
store. The mirror is the existing ledger rule: "adopting an accepted ledger stays a maintainer commit"
(`plane/tasks/loop.py:22-23`). A model whose feature set enables a prior group, or changes `roles`, can be adopted
only with a recorded `adopt` result of the engine-level experiment that justified it (section 6).

### 6. A/B experiments (Requirement 4)

**Manifest.** `plane/experiments/<id>.yaml`, a companion file, is referenced by the Run annotation
`openultrasast.io/experiment: <id>`. Each arm's Tasks carry `openultrasast.io/arm: A|B`. Annotations are stripped
before ax (`plane/manifests.py:4-6`), as `memory-key` is.

```
id: exp-001-known-callers
hypothesis: removing the known-callers line changes the rate at which verify flags a true site
arms: {A: {task_env: {}}, B: {task_env: {OUSAST_VERIFY_CALLERS: "off"}}}    # everything else identical
unit: candidate            # candidate | file | repository
pairing: paired            # every unit in both arms
cluster: repository        # resampling unit for intervals
order: {randomise: per_case, seed: 1}   # which arm runs first per case
metric: {primary: "flag_any_pass_rate(positive units)", secondary: ["flag_any_pass_rate(fixed-pin negatives)", "usd_per_candidate"]}
test: {primary: "cluster_bootstrap_paired_diff", secondary: "exact_mcnemar", alpha: 0.05, sides: 2}
mde: 0.15
stopping: {looks: [0.5, 1.0], boundary: "obrien_fleming"}
budget_usd: {total: 15, per_arm: 7.5}
units_file: plane/experiments/exp-001-known-callers.units.jsonl   # frozen list, digest recorded
```

`ousast plane experiment register <id>` checks the manifest, freezes the units file, and records the sha256 of
both as an `experiment` row (a new kind, with repo `experiments/<id>`). It refuses unless both files are committed
at `HEAD`. `ousast plane run` refuses a Run with an experiment annotation whose manifest or units digest differs
from the registered one.

**Randomisation and pairing.** Paired is the default: every unit runs in both arms, and a seeded per-case coin
decides which arm's tasks run first, so provider drift over a run does not align with arms. Only when a variant
cannot run on the same unit (for example, a change to candidate generation itself) are repositories assigned to
arms by a seeded, family-stratified shuffle. Assignment is recorded in the units file.

**Outcomes.** The `experiment-outcome` task (no model), after the arms, writes one `arm_outcome` row per (unit,
arm): outcome, usd from `unit_cost`, and pass details. Spend per arm is also in the plane's attribution table
(`ousast plane status`).

**Statistics.**

- *Primary*: the paired difference B - A in the per-unit outcome, with a 95% CI from a repository-cluster
  bootstrap (10,000 resamples of repositories, with the units inside each). Units in one repository are
  correlated, so a unit-level test would overstate certainty.
- *Secondary*: the exact McNemar test on discordant units (a binomial test with p = 0.5), reported beside it.
- *Sequential*: two looks, at half and all of the repositories (in a pre-shuffled order), with O'Brien-Fleming
  boundaries (|z| >= 2.797 at the first look, 1.977 at the final). Stopping for futility is not binding.
- *Decision*: **adopt B** if the final CI excludes 0 in B's favour, and **reject B** if it excludes 0 against it.
  For a cost-only change, **equivalent** means the TOST 90% CI of the detection difference lies within +-0.05 and
  the cost CI shows a saving. Otherwise **inconclusive**, and the incumbent stays.
- *Engine-level experiments* (priors on/off, roles, feature groups, model variants) cost no model spend. The arms
  are two training configurations evaluated on the same outer folds, and the unit is the repository. The metric is
  recall at BLOCK (or at ADVISORY where BLOCK is not offered), plus false BLOCKs per 100 benign deltas.

**Where results land.** An `experiment_result` row, and `benchmarks/experiments/<id>/result.json` (arms, units,
the estimates at each look, decision, spend, manifest digest, code commit) in the same commit that records the
decision. Adoption of a winning pipeline variant is a maintainer commit that changes the default (a Task
template's env, or a `[models]` value) and cites the result's digest. The memory proposer's M1/M2 status edits
(`improve/memory.py`) become one variant family: a proposed status change runs as an engine-level experiment
instead of going straight to the benchmark gate.

**First experiment, fully specified (Req 4.4).** The question: `plane-increment-2.json` records declared sites
flagged in any pass as 17 for the plane vs 19 for the reference, of 20. The plane added the known-callers line
(`plane/tasks/verify.py:1-9, 164`, `CALLERS_CAP = 8` at :34), and the comparison is confounded (other changes,
stochastic passes, v2 is where it was seen).

- **Arms.** A is `verify` as today. B is `verify` with `OUSAST_VERIFY_CALLERS=off`, a new switch (about 3 lines)
  that makes `callers_line` return empty. Same model (`deepseek-flash`), `PER_HUNT = 6`, `MAX_STEPS = 6`, same
  candidates, same `facts.json`, same runner image digest, two passes (a, b) per arm.
- **Units: the development corpus, not v2** (v2 generated the hypothesis):
  - population v1, 11 cases, whose engine scans are recorded under `~/ousast-results/independent-v1/scans/` (44
    scans);
  - pmpro, MediaWiki, WP Statistics (dev-php);
  - the 27 full-repository pointer pairs in the verify families (`recipe` pairs of vibe-py and agent-vfc,
    tier != title).

  That is 41 repositories. No development repository has recorded verify candidates today. They are generated
  model-free and frozen in the units file: per pin, the fix-changed functions, plus the top engine- and
  quick-alert functions, up to 8 candidates per pin, on the vulnerable and the fixed pin. Only units where arm A's
  callers line is non-empty are *treated*. The primary analysis is restricted to them, and the rest are reported.
- **Metric.** Primary: the per-positive-unit rate of "flagged in any pass" (the 17-vs-19 metric), with positives
  from the label builder (fix-range functions on the vulnerable pin). Secondary: the flag rate on fixed-pin
  negatives (false flags), and usd per candidate.
- **Sample size and MDE.** About 55 positive units across 41 repositories (about 28 dev + 27 pointer pairs). With
  a discordance rate of about 0.15, alpha 0.05 and power 0.8, the paired MDE is `(1.96 + 0.84) * sqrt(0.15) /
  sqrt(55)`, about **0.15**. The observed gap of 0.10 needs about 115 positive units, so an inconclusive result is
  the likely and honest outcome. It is registered as such in advance, and a follow-up needs new units, not a
  continuation.
- **Budget.** Hunts per pass per arm: 14 dev repositories x 2 pins x up to 3 files (84) + 27 pairs x 2 sides (54)
  = 138. Four arm-passes give 552 hunts x $0.014, **about $7.7 expected**. The ceiling is **$15 total, $7.5 per
  arm**, enforced by the task budgets (`plane/budget.py`). Candidate generation reuses the recorded v1 engine
  scans. For dev-php it runs the engine once per pin on the host, one container at a time, from a frozen source
  export.

### 7. Extrapolation and the one-time v3 check (Requirement 5)

**Learning curves (5.1).** `ousast learn curve --family F --profile P` works in two directions:

- *By repositories*: training on random subsets of 20, 40, 60, 80 and 100% of the outer-training repositories,
  20 subsets per size, each evaluated on the same outer folds.
- *By sources*: training on 1..S of the leave-one-source-out sources, in all orders, capped at 50.

Per point: recall at ADVISORY, recall at BLOCK (where offered), PR-AUC, Brier score, and false BLOCKs per 100
benign deltas. Bands are the 2.5/97.5% quantiles over subsets x repository bootstrap. An inverse power law
`m(n) = a - b * n^-c` is fit to each curve. The projection to 1.5x and 2x the repositories is reported only as a
band, and only where the fit's own bootstrap CI for `c` excludes 0.

**Expected detection on unseen code (5.2).** Per family and per language (and per framework, Req 8.3): the
outer-fold and leave-one-source-out intervals at both operating points, with priors off and with adopted priors.
A stratum with fewer than 10 positive repositories or 10 negative repositories, or whose 95% interval on recall is
wider than 0.5, is printed as **"insufficient data (n repositories)"**, with no number. Today that applies to
memory, prototype, PHP untrusted_destination, and every plane-profile family until the harvest Run.

**The v3 check (5.3), exactly once.**

1. *Before.* The engine and every operating point are adopted, and population v3 is still reserved and unread by
   this spec's code (it is absent from `learn/sources.toml`). `ousast learn predict --population-name
   population-v3-php` writes `benchmarks/independent/prediction-v3.json` and it is committed:
   - the adopted model ids and shas per (family, profile);
   - `feature_set_digest`, priors and roles settings;
   - the operating points;
   - the frozen analyzer source hash (`benchmarks/push/freeze_source.sh`);
   - for each family v3 may contain, the predicted recall and precision intervals from the PHP stratum where
     sufficient, else the pooled-language interval with the label "no PHP stratum";
   - the predicted false BLOCKs per 100 benign deltas;
   - the reference to `protocol-v3.md`, written by the population's owner, not by this spec.

   Only the population's name is needed; its file is not opened.
2. *Run.* v3 is scored under protocol v3, once, by its owner's runner, with the engine's decisions added to the
   recorded outputs.
3. *After.* `benchmarks/independent/result-v3-engine.json` holds, per family, the measured point and interval
   beside the predicted interval, `inside | outside`, the calibration check on v3, and the reach misses. v3 is
   then added to `learn/sources.toml` as spent, and the next model may train on it. Its numbers never again
   qualify anything.

### 8. Integration (Requirements 6, 7.3, 7.5)

**Lookup.** The model comes from, in order:

1. `[decision] model` in the config (a path);
2. the store's `models/adopted.json` when `OUSAST_MEMORY` is set;
3. the packaged `ruleset/decision/<family>-<profile>.json`;
4. none.

`learn/decide.py` is pure Python: `load_models(...) -> Models` and `decide(record, models) -> Decision(p,
operating_point, model_id, top, offered)`.

**`ousast scan`.** A `decide` stage runs after the findings are complete and before `findings.json` is written
(`cli.py:517-520`). It builds `static` records with `build_for_scan` from the quick findings, the engine result,
`analyze_entry_points` and the `repo-facts` functions (source-only), plus deterministic roles. It scores each
candidate and attaches `decision` to the finding: `{p, operating_point: block|advisory|drop, model_id,
top_features, offered}`. Candidates at or above ADVISORY are reported. Dropped ones go to `dropped_by_engine.json`,
beside `shadow_findings.json`. Shadow-status findings enter as candidates too, so a rule's enabled/shadow status
changes the report only if the decision changes (Req 6.3). The shadow split at `cli.py:503-508` applies only in
the fallback. `--fail-on blocked` is a new choice (exit 1 on any BLOCK), and `findings` keeps its meaning.
Markdown, SARIF (`properties.decision`) and `manifest.json` (`decision: {model_ids, fallback, reason}`) carry the
fields.

**`ousast pre-push`.** Candidates are the `CandidateDelta`s from `compare_evidence`, enriched with quick-rule
hits and deterministic roles on the changed functions of head and base. `admit_candidates` (`push/policy.py:879`)
gains `engine: Models | None`:

- With a model, the capability-eligibility reasons `capability_unavailable`, `capability_ambiguous`,
  `capability_disabled`, `capability_unevaluated` and `operation_semantics_mismatch` are replaced by the engine's
  reasons: `engine_below_block`, `engine_block_not_offered` (family insufficient or calibration failed), or none.
- Every structural reason stays a hard requirement: `comparison_provenance_mismatch`, `insufficient_rung`,
  `unchanged`, `change_unsupported`, `witness_unresolved`, `location_unresolved`, `family_semantics_mismatch`,
  `claim_discharged` and `dependency_unresolved` (`push/policy.py:909-960`). `PushReport` invariants
  (`push/report.py:48-97`) require witnesses, locations, consequence and repair for actionable defects.
- With no capability, consequence and repair come from family-level templates shipped beside the model:
  language-level text, never framework text.
- `--mode blocking` blocks only on BLOCK. `--mode advisory` lists ADVISORY and above. Each disposition carries
  `{p, operating_point, model_id, top_features}` in the artifact and one line in the compact report
  (`render_report`, `push/report.py:214`).
- The 30 s default deadline (`cli.py`, `--deadline 30.0`) covers feature building. Everything in the `static`
  profile is source-only or already computed by the scan. Model roles run only with `--model-config`.

**Plane Runs.** The `decide` task (no model) writes `decisions.jsonl`, `remember` stores `decision` rows, and
`ousast plane status` prints BLOCK/ADVISORY counts per case.

**Fallback (6.2).** With no model, or a family below the floor, today's behaviour applies unchanged: rule
statuses, quick/engine findings as they are, pre-push with the empty capability registry. The report says so in
one line: "decision engine: not used (no adopted model | family insufficient data | calibration failed) --
findings are today's rule output". A family whose BLOCK is not offered still gets ADVISORY decisions.

**User adaptation (7.5)** is opt-in: `[decision] adapt = true`. It keeps the user's dismissals in
`.openultrasast/decisions/dismissals.jsonl` in their repository, as finding fingerprints with the model id, and
applies them after the engine: a dismissed fingerprint is suppressed, and optionally a per-repository intercept
offset is fitted on at least 10 dismissals. It never writes to the memory store. The label builder refuses any row
with `origin: user`. It is evaluated separately: on held-out training repositories, by replaying the first half
of their labels as dismissals and measuring the second half. It is reported as "adaptation", never merged into the
generalisation numbers.

## Data Models

- `features` row: envelope (`id, kind, repo, pin, run, task, population, split, image`) + `{candidate, family,
  language, profile, schema_version, feature_set_digest, unit, base?, x, instruments}`.
- `label` row: envelope + `{candidate, family, label, source, source_ref, unit, direction?, weight, split, group,
  frameworks, created, evidence}`. Written only by `ousast learn labels`.
- `decision` row: envelope + `{candidate, family, profile, model_id, p, operating_point, offered, top: [{feature,
  value, contribution}]}`.
- `experiment` row: `{experiment, manifest_sha256, units_sha256, registered, code_commit}`. `arm_outcome` row:
  `{experiment, arm, unit, outcome, passes, usd}`. `experiment_result` row: `{experiment, look, estimate, ci,
  mcnemar_p, decision, spend}`.
- `KINDS` (`plane/memory.py:52`) gains `features, label, decision, experiment, arm_outcome, experiment_result`,
  and `TAG_FIELDS` is unchanged (`family` is already a tag).
- Blobs: `models/<sha>.json`, `models/index.jsonl`, `models/adopted.json`, `curves/<sha>.json`,
  `labels/<sha>.jsonl`.
- Files: `learn/sources.toml`, `ruleset/frameworks.toml`, `ruleset/decision/*.json`,
  `plane/experiments/<id>.yaml` + `.units.jsonl`, `benchmarks/experiments/<id>/result.json`,
  `benchmarks/independent/prediction-v3.json`, `result-v3-engine.json`.

## Error Handling

- Every failure of the feature builder is loud. An instrument that did not read its input records `state:
  failed`, and a Run's `features` task fails when every instrument failed for a case. A plausible all-zero record
  is impossible because zero requires `state: ran`.
- `validate_record` rejects unknown features, out-of-vocabulary enums and label fields, naming the feature and the
  source file.
- The label builder exits 2 on a source that is not in `sources.toml`, a population whose status is not recorded,
  or a group that straddles an outer fold after the merges. The error names the repository.
- Training refuses a (family, profile) below the floor and writes an "insufficient data" artifact stub, so
  `decide` can say why. It refuses when a label's `group` appears in both an outer training and evaluation fold,
  as an assertion before fitting. Newton non-convergence after 50 iterations fails with the lambda and the
  condition number.
- `decide` with a model whose `schema_version` or `feature_set_digest` differs from the builder's falls back,
  with the reason in the report, and never scores a mismatched vector.
- Experiments: a registration mismatch refuses the Run. A budget ceiling ends an arm `unfinished` (`budget.py`),
  and the analysis then reports "incomplete: arm B stopped at $x" and records no decision.
- `put_blob` on FileStore applies the 1 GiB free-space refusal (`plane/memory.py:341`).

## Testing Strategy

- `tests/test_learn_schema.py`: allow-list, name invariance, label fields excluded, missing vs zero (section 1).
- `tests/test_learn_labels.py`, on fixture populations and pairs:
  - positives and negatives per rule, including a fixed-pin function the fix did not touch (not a negative), and
    an unmatched vulnerable-pin candidate (unlabelled);
  - `unscorable` and title-tier exclusion;
  - an adjudication mapping;
  - a source not in `sources.toml`, which cannot label, checked with a fixture population named like v3 and a test
    that asserts the builder never opens its file (`open` monkeypatched);
  - CVE-based group merge.
- `tests/test_learn_folds.py`:
  - no group in both train and test, for outer, leave-one-source-out and leave-one-framework-out folds;
  - inner folds nested;
  - determinism by seed.
- `tests/test_learn_train.py`:
  - Newton fit on a separable-with-noise fixture;
  - `test_matches_sklearn` (optional extra);
  - reproducible bytes from the same store snapshot on FileStore and on MinioStore (gated as today);
  - weights cap per repository;
  - floor refusals.
- `tests/test_learn_calibrate.py`: Platt on a known miscalibration, the slope/intercept check, and the
  ADVISORY-only downgrade.
- `tests/test_learn_decide.py`: operating points, explanations (top-5 order and signs), the missing-instrument
  display, and version-mismatch fallback.
- `tests/test_learn_experiments.py`:
  - registration digest and refusal;
  - paired bootstrap CI on a fixture with a known difference;
  - exact McNemar values against hand-computed binomials;
  - O'Brien-Fleming boundaries;
  - adopt / reject / inconclusive / equivalent decisions.
- `tests/test_semantic_priors.py`:
  - the lint test (no untagged entry contains a `frameworks.toml` symbol);
  - `priors="off"` removes exactly the tagged entries;
  - the split entries keep their language-level calls.
- `tests/test_learn_roles.py`: wrapper inference to depth 3 on a fixture, and unclassified chunks are never "no
  roles".
- `tests/test_plane_features.py`, `test_plane_decide.py`: fixture run directories from the validation-46 shapes.
  `features` drops `site_match`/`in_fix_range`, and `remember` stores `features`/`decision` rows.
- `tests/test_push_decision.py`: admission with an engine replaces only the capability reasons, and every
  structural reason still blocks admission. `PushReport` invariants hold with engine templates.
- `tests/test_scan_decision.py`: the scan fallback line, `dropped_by_engine.json`, and that a shadow/enabled
  status flip without a decision change leaves the report unchanged.
- Regression net: the existing gate, pair and plane tests. `test_benchmark_output_is_byte_identical_to_golden_baseline`
  holds with no model adopted (the fallback is today's path).
- Joern-gated tests run only with the mount recipe (memory note "Joern-gated tests run nowhere"). The engine-alert
  harvest is verified by its own read-count check, not assumed.

## Requirement Traceability

| Requirement | Design section | Verified by |
| --- | --- | --- |
| 1.1 one record per candidate from every instrument | 1 | `test_plane_features.py`, `test_learn_schema.py` |
| 1.2 missing is not negative | 1 (instrument state, `null`) | `test_missing_is_not_zero` |
| 1.3 versions and digests for rebuild | 1 (versioning), 5 | `test_learn_train.py::test_reproducible` |
| 2.1 positives/negatives by source | 3 | `test_learn_labels.py` |
| 2.2 plane verdict is a feature, not a label | 1, 3 | `test_label_fields_never_reach_features`; label rules |
| 2.3 provenance; reserved populations unusable | 3 (`sources.toml`, fail-closed) | `test_learn_labels.py` (v3-named fixture never opened) |
| 3.1 simple, calibrated, per family or pooled | 4 | `test_learn_train.py`, `test_learn_calibrate.py` |
| 3.2 reproducible, versioned | 5 | reproducibility test on both backends |
| 3.3 population-level folds, no repository in both | 4 (folds) | `test_learn_folds.py` + pre-fit assertion |
| 3.4 operating points on training folds | 4 | `test_learn_decide.py` |
| 3.5 explanations stored | 4, 8 | `test_learn_decide.py`, `test_scan_decision.py` |
| 4.1 pre-registered experiment | 6 (manifest, register) | `test_learn_experiments.py` |
| 4.2 paired, assignment and spend recorded | 6 | `arm_outcome` rows; `ousast plane status` |
| 4.3 adopt only on a CI excluding zero or equivalence | 6 (decision rule) | `test_learn_experiments.py` |
| 4.4 known-callers experiment first | 6 (exp-001) | commit 7 record |
| 5.1 learning curves with bands | 7 | `ousast learn curve` output; unit test on a fixture |
| 5.2 intervals per family and language; insufficient data | 7 | `test_learn_decide.py` (floor), report fixture |
| 5.3 v3 checked once, after freezing | 7 | `prediction-v3.json` committed before `result-v3-engine.json` |
| 6.1 probability, operating point, top features in reports | 8 | `test_scan_decision.py`, `test_push_decision.py`, `test_plane_decide.py` |
| 6.2 fallback said in report | 8 | `test_scan_decision.py` |
| 6.3 rule status no longer changes output alone | 8 | status-flip test |
| 7.1 repository-grouped folds across corpora | 3 (group, CVE merge), 4 | `test_learn_folds.py` |
| 7.2 repository-agnostic allow-list with test | 1 | `test_learn_schema.py` |
| 7.3 BLOCK/ADVISORY on unseen repositories; delta unit | 1 (delta), 4, 8 | outer-fold report; `test_push_decision.py` |
| 7.4 calibration checked out of repository; else ADVISORY only | 4 | `test_learn_calibrate.py` |
| 7.5 opt-in adaptation outside the numbers | 8 | label builder refuses `origin: user`; separate report |
| 8.1 language-level knowledge; roles inferred | 2 | `test_learn_roles.py` |
| 8.2 tagged priors, off by default, kept by A/B | 2, 6 | `test_semantic_priors.py`; engine-level experiment records |
| 8.3 leave-one-framework-out, per framework | 2, 4 | `test_learn_folds.py`; report strata |
| 8.4 share depending on priors | 2, 7 | report columns priors off / adopted / difference |

## Commit sequence, mapped to future tasks

Each commit is gated on the full suite's own exit code, `ruff` and `mypy`. None changes a reported number until
commit 9 adopts a model, and without an adopted model every path is today's.

1. **Schema and features** (1.1-1.3, 7.2): `learn/schema.py`, `learn/features.py` (host builder), the new
   `KINDS`, and `plane/tasks/features.py` + the `remember` input, with tests.
2. **Framework tags** (8.2, 8.4): `ruleset/frameworks.toml`, the tags and splits of section 2, `priors=` in the
   semantic and quick loaders (default `all` for today's scan), and the lint test. Verify that
   `test_benchmark_output_is_byte_identical_to_golden_baseline` is unchanged with `priors=all`.
3. **Roles** (8.1): `learn/roles.py` (wrapper inference), `plane/tasks/roles.py` (model roles from
   `model_sinks.py`), and the vocabulary overlay for the engine. Fixture tests, no model call in tests.
4. **Labels** (2.1-2.3, 7.1): `learn/sources.toml`, `learn/labels.py`, `ousast learn labels`, group
   normalisation and CVE merge, and a first label snapshot committed as a measurement record (counts only).
5. **Harvest** (1.1, data): a plane Run of verify a/b on the 78 verify-family pairs and the development cases
   (about $6, ceiling $10), model roles on the candidate files (ceiling $10), and engine features for the pair
   corpus on the host (frozen source, one container at a time, in the background).
6. **Train, calibrate, evaluate** (3.1-3.5, 5.1-5.2, 7.3-7.4, 8.3): `learn/{folds,train,calibrate,evaluate}.py`,
   the model blob API in `plane/memory.py`, `ousast learn train|evaluate|curve`, and the first evaluation report
   (priors off), committed under `benchmarks/measurements/<date>-decision-engine-v1/`.
7. **Experiments** (4.1-4.4): `learn/experiments.py`, the `register` command, `experiment-outcome`, the Run
   annotation checks, `OUSAST_VERIFY_CALLERS`, and exp-001 registered, run and recorded.
8. **Integration** (6.1-6.3, 7.3, 7.5): the `decide` task, the `scan` stage, `pre-push` admission with the engine,
   report fields, the fallback line, and the opt-in adaptation layer.
9. **Adopt** (3.2, 8.2): `ousast learn adopt`, the packaged models for families that pass, and the priors-on/off
   engine experiment per framework with a recorded decision.
10. **v3 check** (5.3): `prediction-v3.json` is committed first, then v3 is run by its owner under protocol v3, and
    `result-v3-engine.json` is committed. Nothing between the two commits may touch the engine, features, priors
    or thresholds.

## Risks

- **Label scarcity decides what can be trained.** The status of each family today:
  - memory (7 repositories, 172 of its 176 pairs from openssl and curl) and prototype (6) are **insufficient
    data**. Users get today's behaviour there, labelled as such.
  - PHP has no pairs, and only about 13 population repositories. The v3 prediction will mostly be the pooled
    interval, marked "no PHP stratum", and it will be wide.
  - The plane profile has 43 rows from one population until the harvest Run.
  - BLOCK at 95% precision is likely **not reachable** for most families on this data. The design reports "BLOCK
    not offered" instead of lowering the target.
- **Weak signals.** The pair baseline has quick-rule labelled recall 0.24 and Youden -0.013 overall
  (`pairs.json` `overall`). The v2 engine recall is 0/17 (`results-v2.json`). A calibrated model over weak signals
  is honest but may be close to the base rate. Recall at ADVISORY 0.90 may need an ADVISORY threshold so low that
  precision is poor. That is reported, not tuned away on outer folds.
- **Leakage paths and their guards.**
  - Label fields in features (`site_match`, `in_fix_range`, fixed-pin alerts): the allow-list and test.
  - The same repository under two names or corpora: normalised group plus CVE merge.
  - Hand rules and framework priors written after seeing a training repository (the `$wpdb` rule from PMPro, the
    hook source from WP Statistics, `taint.sc:911-949`): the priors-off default, and leave-one-framework-out.
    Rules may also carry `taught_by = [repo]`, which masks their features in folds that evaluate those
    repositories. It is backfilled best-effort from comments and git history, and its absence is stated.
  - The mechanism exporter's train-on-test leak (`closed-loop-train-on-test-leak.md`): no exporter output is a
    feature, and mechanism buckets come from the fixed vocabulary.
  - Verify and tie-break design fitted on v2: the v2 fold is marked design-informed.
  - Threshold and lambda selection on outer folds: nested folds, and a pre-fit assertion.
  - v3: fail-closed sources, never opened.
  - User dismissals: refused by the label builder.
- **Prevalence shift.** Calibration on 1:1 pairs overstates the probability in a real push. The primary safety-net
  figures (recall; false BLOCKs per 100 benign deltas) do not depend on the mix. The benign-delta sample is small:
  28 population benign deltas plus pmpro, so the 95% upper bound for 0 false BLOCKs is about 0.12 per push. Benign
  history deltas are the planned remedy and are reported with and without.
- **Framework inference is itself a model.** Model roles cost money and can be wrong. `scan` without `[models]`
  gets only wrapper inference, whose reach on framework-heavy code without dependency source is poor. The report
  says which role source ran. Both are measured by the roles-on/off engine experiment. Nothing assumes they help.
- **Cost on the 7 GB host.**
  - Model spend is small: the harvest about $6, exp-001 about $8, model roles on candidate files about $10, all
    under task ceilings.
  - Engine features are the time cost: about 427 pairs x 2 sides x 30-60 s of JVM and CPG per excerpt is 7-14
    hours serial, plus dev-php full-repository scans of 200-2,000 s each (`results-v1.json` `seconds`). They run
    once per engine image, from a frozen source export, one container at `--memory 3g` at a time, never beside the
    kind cluster's verify pods. Results are cached by (content sha, image id) in the store. The home volume was at
    98%, and records are small (about 1 KB per candidate), but each engine run's scratch output must be cleaned
    per case.
- **Experiments will often be inconclusive.** With 41 development repositories the MDE is about 15 points.
  Pre-registering that and recording "inconclusive" is the intended behaviour. The failure mode to avoid is
  extending an experiment after looking.
- **Pure-Python numerics.** Newton on near-separable data (a feature that alone separates a small family) can
  diverge. L2 with lambda >= 0.01 and the iteration cap bound it, and the sklearn cross-check catches drift.

## Maintainer decisions at design approval (2026-09-30)

- Design approved as written.
- Benign pushes: ordinary non-security commits are mined as **assumed-benign** pushes (no security keyword, no later
  fix touching the same lines), kept as their own label source (`assumed_benign`), reported separately from the
  verified negatives, and never merged with them.
