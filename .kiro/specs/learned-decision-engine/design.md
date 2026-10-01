# Design Document

## Overview

Detection decisions move out of hand edits and into an AI classifier with local memory. The instruments stay and
emit signals. A model-free feature builder turns those signals into one record per candidate. A label builder
attaches ground truth from sources we can defend, and labelled cases become a local memory of examples. A
language-model program, compiled DSPy-style in-house (Req 3, changed 2026-10-01: "We will not be able to scale up
data"), reads the candidate's code, its signals and its inferred roles together with similar labelled cases
retrieved from memory, and answers a verdict with a confidence. That confidence is calibrated only on repositories
the program never saw, and two thresholds on it (BLOCK, ADVISORY) are what `pre-push`, `scan` and plane Runs report.
No statistical model is fitted. Pipeline changes, program variants included, are pre-registered, paired
experiments.

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
  classifier over verify signals cannot be evaluated today. The design starts from the signals every labelled row
  can have, harvests the rest at a stated cost, and accepts that data will stay small: the engine learns by
  memory and compilation, not by fitting parameters.
- **The core install is PyYAML only** (`pyproject.toml:11`). numpy, scipy and scikit-learn are not installed in
  `.venv`. Retrieval (a Gower distance and a cosine over at most 40 vectors) and calibration (two-parameter Platt)
  stay pure Python; the model calls go through the plane's metered client (section 4).
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
| Engine | a language-model program, in-house DSPy-style: signature (code excerpt, signals, roles, family -> verdict, family, confidence, rationale with cited lines), modules `Retrieve -> Classify(k)`, every call through `MeteredClient` bound to a Model per task; no statistical model is fitted |
| Models | DeepSeek (`deepseek-flash`) for classification; OpenRouter (`openai/text-embedding-3-small`) for embeddings only |
| Memory | `example` rows (label + record + excerpt) in the MemoryStore; stage 1 Gower nearest neighbours on the signal profile with explicit missing, stage 2 code-embedding re-rank, 6 examples under a label/family/repository balance rule; an evaluation-boundary filter with a test |
| Compilation | pre-registered balanced Brier score on a compile split of repositories never evaluated; bootstrap few-shot (3 demonstrations) and instruction search (6 proposed + baseline); ceiling $3 per compile; responses cached for byte-identical replay |
| Families | one program for all families; calibration and operating points per family at >= 20 positive and >= 20 negative repositories, pooled at >= 10, otherwise "insufficient data" |
| Calibration | Platt scaling of the program's score, cross-fitted over outer folds; checked per fold (reliability, slope, intercept, ECE); if it fails, ADVISORY only |
| Folds | outer grouped 5-fold by repository (one repetition), plus leave-one-source-out and leave-one-framework-out; compile split disjoint from every evaluation fold |
| Operating points | BLOCK: lowest threshold whose Wilson lower bound on precision is >= 0.95, chosen on the other folds' predictions, never on a majority `unsure`; ADVISORY: threshold reaching 0.90 recall; reported with repository-bootstrap intervals |
| Artifacts | content-addressed compiled-program JSON under `programs/` in the store; adopted version exported into the package by a maintainer commit |
| Cost | ~$0.003 per candidate (k = 1), ~$0.0045 (k = 5, cached); ~$2.2 per compile; ~$3.4-5.2 per full evaluation; first slice ~$5, $7 ceiling, within today's balance |
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
   labels (new, host only, never in a sandbox)        embed (new, Model: OpenRouter embeddings)
   populations: matches_v2 / fix ranges                       |
   pairs: vulnerable vs fixed side                    decide (new, Model: DeepSeek, metered)
   benign deltas, adjudications                       Retrieve (signals -> embeddings, boundary filter)
   source allow-list: v3 absent                       -> Classify(k) -> calibrated p, operating point,
                     |                                rationale -> decision rows / report fields
   memory build/embed (host) -> example rows,             ^           ^ seeded, boundary-filtered memory
   excerpts, embeddings in the store ---------------------+-----------+
                     |                                            |
   learn compile/evaluate (host, metered) ---- program artifact (programs/<sha>.json) ---- adopt (maintainer)
   compile split, bootstrap demos, instruction search,            |
   grouped folds, cross-fitted Platt, thresholds, curves  packaged: ruleset/decision/program-<profile>.json
   experiments (plane Runs with arms) -> arm_outcome rows -> analysis -> adopt | reject | inconclusive
```

A plane Run per case becomes `facts -> va, vb -> agree -> vc -> final -> alerts -> roles? -> features -> embed ->
decide -> remember`. `roles` is optional and Model-bound. `features` is model-free with budget `{usd: 0, calls: 0}`,
as `remember` and the loop steps are (`plane/tasks/loop.py:1-5`). `embed` and `decide` are Model-bound (one Model
per Task, `plane/egress.py:87`) and metered. `remember` ingests the new `features` and `decision` rows. Labels are
never computed in a Run. They are built on the host from ground-truth files the sandbox never receives, so no task
that produces a feature can read a label.

New code: `src/openultrasast/learn/` (`schema.py`, `features.py`, `roles.py`, `labels.py`, `sources.toml` -- done --
and `excerpt.py`, `examples.py` (example store), `retrieve.py`, `program.py`, `compile.py`, `folds.py`,
`calibrate.py`, `evaluate.py`, `decide.py`, `experiments.py`, `compile.toml`),
`src/openultrasast/plane/tasks/{features,roles,embed,decide}.py`, `plane/models/openrouter-embedding.yaml`,
`ruleset/frameworks.toml`, `ruleset/decision/`, and CLI groups `ousast learn ...` and `ousast plane experiment ...`.
The reconciler is not touched. Its 500-line budget stays (`tests/test_plane_reconciler.py`).

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
repository exists. Every feature of an instrument whose state is not `ran` is `null`. The engine never imputes a
`null`: retrieval compares instrument states block by block (section 4.2), and the prompt shows "no coverage",
"failed" or "not applicable" in words.

**Profiles.** `static` is what `pre-push` and `scan` can compute locally without a model: quick rules, engine,
facts, deterministic roles and delta. `plane` adds verify, agree and model roles. A program is compiled and
calibrated per profile. A `static` program never sees verify features, in its prompt or its memory, so it cannot
learn to lean on an instrument that is absent in deployment.

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

**Evaluation (Req 8.2-8.4).** The engine is always compiled and reported with `priors=off` (prior features hidden
from the prompt and from the retrieval distance). A prior group (one
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

- The `static` profile can be evaluated for six families, pooled for output_encoding, and not at all for memory or
  prototype.
- The `plane` profile cannot be evaluated until verify has run on labelled units. The harvest Run in the commit
  sequence (step 5) runs passes a and b on the 78 scorable, non-title pairs in the verify families (injection,
  untrusted_destination, config_secrets; `verify.OPERATIONS`, `plane/tasks/verify.py:38-50`) on both sides, and on
  the development cases. That is about 312 + 110 hunts at $0.014 each (validation-46: $0.8567 over 61 hunts),
  **about $6**.
- PHP is reported as its own stratum only where it reaches 10 positive repositories. Today that is injection at
  the boundary, and untrusted_destination is "insufficient data".

### 4. The decision engine: an AI classifier with local memory (Requirements 3, 7.1, 7.3, 7.4)

The engine is a declared language-model program, compiled DSPy-style, not a fitted statistical model (Req 3.1).
Maintainer, 2026-10-01: "We will not be able to scale up data" and "we need to have the decision engine on AI
classifier not ML. with local memory, dspy style". Choices: DSPy-style **in-house** (the DSPy library is not a
dependency), and retrieval by **signals + code embeddings**. DeepSeek is the LLM; OpenRouter serves embeddings
only (memory note "Model calling was broken 2026-09").

What it builds on:

- the metered client `MeteredClient` (`plane/budget.py:66-152`): usd and calls ceilings, `BudgetExhausted` ->
  `unfinished`, `AccountError` -> `failed`, prices from a Model manifest (`prices_from`, `plane/budget.py:45-54`;
  `plane/models/deepseek-flash.yaml`: $0.014 cache hit, $0.44 miss, $1.32 output per million tokens);
- the Model-bound task pattern of `plane/tasks/roles.py:141-241` (injected client, units log, restart skip, exit
  codes 0/2/3), and `build_client` (`plane/tasks/verify.py:335`);
- `DeepSeekChatClient` (`model/endpoint.py:91-150`): thinking disabled so temperature is honoured, JSON mode with
  one empty-content retry, optional logprobs (`ChatResponse.mean_logprob`, `tool_hunter.py:160, 287`);
- `OpenRouterEmbeddingClient.embed` (`provider/openrouter.py:137-170`) and `[embeddings] model` /
  `OPENROUTER_EMBEDDING_MODEL` (`config.py:85-88, 294-298`; `.env.example`: `openai/text-embedding-3-small`);
- the feature record (`learn/features.py:78-115` `record`, `learn/schema.py:231` `validate_record`, the
  `EXCLUDED_FIELDS` deny-list at `learn/schema.py:88-95`), roles (`learn/roles.py`), labels and groups
  (`learn/labels.py:296-320` `Label`, `:182` `Groups`, floors at `:53-54`), and `function_span`
  (`learn/features.py:234`) for excerpts;
- the store (`plane/memory.py:182-298`, `KINDS` at `:55-58`, `put_facts`/`get_facts` at `:225-262`, the 1 GiB
  free-space refusal at `:347`) and the host seed of a Run's memory snapshot (`memory.seed`, `plane/memory.py:642`;
  the sandbox cannot read the store, `plane/tasks/loop.py:8-11`).

#### 4.1 The program

**Signature** (`learn/program.py`, a frozen dataclass rendered into the prompt and used to parse the answer):

| Field | Direction | Type and bound |
| --- | --- | --- |
| `code` | in | the candidate function, numbered lines, at most 80 lines and 4,000 characters (section 4.2 excerpt rules); for a `delta` unit, also the base->head diff of the function, at most 40 lines |
| `signals` | in | the allow-listed record `x` and `instruments` states, rendered as `name: value` lines, `null` shown as "<instrument>: no coverage / failed / not applicable"; validated by `validate_record` before rendering; nothing from `EXCLUDED_FIELDS` |
| `roles` | in | inferred roles of the function (`learn/roles.py` wrapper roles; model roles in the `plane` profile): role, operation, line, origin (`ORIGINS`, `learn/schema.py:83`) |
| `family` | in | the candidate's family (from the rule or engine family; `unknown` allowed) |
| `verdict` | out | `vulnerable` \| `not_vulnerable` \| `unsure` |
| `family` | out | one of the families, or `none` |
| `confidence` | out | float in [0, 1], the model's stated probability that its verdict is right |
| `rationale` | out | at most 3 sentences; must cite at least one line number of `code` (`cited_lines`), and may name signals |

The answer is JSON (`json_object=True`). A reply that does not parse, or cites no line in range, is retried once
at temperature 0; if it still fails it becomes `unsure` with `parse_failed: true` in the decision row, never
`not_vulnerable` ("verify the instrument": a broken answer is not a clean result).

**Modules**, composed as `Program = Retrieve -> Classify(k)`:

- `Retrieve(record, excerpt, boundary) -> examples` (section 4.2), model-free except for one embedding of the
  candidate excerpt (cached).
- `Classify(k)`: the prompt is `instruction + fixed demonstrations` (the compiled prefix, identical for every
  candidate so the provider's prefix cache hits) `+ retrieved examples + the candidate`. Sample 1 runs at
  temperature 0; samples 2..k at temperature 0.7, issued concurrently. `k` is a compiled setting in {1, 3, 5}.
- The raw score is `s = mean_j p_j` with `p_j = confidence_j` for `vulnerable`, `1 - confidence_j` for
  `not_vulnerable`, and 0.5 for `unsure`/`parse_failed`. The reported verdict is the majority (ties -> `unsure`);
  a majority `unsure` can never reach BLOCK.

**Client plumbing (small, explicit changes).** `MeteredClient.complete` (`plane/budget.py:117-136`) forwards only
`json_object`; it gains `temperature` and `logprobs` pass-through. `DeepSeekChatClient._call`
(`model/endpoint.py:127-142`) adds `temperature` to `extra` beside `thinking`. No provider seed is relied on.
Embedding calls get a metered wrapper `MeteredEmbeddingClient` in `plane/budget.py` that reads the response's
`usage.prompt_tokens` (OpenRouter returns it; `parse_embedding_response`, `provider/openrouter.py:173`, keeps only
the vectors today and is extended to keep usage) and prices it from an embedding Model manifest.

**Plane tasks.** One Model per Task (`egress.policy_for(task, workspaces, model)`, `plane/egress.py:87`), so:

- `embed` (new, Model `openrouter-embedding`, egress `openrouter.ai`): embeds the case's candidate excerpts
  missing from the cache, writes `embeddings.jsonl`. Budget default `{usd: 0.05, calls: 20}` per case.
- `decide` (new, Model `deepseek-flash`): reads `features`, `roles`, `embeddings.jsonl` and the **seeded memory
  snapshot** (the host writes the boundary-filtered examples and the adopted program into the Run's inputs, the
  `loop snapshot` pattern), runs the program, writes `decisions.jsonl`. Budget default `{usd: 0.25, calls: 300}`
  per case. Exit codes as `roles`.

A plane Run per case becomes `facts -> va, vb -> agree -> vc -> final -> alerts -> roles? -> features -> embed ->
decide -> remember`.

**Host path.** `learn/decide.py: decide_all(records, excerpts, program, memory, client, embedder, budget)` for
`scan` and `pre-push`, with the same program code. It needs `[models]` (a DeepSeek key) and either a store
(`OUSAST_MEMORY`) or the packaged program; otherwise the fallback (section 8).

#### 4.2 Local memory retrieval (Req 3.2, 3.4, 3.6)

**The example store.** One `example` row (a new kind in `KINDS`) per labelled candidate that has both a label
(`ousast learn labels`, `learn/labels.py`) and a feature record: envelope + `{candidate, family, language, profile,
label, source, group, frameworks, unit, x, instruments, roles, excerpt_sha, label_set_digest}`. The excerpt is a
content-addressed blob `excerpts/<sha>.txt`; the embedding is `embeddings/<model-slug>/<excerpt_sha>.json` (float32
vector in base64, model id, dimensions, tokens, created). Both use the new `put_blob(prefix, data) -> sha` /
`get_blob(prefix, sha)`, generalising `put_facts`/`get_facts`. Examples are built on the host by `ousast learn
memory build` (model-free) and `ousast learn memory embed` (metered). The snapshot: `verified_pin_labels` 424
positive / 436 negative rows in 105 groups, plus conditional negatives (benign_control 72, assumed_benign 4,671)
that become examples only once their condition (a candidate signal at the tip and none at the base) is evaluated
(`benchmarks/measurements/2026-09-30-decision-engine-labels/labels.json`). Rows name functions and hold third-party
code: the store is local, nothing is committed but counts.

**Excerpt rules** (`learn/excerpt.py`): the function body at the label's pin from the clone (`labels.Clone`,
`learn/labels.py:365`) via `function_span`; numbered lines; no path, repository or commit; comments kept, but
advisory ids (`_ADVISORY`, `learn/labels.py:59`) and lines matching `security_reason` (`learn/labels.py:277`)
inside comments are replaced by `<redacted>`. Candidate excerpts: at most 80 lines / 4,000 characters, centred on
the changed lines of a delta or the engine/quick hit line. Memory examples: at most 40 lines / 2,000 characters.
Memory examples carry **no rationale**: code, signals, roles, family and label only (cheaper, and no generated text
that could leak the label; only the compiled demonstrations carry rationales, section 4.3).

**Stage 1: signal-profile nearest neighbours.** A Gower distance over the allow-listed features of the active
profile (`features_for(profile)`, `learn/schema.py:163`), computed per instrument block so that "missing" is
explicit rather than imputed:

- For instrument `i`, if both records have `state == ran`: `d_i` = mean over its features of `d_f`, where a
  numeric feature is `|a - b| / cap` (the `FeatureSpec.cap`; floats in [0, 1] use 1), a bool or enum is `0` if
  equal else `1`, null in both is `0` and null in one is `1`.
- If the states differ (`ran` vs `none`/`failed`/`not_applicable`): `d_i = 1`. If both are the same non-`ran`
  state: `d_i = 0`. `failed` vs `none` counts as different (`1`).
- `D = sum_i w_i d_i / sum_i w_i`, with `w_i = 1` for every instrument block in the profile (language is one
  block). Prior features (`FeatureSpec.prior`) are dropped when `priors = off`. Weights are a compile-time
  setting only if an A/B shows a gain; the default is uniform.
- Candidates in the eligible pool (after the boundary filter) are ranked by `D`, ties by `sha256(example_id +
  seed)`; the first `n1 = 40` of the candidate's family and the first `n1` of the other families go to stage 2
  (per side since 2026-10-01, so a minority family reaches stage 2; Risks, "First paid slice").

**Stage 2: code-embedding re-rank.** Cosine similarity of the candidate's excerpt embedding with each stage-1
example's. The re-rank score is `r = lam * (1 - D) + (1 - lam) * cos`, with `lam` a compiled setting in {0, 0.5}
(default 0.5). An example or candidate without an embedding (budget, provider failure) keeps its stage-1 order,
and the decision row records `retrieval: "signals_only"`. Embedding model: `openai/text-embedding-3-small` via
OpenRouter (1,536 dimensions; $0.02 per million input tokens at list price, confirmed by the smoke run's `usage`).
Cache key `sha256(normalised excerpt)` per embedding model, so the store is embedded once (~5,600 excerpts x ~900
tokens = ~5.0 M tokens, **about $0.10**) and each new candidate costs ~1,200 tokens (**$0.000024**).

**Balance rule** (`k_ret = 6`, a compiled setting in {4, 6, 8}): walk the re-ranked list and take examples subject
to: at most `k_ret/2` per label, at least 2 of each label when the pool has them; at most 2 per repository group;
at least `k_ret - 2` of the candidate's family when the pool has them (the rest from other families as contrast).
If the pool cannot satisfy a minimum, take what exists and record `balance: "short"`.

**The evaluation boundary (Req 3.4, 7.1).** `learn/retrieve.py: eligible(example, target, fold)` is the only way
an example enters a prompt, for retrieved examples and for the compiled demonstrations alike:

- `example.group` is not in the fold's evaluation groups (all of them, not just the target's), and not the
  target's group after the CVE/alias merge (`Groups`, `learn/labels.py:182`);
- leave-one-source-out: `example.source` is not the held-out source;
- leave-one-framework-out on F: `F not in example.frameworks`; a compiled demonstration tagged F is swapped for its
  pre-computed alternate (section 4.3);
- in evaluation, an example whose embedding cosine with the target is >= 0.98 is also dropped as a near-duplicate
  (a vendored copy or fork the group merge missed); the count dropped is reported. In deployment it is kept.
- In deployment (`scan`, `pre-push`), a repository whose normalised name matches a corpus group excludes that group
  from retrieval, and the report says "repository is in the corpus: its own cases excluded".

`tests/test_learn_retrieve.py::test_boundary` builds fixture folds (outer, leave-one-source-out,
leave-one-framework-out) and asserts, for every target and fold, that every retrieved id and every demonstration id
in the rendered prompt is eligible; a second test asserts that `memory.seed` for a plane Run writes no example of
the case's group. A pre-call assertion in `Classify` repeats the check on the ids actually rendered.

**New labels enter memory (Req 3.6).** Adding an example row changes retrieval at once; nothing is recompiled. Each
decision records the `memory_snapshot_digest` (`improve.memory.index_digest`, `improve/memory.py:351`) so the
effect of new labels is an A/B with two memory snapshots as arms (section 6).

#### 4.3 Compilation, DSPy-style and in-house (Req 3.3)

`ousast learn compile --profile P --spec learn/compile.toml` produces a compiled program from a frozen data
snapshot. The compile spec is committed before the compile runs (pre-registration).

**Compile split.** 25% of repository groups (seeded, stratified by family) form the compile split `C`. `C` is
never an evaluation fold; it remains memory for the evaluation of other repositories. Inside `C`, groups are split
60/40 into `C_boot` (demonstration source) and `C_val` (scoring). One compile per profile, not one per outer fold:
nested compiles per fold would cost five times as much, and `C` being disjoint from every evaluation fold keeps the
reported numbers out-of-repository.

**Metric (pre-registered, `compile.toml`).** Primary: the **balanced Brier score** of the raw score `s` on `C_val`,
each (family, label) cell weighted equally and each repository capped at 5 effective rows per cell (the weight rule
of the earlier design). Lower is better; `unsure` and `parse_failed` score as 0.5. Secondary (reported, not
optimised): recall at precision 0.90 and the share of `unsure`. Tie (within 0.005): fewer prompt tokens wins.

**Bootstrap few-shot.** Run the program with no demonstrations (retrieval on, `k = 1`, temperature 0) on up to 150
candidates of `C_boot`. Keep as demonstration candidates those whose verdict is right with `confidence >= 0.7`
and whose rationale cites a line in range and names no identity (repository, path, CVE id: scanned and refused).
The rationale was produced without seeing the label, so a demonstration teaches reasoning, not the answer. From the
pool, draw 4 demonstration sets of `m = 3` (one positive, one negative, one of either; families mixed), seeded. For
every demonstration, an alternate from a different framework is stored for leave-one-framework-out folds.

**Instruction search.** One proposal call gives the model the signature, a glossary of the signals, and 20
summarised bootstrap errors (signals and verdicts, no code), and asks for 6 candidate instructions. With the
hand-written baseline instruction that is 7. Scoring on `C_val` (60 candidates, `k = 1`): the 7 instructions with
demo set 1, then the best instruction with demo sets 2-4: 10 configurations x 60 = 600 calls. Then `k` in {1, 3, 5}
and `lam` in {0, 0.5} are **not** searched in the compile: they are A/B variants (section 6), so compile spend stays
bounded.

**Budget.** About $2.2 per compile (section 4.6); ceiling **$3.00** per compile through `MeteredClient`. A compile
that hits its ceiling records `unfinished` and produces no artifact.

**Reproducibility (Req 3.3).** Every model and embedding response is cached as `responses/<sha>.json`, keyed by
`sha256(model id, Model parameters digest, messages, temperature, sample index, json_object)`. Every random choice
(compile split, demo draws, tie-breaks, subsets) is seeded from `compile.toml`. Re-running a compile on the same
store snapshot with the cache reproduces the artifact byte for byte at $0 (`test_learn_compile.py::
test_reproducible_from_cache`, on FileStore and on MinioStore gated as today). Without the cache, temperature 0 is
not a determinism guarantee at the provider; the artifact records the cache digest so a re-run can say whether it
was replayed or re-asked.

#### 4.4 Folds and calibration (Req 3.5, 7.1, 7.4)

**Folds.** Every split is by `group` (repository), across all corpora; the label builder's merges hold.

- *Outer*: grouped K = 5 over the groups outside `C`, stratified by family and label, **one** repetition (cost);
  intervals come from the repository-cluster bootstrap, not from repetitions.
- *Leave-one-source-out* and *leave-one-framework-out* as in the earlier design (each population and pair slice
  held out whole; framework F held out where F has >= 10 groups). The label snapshot has no framework at 10 groups
  today (`by_framework`: express 4, flask 2, django 1), so leave-one-framework-out is expected to print
  "insufficient data" until the corpus grows; it costs nothing until then.
- The v2 fold stays marked *design-informed*.
- Families below the floors (`PER_FAMILY_FLOOR = 20`, `POOLED_FLOOR = 10`, `learn/labels.py:53-54`) are not
  evaluated at all and get no engine decision: memory, config_secrets and unknown today (385 rows not spent on).

**Calibration.** The raw score `s` is mapped by Platt scaling on `logit(clip(s, 0.01, 0.99))`. It is
**cross-fitted** over outer folds: the map applied to fold j is fitted on the out-of-fold predictions of the other
folds (each of which was itself made with memory excluding its own fold), so no map is fitted on the fold it is
checked on. Per family at the per-family floor; pooled with a per-family intercept between the floors. Isotonic and
binned maps are not used: too few positives per family. The adopted map is refitted on all out-of-fold
predictions. The check is unchanged: reliability table (5 quantile bins), slope and intercept with
repository-bootstrap CIs, expected calibration error. **Holds** when the slope CI contains 1, the intercept CI
contains 0 and ECE <= 0.05; otherwise ADVISORY only, recorded as `block.offered = false, reason = "calibration"`.
The probability stays "calibrated on the labelled mix"; the prevalence-free figures (recall at a point, false
BLOCKs per 100 benign deltas, precision at pi in {0.01, 0.05}) remain primary.

Confidence source alternatives (each an A/B variant, not a default): the verdict token's probability from
`logprobs` (no extra cost), and the verbal confidence alone at `k = 1`. The default is the self-consistency mean
at `k = 5` if the smoke run measures prefix-cache hits on samples 2..k (hit share >= 0.8 of their prompt tokens);
otherwise `k = 1` with verbal confidence, because uncached repeats cost 5x (section 4.6).

#### 4.5 Operating points and explanations (Req 7.3, 6.1)

Operating points are read from the calibrated probability, chosen on the cross-fitted predictions of the folds
other than the one reported (nested, as before):

- **BLOCK**: the lowest threshold whose precision has a Wilson 95% lower bound >= 0.95 among delta units, and the
  majority verdict is not `unsure`. If none exists, `block.offered = false, reason = "precision_unreachable"`.
- **ADVISORY**: the highest threshold reaching recall >= 0.90. Its precision is reported, not assumed.
- **DROP**: below ADVISORY.

Both are reported on outer folds with recall, precision and false BLOCKs per 100 benign deltas, each with a
repository-cluster bootstrap 95% interval (2,000 resamples).

Each decision carries: the calibrated `p`, the operating point, the program id, the majority `rationale` and its
`cited_lines`, the signals the rationale names (checked against the record; names not in the record are dropped),
the retrieved neighbours as counts by label and family (never identities), and `retrieval` mode. These replace the
logistic "top contributing features" of the earlier design in reports (Req 6.1).

#### 4.6 Cost model

Prices: `deepseek-flash` $0.014 / $0.44 / $1.32 per million cache-hit / miss / output tokens; embeddings $0.02 per
million. Token sizes are estimates to be replaced by the smoke run's measured `usage`:

| Prompt part | Tokens | Cached |
| --- | --- | --- |
| instruction | ~500 | yes (shared prefix) |
| 3 compiled demonstrations (40-line excerpt, signals, label, rationale) | ~2,250 | yes |
| 6 retrieved examples (~750 each) | ~4,500 | no |
| candidate (80-line excerpt ~1,100, signals and roles ~300) | ~1,400 | no |
| output (JSON, rationale <= 3 sentences) | ~200 | -- |

- **Per candidate, `k = 1`**: 2,750 x 0.014 + 5,950 x 0.44 + 200 x 1.32 per million = **$0.0029**.
- **Each extra sample** (same prompt, fully cached): 8,700 x 0.014 + 200 x 1.32 per million = **$0.0004**. So
  `k = 5` is **$0.0045** with cache hits, and $0.0146 if the cache does not hit (the smoke run decides the default).
- **Embedding**: $0.000024 per candidate; the whole store about $0.10 once.
- **Per compile**: bootstrap 150 x $0.0029 = $0.44; proposals ~$0.01; scoring 600 x $0.0029 = $1.74; total
  **~$2.2, ceiling $3.00**.
- **Per full evaluation** of one program, evaluated families only (475 verified rows outside memory,
  config_secrets and unknown) plus a 200-unit benign-delta sample for false BLOCKs:
  - outer folds: 675 candidates, **$2.0 at k = 1, $3.0 at k = 5** (cached);
  - leave-one-source-out: 475 more, **$1.4 / $2.1**;
  - leave-one-framework-out: $0 today (no framework at the floor);
  - total **~$3.4 (k = 1) to $5.2 (k = 5)**, ceiling $7.
- **Learning curves** (section 7): 6 memory-size points + 3 source-count points on a fixed 200-candidate subset at
  `k = 1`: 9 x 200 x $0.0029 = **~$5.2**, ceiling $7.
- **A program-variant A/B** on 300 paired candidates: arm A replays cached responses from the evaluation ($0);
  arm B costs **$0.9 (k = 1) to $1.35 (k = 5)**.
- **Deployment**: `pre-push` with ~5 candidates is ~$0.02 per push at `k = 5`; a plane Run case with ~30 candidates
  ~$0.14.

**Against the balance.** DeepSeek was ~$19.6 before the harvest; the harvest's verify passes are ~$6 expected and
model roles up to their $10 ceiling, so **~$4-14 remains** depending on what the harvest actually spends (read the
provider balance after it ends; do not assume). Affordable now, as one go-ahead of **~$4.5-5.5 expected, $7 ceiling**:
the smoke run (20 candidates, ~$0.10, measures cache hits and real token counts), embedding the store (~$0.10,
OpenRouter, separate account), one compile (~$2.2), and the outer-fold evaluation at the cheaper confirmed `k`
(~$2-3). Leave-one-source-out, the learning curves, program A/Bs and exp-001 (~$7.7) together need **~$18-20 more**
and a top-up. No single run may start whose ceiling exceeds the balance read just before it.

### 5. Compiled program artifacts and versioning (Requirement 3.3)

A compiled program is one canonical JSON (sorted keys, floats with `repr`), a content-addressed blob
`programs/<sha256>.json`, with `programs/index.jsonl` (every version) and `programs/adopted.json` (profile -> sha;
a single overwritten object, versioned under MinIO, history in the index on FileStore). On MinIO the object is
tagged `kind=program` and `profile`.

```
{"program_id": "<sha256>", "kind": "llm-program", "schema_version": 1, "feature_set_digest": "...",
 "profile": "static" | "plane", "signature": {"digest": "...", "fields": [...]},
 "instruction": "<text>", "instruction_source": "baseline" | "proposed:<n>",
 "demos": [{"example_id", "excerpt_sha", "label", "family", "rationale", "alternate": "<example_id>"}],
 "retrieval": {"distance": "gower-v1", "n1": 40, "k": 6, "lam": 0.5, "balance": {...},
               "embedding_model": "openai/text-embedding-3-small", "near_duplicate_cos": 0.98,
               "excerpt": {"candidate_lines": 80, "candidate_chars": 4000, "example_lines": 40, "example_chars": 2000}},
 "classify": {"model": "deepseek-flash", "model_params_digest": "...", "k": 5, "temperature": [0.0, 0.7],
              "confidence": "vote_mean" | "verbal" | "logprob", "max_output_tokens": 300},
 "calibration": {"method": "platt-crossfit", "per_family": {...}, "check": {...}},
 "operating_points": {"<family>": {"block": {"threshold", "offered", "reason", "target_precision": 0.95},
                                   "advisory": {"threshold", "target_recall": 0.90}}},
 "priors": "off" | ["wordpress", ...], "roles": "off" | "deterministic" | "model",
 "data": {"memory_snapshot_digest", "label_set_digest", "compile_groups_digest", "sources": [...], "excluded": {...}},
 "compile": {"spec_sha256", "metric": "balanced_brier_v1", "configurations": [{"instruction", "demo_set", "score"}],
             "usd", "calls", "response_cache_digest", "replayed": true | false},
 "evaluation": {"folds_digest", "outer": {...}, "leave_one_source_out": {...}, "leave_one_framework_out": {...},
                "strata": {...}, "curves": "curves/<sha>.json"},
 "instruments": {"ruleset_digest", "engine_image", "runner_image", "verify_model", "prompt_digest", "roles_model"},
 "seed": 0, "code_commit": "<git sha>", "created": "<iso>"}
```

The memory itself is not in the artifact; `memory_snapshot_digest` pins which memory the evaluation used. A
decision made later with a different memory snapshot records its own digest.

**Adoption** stays a maintainer commit: `ousast learn adopt <program_id>` writes `programs/adopted.json` and exports
the artifact to `src/openultrasast/ruleset/decision/program-<profile>.json`. The packaged copy holds demonstrations
with third-party code excerpts: only demonstrations from repositories with a recorded permissive licence are
exported; others are replaced by their alternates or dropped, and the exported program is re-evaluated as its own
variant (the memory-size-0 configuration of section 7 if no store ships). A program whose priors or roles setting
differs from the incumbent is adopted only with a recorded A/B result (section 6).

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
- *Engine-level experiments* compare **compiled program variants**: priors on/off, roles, `k` in {1, 3, 5}, the
  confidence source (vote mean, verbal, logprob), `lam` in {0, 0.5}, `k_ret`, comments kept vs stripped in
  excerpts, two instructions, two memory snapshots (Req 3.6: the effect of new labels), or a different chat model.
  They are no longer free. The arms are two programs run on the same candidates in the same outer folds (paired),
  the unit is the candidate and the resampling cluster the repository. Arm A replays the incumbent's cached
  responses from its evaluation ($0); arm B is paid: about $0.9-1.35 per 300 paired candidates (section 4.6), with
  the arm's ceiling in the manifest's `budget_usd`. The metric is recall at BLOCK (or at ADVISORY where BLOCK is
  not offered), plus false BLOCKs per 100 benign deltas; the balanced Brier score is secondary. A variant that only
  changes compile-time choices is compiled on the same compile split with the same seed, so the two arms differ in
  exactly the declared setting. Because model calls are stochastic, each arm records its response-cache digest; a
  re-analysis replays both arms at $0.

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

**Learning curves over memory size (5.1).** `ousast learn curve --profile P` varies what the program may
retrieve, not what it was compiled with (the compiled instruction and demonstrations stay fixed, so the curve
measures memory):

- *By memory size*: the eligible memory restricted to a random share of its repository groups, 0%, 25%, 50% and
  100%, with two seeded draws at 25% and 50% (6 points). 0% is the program with its demonstrations only, which is
  also the configuration a user without a store gets (section 5).
- *By sources*: memory restricted to 1, 2 and all of the label sources (pairs, populations, adjudications), 3
  points.
- Every point is evaluated on the same fixed, stratified 200-candidate subset of the outer folds, at `k = 1`, with
  the boundary filter applied (about $5.2 for all 9 points, ceiling $7; section 4.6).

Per point: recall at ADVISORY, recall at BLOCK (where offered), PR-AUC, balanced Brier score, false BLOCKs per 100
benign deltas, and the share of `unsure`, per family where the family has the floor. Bands are the 2.5/97.5%
quantiles over the draws x a repository-cluster bootstrap. An inverse power law `m(n) = a - b * n^-c` in the
number of memory groups is fit to each curve; a projection to 1.5x and 2x the memory is reported only as a band,
and only where the bootstrap CI for `c` excludes 0. A flat curve is a finding: it says memory does not help that
family and the demonstrations carry the result.

**Expected detection on unseen code (5.2).** Per family and per language (and per framework, Req 8.3): the
outer-fold and leave-one-source-out intervals at both operating points, with priors off and with adopted priors.
A stratum with fewer than 10 positive repositories or 10 negative repositories, or whose 95% interval on recall is
wider than 0.5, is printed as **"insufficient data (n repositories)"**, with no number. Today that applies to
memory, prototype, PHP untrusted_destination, and every plane-profile family until the harvest Run.

**The v3 check (5.3), exactly once.**

1. *Before.* The engine and every operating point are adopted, and population v3 is still reserved and unread by
   this spec's code (it is absent from `learn/sources.toml`). `ousast learn predict --population-name
   population-v3-php` writes `benchmarks/independent/prediction-v3.json` and it is committed:
   - the adopted program id per profile, its `memory_snapshot_digest` and the chat and embedding model ids;
   - `feature_set_digest`, priors and roles settings;
   - the operating points;
   - the frozen analyzer source hash (`benchmarks/push/freeze_source.sh`);
   - for each family v3 may contain, the predicted recall and precision intervals from the PHP stratum where
     sufficient, else the pooled-language interval with the label "no PHP stratum";
   - the predicted false BLOCKs per 100 benign deltas;
   - the reference to `protocol-v3.md`, written by the population's owner, not by this spec.

   Only the population's name is needed; its file is not opened.
2. *Run.* v3 is scored under protocol v3, once, by its owner's runner, with the engine's decisions added to the
   recorded outputs. The engine's spend on v3 is a model cost (about $0.0045 per candidate at `k = 5`); its
   ceiling is fixed in `prediction-v3.json` from the candidate count the owner reports, never by opening v3 files
   from this spec's code, and needs the maintainer's go-ahead.
3. *After.* `benchmarks/independent/result-v3-engine.json` holds, per family, the measured point and interval
   beside the predicted interval, `inside | outside`, the calibration check on v3, and the reach misses. v3 is
   then added to `learn/sources.toml` as spent, and its cases may enter memory. Its numbers never again
   qualify anything.

### 8. Integration (Requirements 6, 7.3, 7.5)

**Lookup.** The compiled program comes from, in order:

1. `[decision] program` in the config (a path);
2. the store's `programs/adopted.json` when `OUSAST_MEMORY` is set (with the store's memory for retrieval);
3. the packaged `ruleset/decision/program-<profile>.json` (demonstrations only, no retrieval memory unless a store is
   configured; its own calibration, section 5);
4. none.

The program also needs a chat Model: `[models]` with a DeepSeek key on the host, the bound Model in a plane Run.
Embeddings are optional: without an OpenRouter key retrieval runs `signals_only` and says so.
`learn/decide.py`: `load_program(...) -> Program` and `decide_all(records, excerpts, program, memory, client,
embedder, budget) -> list[Decision(p, operating_point, program_id, verdict, rationale, cited_lines, signals,
neighbours, retrieval, offered)]`, all calls through `MeteredClient`.

**`ousast scan`.** A `decide` stage runs after the findings are complete and before `findings.json` is written
(`cli.py:517-520`). It builds `static` records with `build_for_scan` from the quick findings, the engine result,
`analyze_entry_points` and the `repo-facts` functions (source-only), plus deterministic roles. It scores each
candidate and attaches `decision` to the finding: `{p, operating_point: block|advisory|drop, program_id, verdict,
rationale, cited_lines, signals, offered}`. Candidates at or above ADVISORY are reported. Dropped ones go to
`dropped_by_engine.json`, beside `shadow_findings.json`. Shadow-status findings enter as candidates too, so a rule's
enabled/shadow status changes the report only if the decision changes (Req 6.3). The shadow split at
`cli.py:503-508` applies only in the fallback. `--fail-on blocked` is a new choice (exit 1 on any BLOCK), and
`findings` keeps its meaning. Markdown, SARIF (`properties.decision`) and `manifest.json` (`decision: {program_id,
usd, fallback, reason}`) carry the fields.

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
  `{p, operating_point, program_id, verdict, rationale, cited_lines}` in the artifact and one line in the compact report
  (`render_report`, `push/report.py:214`).
- The 30 s default deadline (`cli.py`, `--deadline 30.0`) covers feature building and `decide`. Everything in the
  `static` profile is source-only or already computed by the scan. Model roles run only with `--model-config`.
  `decide` issues candidates and their `k` samples concurrently (at most 8 requests in flight); a candidate not
  decided by the deadline is reported `undecided: deadline` and listed as ADVISORY-unscored, never dropped and never
  blocked. A push's decide budget defaults to `{usd: 0.10, calls: 120}`.

**Plane Runs.** The `embed` and `decide` tasks (Model-bound, section 4.1) write `embeddings.jsonl` and
`decisions.jsonl`; the host seeds `decide` with the adopted program and the case's boundary-filtered memory;
`remember` stores `decision` rows, and `ousast plane status` prints BLOCK/ADVISORY counts per case.

**Fallback (6.2).** With no adopted program, no chat Model or key, an exhausted budget, or a family below the
floor, today's behaviour applies unchanged: rule
statuses, quick/engine findings as they are, pre-push with the empty capability registry. The report says so in
one line: "decision engine: not used (no adopted program | no model key | budget exhausted | family insufficient data |
calibration failed) --
findings are today's rule output". A family whose BLOCK is not offered still gets ADVISORY decisions.

**User adaptation (7.5)** is opt-in: `[decision] adapt = true`. It keeps the user's dismissals in
`.openultrasast/decisions/dismissals.jsonl` in their repository, as finding fingerprints with the program id and the
excerpt sha. Dismissed fingerprints are suppressed after the engine, and, with at least 10 dismissals, they enter a
**user-local memory** (examples labelled `not_vulnerable`, `origin: user`) that `Retrieve` reads for that repository
only, beside the corpus memory. It never writes to the memory store; the label builder and the example builder
refuse any row with `origin: user`. It is evaluated separately: on held-out repositories, by replaying the first half
of their labels as dismissals and measuring the second half, and reported as "adaptation", never merged into the
generalisation numbers.

## Data Models

- `features` row: envelope (`id, kind, repo, pin, run, task, population, split, image`) + `{candidate, family,
  language, profile, schema_version, feature_set_digest, unit, base?, x, instruments}`.
- `label` row: envelope + `{candidate, family, label, source, source_ref, unit, direction?, weight, split, group,
  frameworks, created, evidence}`. Written only by `ousast learn labels`.
- `example` row: envelope + `{candidate, family, language, profile, label, source, group, frameworks, unit, x,
  instruments, roles, excerpt_sha, label_set_digest}`. Written only by `ousast learn memory build`; refuses
  `origin: user` and any source not in `sources.toml`.
- `decision` row: envelope + `{candidate, family, profile, program_id, memory_snapshot_digest, p, raw_score,
  operating_point, offered, verdict, votes, rationale, cited_lines, signals, neighbours: {label: n, family: n},
  retrieval: "signals+embeddings" | "signals_only", parse_failed, usd, calls}`.
- `experiment` row: `{experiment, manifest_sha256, units_sha256, registered, code_commit}`. `arm_outcome` row:
  `{experiment, arm, unit, outcome, passes, usd, response_cache_digest}`. `experiment_result` row: `{experiment,
  look, estimate, ci, mcnemar_p, decision, spend}`.
- `KINDS` (`plane/memory.py:55-58`) already holds `features, label, decision, experiment, arm_outcome,
  experiment_result` (task 1) and gains `example`. `TAG_FIELDS` is unchanged (`family` is already a tag).
- Blobs: `programs/<sha>.json`, `programs/index.jsonl`, `programs/adopted.json`, `excerpts/<sha>.txt`,
  `embeddings/<model-slug>/<sha>.json`, `responses/<sha>.json`, `curves/<sha>.json`, `labels/<sha>.jsonl`.
- Models: `plane/models/openrouter-embedding.yaml` (provider extension `openrouter`, egress `openrouter.ai`,
  `secretKey` OPENROUTER_API_KEY, `parameters.input_per_m: 0.02`, cache and output rates 0).
- Files: `learn/sources.toml`, `learn/compile.toml`, `ruleset/frameworks.toml`, `ruleset/decision/program-*.json`,
  `plane/experiments/<id>.yaml` + `.units.jsonl`, `benchmarks/experiments/<id>/result.json`,
  `benchmarks/independent/prediction-v3.json`, `result-v3-engine.json`.

## Error Handling

- Every failure of the feature builder is loud. An instrument that did not read its input records `state:
  failed`, and a Run's `features` task fails when every instrument failed for a case. A plausible all-zero record
  is impossible because zero requires `state: ran`.
- `validate_record` rejects unknown features, out-of-vocabulary enums and label fields, naming the feature and the
  source file. The prompt renderer refuses a record that did not pass it.
- The label builder exits 2 on a source that is not in `sources.toml`, a population whose status is not recorded,
  or a group that straddles an outer fold after the merges. The error names the repository.
- The example builder fails a candidate whose excerpt is empty or whose function span is not found (it never
  stores an empty excerpt as an example), and reports the count per source; `memory build` exits 2 if more than 10%
  of a source's labels have no excerpt (an unread clone is not a small memory).
- Compile and evaluation refuse a family below the floor and write an "insufficient data" stub, so `decide` can say
  why. They assert before every call that no rendered example or demonstration is outside the boundary (section
  4.2), and before a compile that the compile split and the evaluation folds share no group.
- A model answer that does not parse is retried once, then recorded `unsure, parse_failed`. A run where more than 5%
  of answers are `parse_failed` is reported as an instrument failure, not as a result.
- A smoke check precedes every paid run: 3 candidates, the provider's `usage` present and non-zero, the reply
  parsed, the embedding dimension as declared. A run whose first calls report zero tokens stops (memory note
  "Model calling was broken 2026-09": a working-looking zero).
- `BudgetExhausted` ends a compile or evaluation `unfinished` with no artifact and no number; `AccountError` ends it
  `failed` (`plane/budget.py:22-38`).
- `decide` with a program whose `schema_version`, `feature_set_digest` or signature digest differs from the
  builder's falls back, with the reason in the report, and never renders a mismatched record.
- Experiments: a registration mismatch refuses the Run. A budget ceiling ends an arm `unfinished` (`budget.py`),
  and the analysis then reports "incomplete: arm B stopped at $x" and records no decision.
- `put_blob` on FileStore applies the 1 GiB free-space refusal (`plane/memory.py:347`).

## Testing Strategy

No test makes a model or embedding call: the chat and embedding clients are scripted fakes (the
`tool_hunter.ChatClient` protocol, `index.EmbeddingClient` at `index.py:56`) that record what was asked.

- `tests/test_learn_schema.py`: allow-list, name invariance, label fields excluded, missing vs zero (section 1).
- `tests/test_learn_labels.py`, on fixture populations and pairs (done, task 4):
  - positives and negatives per rule, including a fixed-pin function the fix did not touch (not a negative), and
    an unmatched vulnerable-pin candidate (unlabelled);
  - `unscorable` and title-tier exclusion;
  - an adjudication mapping;
  - a source not in `sources.toml`, which cannot label, checked with a fixture population named like v3 and a test
    that asserts the builder never opens its file (`open` monkeypatched);
  - CVE-based group merge.
- `tests/test_learn_excerpt.py`: bounds (lines, characters), centring on changed lines, no path or repository in
  the excerpt, advisory ids and security wording in comments redacted, delta diff rendering.
- `tests/test_learn_retrieve.py`:
  - Gower distance on hand-computed fixtures: both `ran`, state mismatch = 1, same non-`ran` state = 0, null in one
    = 1, prior features dropped with `priors = off`;
  - re-rank with `lam` in {0, 0.5}, `signals_only` without embeddings;
  - the balance rule (label, family and per-repository caps; `short` recorded);
  - `test_boundary`: for outer, leave-one-source-out and leave-one-framework-out fixture folds, every rendered
    example and demonstration is eligible; `memory.seed` writes no example of the case's group; the near-duplicate
    drop in evaluation only; the deployment self-exclusion.
- `tests/test_learn_program.py`: the rendered prompt contains no `EXCLUDED_FIELDS` name or label value; the shared
  prefix is byte-identical across candidates; parsing (valid, invalid -> one retry -> `unsure, parse_failed`;
  cited line out of range); majority and score `s`; `unsure` cannot BLOCK; `MeteredClient` receives `temperature`
  and stops at its ceiling; the response cache key and replay.
- `tests/test_learn_compile.py`: bootstrap keeps only correct, confident, identity-free rationales; instruction
  candidates scored by the balanced Brier metric with ties to fewer tokens; compile split disjoint from evaluation
  folds; `test_reproducible_from_cache` (byte-identical artifact on FileStore, and on MinioStore gated as today);
  ceiling -> `unfinished`, no artifact.
- `tests/test_learn_folds.py`: no group in both an evaluation fold and the compile split or retrieval pool, for
  outer, leave-one-source-out and leave-one-framework-out folds; determinism by seed.
- `tests/test_learn_calibrate.py`: Platt on a known miscalibration, cross-fitting (fold j's map never saw fold j),
  the slope/intercept/ECE check, and the ADVISORY-only downgrade.
- `tests/test_learn_decide.py`: operating points from cross-fitted predictions, explanation fields (signals named in
  the rationale but absent from the record are dropped), version-mismatch fallback, deadline -> `undecided`.
- `tests/test_learn_experiments.py`:
  - registration digest and refusal;
  - paired bootstrap CI on a fixture with a known difference;
  - exact McNemar values against hand-computed binomials;
  - O'Brien-Fleming boundaries;
  - adopt / reject / inconclusive / equivalent decisions;
  - a program-variant experiment whose arm A replays cached responses at $0.
- `tests/test_semantic_priors.py` (done, task 2): the lint test, `priors="off"` removes exactly the tagged entries,
  the split entries keep their language-level calls.
- `tests/test_learn_roles.py` (done, task 3): wrapper inference to depth 3 on a fixture, and unclassified chunks are
  never "no roles".
- `tests/test_plane_features.py`, `test_plane_embed.py`, `test_plane_decide.py`: fixture run directories from the
  validation-46 shapes. `features` drops `site_match`/`in_fix_range`; `embed` and `decide` meter, honour budgets and
  exit 0/2/3; `remember` stores `features`/`decision` rows.
- `tests/test_push_decision.py`: admission with an engine replaces only the capability reasons, and every
  structural reason still blocks admission. `PushReport` invariants hold with engine templates.
- `tests/test_scan_decision.py`: the scan fallback line (no program, no key, budget), `dropped_by_engine.json`, and
  that a shadow/enabled status flip without a decision change leaves the report unchanged.
- Regression net: the existing gate, pair and plane tests. `test_benchmark_output_is_byte_identical_to_golden_baseline`
  holds with no program adopted (the fallback is today's path).
- Joern-gated tests run only with the mount recipe (memory note "Joern-gated tests run nowhere"). The engine-alert
  harvest is verified by its own read-count check, not assumed.

## Requirement Traceability

| Requirement | Design section | Verified by |
| --- | --- | --- |
| 1.1 one record per candidate from every instrument | 1 | `test_plane_features.py`, `test_learn_schema.py` |
| 1.2 missing is not negative | 1 (instrument state, `null`), 4.2 (distance) | `test_missing_is_not_zero`; `test_learn_retrieve.py` |
| 1.3 versions and digests for rebuild | 1 (versioning), 5 | `test_learn_compile.py::test_reproducible_from_cache` |
| 2.1 positives/negatives by source | 3 | `test_learn_labels.py` |
| 2.2 plane verdict is a feature, not a label | 1, 3 | `test_label_fields_never_reach_features`; label rules |
| 2.3 provenance; reserved populations unusable | 3 (`sources.toml`, fail-closed) | `test_learn_labels.py` (v3-named fixture never opened) |
| 3.1 declared LM program on the metered client; no statistical model | 4.1 | `test_learn_program.py`, `test_plane_decide.py` |
| 3.2 retrieval by signals re-ranked by code embeddings; no identities | 4.2 | `test_learn_retrieve.py`, `test_learn_excerpt.py` |
| 3.3 compiled on training folds; versioned; reproducible | 4.3, 5 | `test_learn_compile.py` |
| 3.4 retrieval never crosses the evaluation boundary | 4.2 (boundary), 4.4 | `test_learn_retrieve.py::test_boundary`, `test_learn_folds.py`, pre-call assertion |
| 3.5 confidence calibrated on held-out repositories; else ADVISORY only | 4.4 | `test_learn_calibrate.py` |
| 3.6 new labels improve via memory, measured by A/B | 4.2, 6 | memory-snapshot experiment; `memory_snapshot_digest` on decisions |
| 4.1 pre-registered experiment | 6 (manifest, register) | `test_learn_experiments.py` |
| 4.2 paired, assignment and spend recorded | 6 | `arm_outcome` rows; `ousast plane status` |
| 4.3 adopt only on a CI excluding zero or equivalence | 6 (decision rule) | `test_learn_experiments.py` |
| 4.4 known-callers experiment first | 6 (exp-001) | task 7 record |
| 5.1 learning curves over memory size and sources, with bands | 7 | `ousast learn curve` output; unit test on a fixture |
| 5.2 intervals per family and language; insufficient data | 7 | `test_learn_decide.py` (floor), report fixture |
| 5.3 v3 checked once, after freezing | 7 | `prediction-v3.json` committed before `result-v3-engine.json` |
| 6.1 probability, operating point, contributing evidence in reports | 4.5, 8 | `test_scan_decision.py`, `test_push_decision.py`, `test_plane_decide.py` |
| 6.2 fallback said in report | 8 | `test_scan_decision.py` |
| 6.3 rule status no longer changes output alone | 8 | status-flip test |
| 7.1 repository-grouped folds across corpora | 3 (group, CVE merge), 4.4 | `test_learn_folds.py` |
| 7.2 repository-agnostic allow-list with test | 1, 4.2 (excerpt rules) | `test_learn_schema.py`, `test_learn_excerpt.py` |
| 7.3 BLOCK/ADVISORY on unseen repositories; delta unit | 1 (delta), 4.5, 8 | outer-fold report; `test_push_decision.py` |
| 7.4 calibration checked out of repository; else ADVISORY only | 4.4 | `test_learn_calibrate.py` |
| 7.5 opt-in adaptation outside the numbers | 8 | builders refuse `origin: user`; separate report |
| 8.1 language-level knowledge; roles inferred | 2 | `test_learn_roles.py` |
| 8.2 tagged priors, off by default, kept by A/B | 2, 6 | `test_semantic_priors.py`; program-variant experiment records |
| 8.3 leave-one-framework-out, per framework | 2, 4.4 | `test_learn_folds.py`; report strata |
| 8.4 share depending on priors | 2, 7 | report columns priors off / adopted / difference |

## Commit sequence, mapped to future tasks

Each commit is gated on the full suite's own exit code, `ruff` and `mypy`. None changes a reported number until
commit 9 adopts a program, and without an adopted program every path is today's. Steps that spend model money
start only after the maintainer confirms their budget against the balance read just before.

1. **Schema and features** (1.1-1.3, 7.2) -- done.
2. **Framework tags** (8.2, 8.4) -- done.
3. **Roles** (8.1) -- done.
4. **Labels** (2.1-2.3, 7.1) -- done.
5. **Harvest** (1.1, data) -- in progress: verify a/b on the verify-family pairs and the development cases (about
   $6, ceiling $10), model roles on the candidate files (ceiling $10), engine features on the host.
6. **Program, memory, compile, first evaluation** (3.1-3.6, 5.1-5.2, 7.3-7.4, 8.3): excerpts and the example
   store, metered embeddings and the cache, retrieval with the boundary test, the program and response cache, folds,
   compile, cross-fitted calibration; then the paid slice (smoke, embed, compile, outer evaluation, ~$5, ceiling $7)
   and, after a second go-ahead, leave-one-source-out and the memory-size curves (~$7, ceiling $10), committed under
   `benchmarks/measurements/<date>-decision-engine-v1/`.
7. **Experiments** (4.1-4.4): `learn/experiments.py`, `register`, `experiment-outcome`, the Run annotation checks,
   `OUSAST_VERIFY_CALLERS`, exp-001 registered, run and recorded, and the program-variant experiment machinery.
8. **Integration** (6.1-6.3, 7.3, 7.5): the `embed` and `decide` tasks with the seeded memory, the `scan` stage,
   `pre-push` admission with the engine, report fields, the fallback line, and the opt-in adaptation layer.
9. **Adopt** (3.3, 8.2): `ousast learn adopt`, the packaged program with the licence filter, the priors-on/off and
   `k` experiments with recorded decisions.
10. **v3 check** (5.3): `prediction-v3.json` is committed first, then v3 is run by its owner under protocol v3, and
    `result-v3-engine.json` is committed. Nothing between the two commits may touch the program, memory snapshot,
    features, priors or thresholds.

## Risks

- **Label scarcity decides what can be evaluated.** The status of each family today:
  - memory (5 repository groups, 173/173 rows, almost all openssl and curl), config_secrets (5) and prototype are
    **insufficient data** (`labels.json` `verified_pin_labels`). Users get today's behaviour there, labelled as
    such, and no money is spent evaluating them.
  - PHP has no pairs and 13 positive population groups. The v3 prediction will mostly be the pooled interval,
    marked "no PHP stratum", and it will be wide.
  - The plane profile has 43 rows from one population until the harvest Run.
  - BLOCK at 95% precision is likely **not reachable** for most families on this data. The design reports "BLOCK
    not offered" instead of lowering the target.
- **Weak signals, strong code.** The pair baseline has quick-rule labelled recall 0.24 and Youden -0.013 overall
  (`pairs.json` `overall`); the v2 engine recall is 0/17 (`results-v2.json`). The program reads the code, so it
  can beat the signals, but the verify history says the model over-flags (v1 1/12, v2 0/17 adjudicated true). A
  calibrated classifier that mostly says "advisory" is honest; recall at ADVISORY 0.90 may need a threshold with
  poor precision. That is reported, not tuned away on outer folds.
- **LLM nondeterminism.** The same prompt can answer differently, and temperature 0 is not a provider guarantee.
  Guards: every response cached and replayable (numbers reproduce at $0); sample 1 at temperature 0; the vote mean
  over `k` samples as the score; the A/B unit is paired and both arms' caches are recorded; a re-ask agreement rate
  on a fixed 30-candidate canary set is reported with each evaluation.
- **Label leakage into prompts.**
  - Through rationales: memory examples carry no rationale; demonstration rationales are produced without the label
    and scanned for identities and advisory ids; the candidate's prompt never holds `EXCLUDED_FIELDS` (test).
  - Through code: fixed-side excerpts can carry fix comments ("prevent XSS", a CVE id). Advisory ids and security
    wording in comments are redacted; a comments-stripped arm measures what remains. Delta excerpts show the diff of
    the change under test, never the later fix.
  - Through memorisation: the chat model may have seen public CVE fixes in pre-training. Not removable; the v3
    check (unpublished fixes are rarer there) and per-source numbers expose it, and the report names it.
- **Retrieval leakage.** Same repository under another name or corpus: group normalisation, CVE merge, the
  near-duplicate drop at cosine >= 0.98 in evaluation, and `test_boundary`. Demonstrations from the compile split
  are, by construction, from repositories never evaluated. The seed for plane Runs filters on the host, where the
  labels are; the sandbox never receives an example of its own case's group.
- **Label-tracking signals (maintainer decision 2026-10-01: "Neutralise both for v1").** The harvest found two
  signals that follow the pair label instead of the code: verify candidates on fixed sides named functions the side
  no longer declares (now never produced: a side's candidates are only the functions it declares, the rest counted
  `absent_on_side`), and the engine's "read the file, asked no question" state, which a fixed side reaches by losing
  its sink. The v1 program withholds the engine instrument entirely -- state and values -- from prompts,
  demonstrations, the instruction proposer and the retrieval distance (input profile `v1`, `ProgramSpec.inputs`);
  the stored record keeps it. The engine returns only through a pre-registered A/B evaluated on assumed-benign and
  benign-control negatives, where it cannot track a fix. `ousast learn audit-leaks` reports how well every signal
  alone separates the sides of a pair and flags any above 0.20 (counts under `benchmarks/measurements/`).
- **Earlier leakage paths still apply.** Hand rules and framework priors written after seeing a training repository
  (the `$wpdb` rule from PMPro, the hook source from WP Statistics, `taint.sc:911-949`): priors off by default,
  leave-one-framework-out, best-effort `taught_by = [repo]`. The mechanism exporter's train-on-test leak
  (`closed-loop-train-on-test-leak.md`): no exporter output is a feature. Verify and tie-break fitted on v2: the v2
  fold is design-informed. Thresholds and instructions chosen on reported folds: cross-fitting and the compile
  split. v3: fail-closed sources, never opened. User dismissals: refused by both builders.
- **Cost.** Model spend is now per candidate and per evaluation, not one-off. Measured (section 4.6) the first
  slice fits today's balance; everything after it needs a top-up. Guards: `MeteredClient` ceilings on every task
  and command, a smoke check that measures real tokens and cache hits before any paid run, cached replay for
  re-analysis, unevaluable families skipped, `k = 1` if the prefix cache does not hit. Deployment cost (~$0.02 per
  push) is a user-facing change: `pre-push` without a key falls back, and the report states the spend.
- **Model and version drift.** `deepseek-flash` is an alias whose weights can change, and so can OpenRouter's
  embedding route. The artifact records model ids, the Model parameters digest and the response `model` field;
  before adoption and before the v3 prediction the canary set is re-asked, and agreement below 0.9 with the
  cached answers, or an embedding dimension change, invalidates the evaluation (re-embed, re-evaluate) rather than
  being averaged in. Prices are data in the Model manifest; a price change changes only cost reports.
- **Latency.** A model call per candidate is slower than a dot product. The 30 s `pre-push` deadline is met by
  concurrency and the `undecided: deadline` state; a push with many candidates gets partial decisions, stated.
- **Packaging third-party code.** Demonstrations and memory hold excerpts of corpus repositories. Only
  permissively licensed excerpts may ship in the package; the store is never shipped. A user without a store gets
  the demonstrations-only program, whose own curve point (memory 0%) and calibration are what they are told.
- **Framework inference is itself a model.** Model roles cost money and can be wrong. `scan` without `[models]`
  gets only wrapper inference, whose reach on framework-heavy code without dependency source is poor. The report
  says which role source ran. Both are measured by the roles-on/off experiment. Nothing assumes they help.
- **Host time on the 7 GB host.** Engine features remain the time cost (7-14 hours serial for the pair corpus,
  dev-php scans of 200-2,000 s each), run once per engine image from a frozen source export, one container at
  `--memory 3g` at a time, never beside the kind cluster's verify pods, cached by (content sha, image id). Model
  calls add wall time but no memory pressure; excerpts and embeddings are small (~8 KB per example with a 1,536-float
  vector, ~45 MB for 5,600 examples).
- **Experiments will often be inconclusive.** With 41 development repositories the MDE is about 15 points.
  Pre-registering that and recording "inconclusive" is the intended behaviour. The failure mode to avoid is
  extending an experiment after looking.

- **First paid slice, 2026-10-01 (tasks 6.2, 6.6; injection only).** Four instrument defects surfaced before any
  number was believed, each fixed with a test:
  - *The memory build joined no pair.* The harvest stores a pair side's record under its unit pin (the blob sha1 of
    the side's excerpt), not under `label_pin`; `ousast learn memory build --units <harvest units.json>` joins them.
    And a candidate's `static` and `plane` records share a key, so reading both let one overwrite the other and
    silently drop about half the examples; the build now reads its own profile only. 85 -> 724 examples.
  - *Contrast was unbounded.* The balance rule padded a short pick with other families (up to 5 of 6), and stage 1
    took the 40 nearest of all families, so a minority family often never reached stage 2. Now stage 1 takes the
    `n1` nearest of the candidate's family and the `n1` nearest others, and at most 2 contrast examples are shown
    whenever the pool holds the family (maintainer: "allow 2 contrast"); never padded.
  - *Proposed instructions dropped the answer contract*, and DeepSeek's JSON mode refuses a prompt without the word
    "json" (HTTP 400, the first compile stopped there). The contract (`ANSWER_FORMAT`) is now part of the signature
    and appended to any instruction that lacks it; the baseline prefix is byte-identical.
  - The adjudication source fails the 10% excerpt gate: 9 of its 43 candidates are anonymous functions (`<lambda>N`,
    `<module>`) that `function_span` cannot find by name; the clones were read. Open.
  The memory is small: 724 static examples (only harvested candidates have feature records; the 97 advisory-fix pairs
  have none yet), injection 140 (75/65), so `C_val` had 13 injection candidates and the compile metric is noisy.
  The measured ranking signal is real but weak at the recall target: AUC 0.74 out of repository, ADVISORY at recall
  0.90 has precision 0.54 (prevalence 0.53); the majority `vulnerable` verdict alone has precision 0.86, recall 0.43.
  Canary re-ask agreement at temperature 0 was 0.83, below the 0.9 the adoption check requires.

## Maintainer decisions at design approval (2026-09-30)

- Design approved as written.
- Benign pushes: ordinary non-security commits are mined as **assumed-benign** pushes (no security keyword, no later
  fix touching the same lines), kept as their own label source (`assumed_benign`), reported separately from the
  verified negatives, and never merged with them.

## Maintainer decisions for the Requirement 3 change (2026-10-01)

- The decision engine is an AI classifier with local memory, not ML: "We will not be able to scale up data" and
  "we need to have the decision engine on AI classifier not ML. with local memory, dspy style".
- DSPy-style **in-house** (signature, modules, bootstrap few-shot, instruction search on the plane's metered
  client), not the DSPy library.
- Retrieval by **signals + code embeddings**: signal-profile nearest neighbours re-ranked by OpenRouter code
  embeddings. DeepSeek is the LLM; OpenRouter is used for embeddings only.

Open for the maintainer at design approval:

- The first paid slice of task 6 (smoke, embed, one compile, outer evaluation): ~$5 expected, $7 ceiling, against
  the balance read after the harvest.
- The second slice (leave-one-source-out, memory-size curves): ~$7, ceiling $10, and the top-up it needs.
- Which corpus licences allow demonstrations to ship in the package (section 5).


- 2026-10-01: revised design approved; packaged demonstrations limited to permissive licences (MIT, BSD, Apache-2.0,
  ISC, zlib); copyleft and unknown-licence code is used for evaluation and local memory only, never packaged.
