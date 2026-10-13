# Semgrep CE as a third arm on the valid pilot (2026-10-13)

The question from `../2026-10-13-semgrep-brief/BRIEF.md` (option C): does Semgrep, running our own
rules and facts, catch more on the valid pilot than our engine does? It does not. It caught none of the
12 positives and raised false alarms on 12.6 of every 100 ordinary pushes.

Instrument: semgrep 1.179.0 CE (linuxbrew), `-j 1`, `--timeout 60 --max-memory 1500`, offline flags.
Rules: `rules/` here (81 rules, from `python -m benchmarks.valid.semgrep_arm rules`). Records:
`~/ousast-results/valid/pilot/semgrep/` (252 records, outside the repo). Same frozen manifest
(`benchmarks/valid/pilot/pool-valid.toml`, slice 1) and same scorer as the other arms.

## Headline

| Arm | Recall (12 positives) | False alarms per 100 pushes (Wilson 95%) | Precision |
|---|---|---|---|
| (a) hook as shipped, 163 done | 0/12, 0.0% (0.0-24.3) | 0.7 (0.1-3.7), n=149 | 0.0% (0/1) |
| (b) hunter, raw | 6/12, 50.0% (25.4-74.6) | 92.5 (88.4-95.2), n=239 | 2.6% |
| (b') hunter, classifier-filtered | 5/12, 41.7% (19.3-68.0) | 54.4 | 3.6% |
| **(c) Semgrep, our rules + facts** | **0/12, 0.0% (0.0-24.3)** | **12.6 (8.9-17.4), n=239**; cluster 3.8-23.4, ICC 0.28 | **0.0% (0/33)** |

`metrics_semgrep.json`: "recall 0.0% (Wilson 0.0-24.3), false alarms 12.6 per 100 pushes, precision
0.0%; exploit-verified 0 of 5 (5 not yet proved)". Exploit-verified is not applicable: the 5 flagged
positives are all wrong-family hits, none was a catch.

The (c) false-alarm rate is not like-for-like with (a). The hook keeps a quick hit only on a changed
line or inside a changed function (`push/quick.py:122-130`); this arm counts every result anywhere in a
changed file, as the run instructions asked. Restricting the same records afterwards to results on a
changed line gives 5/239 = 2.1 per 100 (Wilson 0.9-4.8); within 10 lines of a change, 9/239 = 3.8
(2.0-7.0). Scoped either way it is still a higher rate than (a), and recall stays at zero.

## Per positive

| Repo | Family | (a) hook | (b) raw | (c) Semgrep | What Semgrep reported |
|---|---|---|---|---|---|
| bytebase/dbhub | access_control | miss | miss | miss | `js-command-exec` at `sql-parser.ts:87`: `dollarQuoteOpenRegex.exec(...)`, a RegExp call |
| contentful/contentful-mcp-server | untrusted_destination | miss | miss | miss | nothing |
| fastapi-users/fastapi-users | access_control | miss | miss | miss | nothing |
| i18next/i18next-http-middleware | output_encoding | miss | hit | miss | nothing |
| imzbf/md-editor-v3 | output_encoding | miss | hit | miss | `js-command-exec` at `code/index.ts:37`: `re.exec(info)`, a RegExp call |
| jupyter-lsp/jupyterlab-lsp | path | miss | hit | miss | nothing |
| matrix-org/matrix-appservice-bridge | access_control | miss | miss | miss | nothing |
| nvbn/thefuck | path | miss | hit | miss | nothing |
| ondata/ckan-mcp-server | untrusted_destination | miss | hit | miss | nothing |
| webpack/webpack-bundle-analyzer | output_encoding | miss | miss | miss | nothing |
| zenitram/malla | output_encoding | miss | hit | miss | nothing |
| zereight/gitlab-mcp | path | miss | miss | miss | `js-command-exec` + taint `sink:javascript:exec` at `index.ts:12429`: `/^Bearer.../i.exec(authHeader)` |

No rule origin caught anything. Why the positives are silent: three are access_control, which only the
obligations express, and none of those convert. The four output_encoding positives are a value reaching
`innerHTML` from a function argument or a markdown renderer, and the taint rules' sources are request
objects (`req.query`, `request.args`). The intra-function CE taint never sees an argument as a source.
The path and destination positives take their input from tool arguments or archive members, which are
also not modelled sources. Our hook misses these 12 for the same reason. Swapping the engine does not
change the vocabulary.

## False alarms (239 ordinary pushes, 30 flagged)

Pushes flagged, by rule origin: `js-command-exec` 16, `python-sql-injection` 8, `sink:javascript:exec`
8, `python-unsafe-eval` 3, `sink:javascript:html.response` 2, `python-os-command` 1,
`sink:javascript:prototype.merge` 1. The results are 95 in total: 90 injection, 3 prototype, 2
output_encoding. Only 18 carry a taint trace; the other 77 are regex.

The flags come from five repos: malla 10, gitlab-mcp 10, webpack-bundle-analyzer 4, dbhub 3,
matrix-appservice-bridge 2, thefuck 1. An ICC of 0.28 means a handful of files drive the rate. What the
lines are:

- `js-command-exec` (`\b(exec|execSync)\s*\(`) and the taint sink `$OBJ.exec(...)` match `RegExp.exec`.
  In gitlab-mcp the request header is a taint source, so `/regex/.exec(authHeader)` reads as command
  injection with a dataflow trace. The rest are `childProcess.execSync` in test files.
- `python-sql-injection` matches multi-line `cursor.execute(` calls built from f-strings or constants in
  malla's repositories. The regex cannot tell a constant from input.
- `python-unsafe-eval` matched `eval()` inside a comment. The quick engine drops matches in comments;
  `pattern-regex` does not (see "not carried" below).
- `sink:javascript:prototype.merge` matched `Map.set(...)`. lodash's `set` converts to `$OBJ.set(...)`.
- `sink:javascript:html.response` matched `res.send({token, userId})`, an object Express sends as JSON.

## Runtime

251 Semgrep runs: mean 8.5 s per change, median 7.7 s, min 5.6 s, max 37.3 s (gitlab-mcp, a 453 KB
`index.ts`). Total 35.6 min of Semgrep wall time; the whole run (with checkouts) took 36 min,
12:31 to 13:07. 846 target files and 24.8 MB were read before the runs. Most of the per-change cost is
Semgrep's fixed startup, about 5 s (the brief measured 4.7 s). The in-process regex tier runs in under a
second.

## Instrument

- Every run read its targets and printed bytes per file first. No run returned faster than 1 s
  (`suspect_fast` 0). Every Semgrep exit was 0. For each change, `paths.scanned` is recorded next to
  the bytes read.
- 1 instrument failure (0.4%, under the scorer's 5% limit): a matrix-appservice-bridge ordinary change
  whose four changed files were all deleted at head (`no_readable_targets`).
- 30 changed files were missing at head and skipped.
- 103 changes had targets Semgrep did not scan because no rule covers that language: `.md` 94, `.json`
  72, no extension 16, `.html` 13, `.yml` 11, `.css` 10, and others. Our hook does not read these
  either.
- 2 PartialParsing errors (TypeScript `import("...")` types, a regex literal). Both files were still
  scanned.
- Smoke test before the run: the converted rules fired with traces on hand-written Python, JS/TSX, Java,
  C and PHP samples (`os.system`, `innerHTML`, `dangerouslySetInnerHTML`, `executeQuery`, `strcpy`,
  `echo $x;`, `include $_GET`). So the zero recall is not a dead ruleset.

## Conversion report (`rules/conversion_report.json`)

- Regex rules: 41 of 52 converted to `pattern-regex`. 11 were skipped: 5 shadow (`php-sql-call-composition`,
  `php-code-eval`, `php-unserialize`, `php-maybe-unserialize`, `php-xss-echo-input`) and 6
  `*-language` fallbacks (inactive while their tagged rule is active). No rule targets non-code
  files, and none was dropped by an emit floor (the arm uses the hook's default floor, 0.0; `--min-precision`
  sets one). Groovy has no parser and becomes `languages: [generic]` with `paths.include: [*.groovy, *.tpl]`.
- One rewrite: `php-sql-sprintf-unescaped` uses `(?:...){0,2000}?`, which PCRE2 rejects as "regular
  expression is too large". It became `*?`, so the window is now the whole statement instead of 2000
  characters.
- Facts: 40 taint/search rules (JS 10, PHP 10, Python 10, Java 7, C 3), one per (language, sink id,
  CWE). Sources come from every source fact of that language; sanitizers come from cleansing sanitizer
  facts. `weak_literals` sinks (hashlib, MessageDigest) become search rules with a `metavariable-regex`.
  Format sinks focus their format argument, and parameterized calls (`execute`, `query`) focus a
  single-argument call.
- Not convertible, skipped and named:
  - `guard` sanitizers (`php:allowlist` = `in_array`, `python:url_allowlist`): safety depends on
    dominance.
  - `parameterized` sanitizer facts (4): a call shape, expressed as the focused sink form instead.
  - `literal_format_arg` (C): expressed by focusing the format argument.
  - `dispatch:php:wordpress_hooks`: string-keyed registry routing.
  - `layout` facts (2): scope policy, not rules.
  - `v-html`: a template directive.
  - All 37 obligation tables: an absence has no pattern.
- Lossy (converted, but with weaker semantics):
  - `quoted_only` `sql_escape` became a full sanitizer. This silences the CVE-2024-1071 shape the project
    keeps.
  - `prefix_fixes_origin` on 4 destination sinks (JS/Python outbound requests and redirects) is
    dropped. A fixed-origin prefix no longer clears the value; Django's `reverse` anchors became
    sanitizers.
- Not carried at all: comment skipping, framework priors as a switch, `min_evidence_level`, ranking, the
  rung.

## What this says

Running the same vocabulary through Semgrep's engine adds no catches on these 12 positives. It adds
false alarms, from rules that the quick tier keeps quiet with comment skipping and changed-line scoping.
The misses come from the vocabulary (sources limited to request objects, no access_control without
obligations), not from the engine. This is the measured reason the brief asked for, and it points
against option A/B: the steering rule ("do not ... add a second engine") stands. If the arm is reused,
fix the cheap false alarms first: exclude `RegExp.exec`, skip comments, and scope results to changed
lines.

## Reproduce

```bash
export PYTHONPATH=$PWD
.venv/bin/python -m benchmarks.valid.semgrep_arm rules --out ~/ousast-results/valid/pilot/semgrep-rules/
for only in vulnerability ordinary; do
  .venv/bin/python -m benchmarks.valid.semgrep_arm run benchmarks/valid/pilot/pool-valid.toml --slice 1 \
    --repos ~/ousast-results/valid/pilot/repos_hist.json --rules ~/ousast-results/valid/pilot/semgrep-rules \
    --out ~/ousast-results/valid/pilot/semgrep --only $only
done
.venv/bin/python -m benchmarks.unseen.score ~/ousast-results/valid/pilot/semgrep --out ~/ousast-results/valid/pilot/scored_semgrep.json --slice-id 1
.venv/bin/python -m benchmarks.valid.metrics ~/ousast-results/valid/pilot/semgrep --scored ~/ousast-results/valid/pilot/scored_semgrep.json --out ~/ousast-results/valid/pilot/metrics_semgrep.json
```

The ordinary pass exits 2 because of the one instrument failure; the run still finishes and resumes
past done records.
