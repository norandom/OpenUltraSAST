# Could Semgrep CE or Opengrep replace the quick-rule engine and the tree-sitter taint overlay?

Date: 2026-10-13. Read-only research; measurements ran on this host (semgrep 1.179.0, 4 cores). Short
answer: as an engine, yes for most quick rules and the intra-function taint overlay; as a shipped rule
corpus, no; obligations, sanitizer semantics and measured floors do not carry over. Recommend C first.

## 1. What we have

**Quick rules.** `src/openultrasast/findings.py:45-75` compiles every enabled TOML rule to a Python
regex, filters by `rule.languages`, skips matches in comments (`:197-218`), and emits a
`StaticFinding` (`:15-36`: `finding_id, path, title, severity, confidence, evidence_level, rationale,
line, function_name, reachability_status/evidence/conditions, tags, ranking_priority, status, rung`).
Severity comes from `policy/CWE_Score.tsv` (168 rows: Flaw Category, CWE ID, Name, Flaw Severity
0-5, Static, Dynamic) via `resolve_severity` (`findings.py:121`). Floors `min_emit_priority` /
`min_emit_precision` (`:52-60`) and the ledger overlay (`ruleset/store.py:44-74`) keep low-precision
rules shadowed. Rule schema, `ruleset/store.py:20-42`: `rule_id, title, languages, cwe, tags,
pattern, status (enabled|shadow|disabled), min_evidence_level, precision_estimate, version,
framework, library, fallback_for`. Counts: C 6, Groovy 1, Java 4, JavaScript 12, PHP 18 (6 shadow),
Python 11 = 52 rules.

Example 1 (`ruleset/python/rules.toml`):
```toml
[[rule]]  rule_id = "python-shell-true"   cwe = "CWE-78"   tags = ["syscall_entry"]   languages = ["python"]
status = "enabled"   precision_estimate = 0.0   version = "1"
pattern = '''subprocess\.[a-zA-Z_]+\s*\([^\n]*shell\s*=\s*True'''
```
Example 2, `ruleset/php/rules.toml:48-59`: `php-sql-unquoted-concat`, `cwe = "CWE-89"`, `framework =
"wordpress"`, `precision_estimate = 0.034`, a 300-character lookbehind regex over `ORDER BY ... " . $x`.

**Taint overlay.** Facts live in `ruleset/semantic/*.toml` (101 tables: Python 5 sources / 18 sinks /
4 sanitizers; PHP 3/11/11; JavaScript 2/17/6; Java 2/9/4; C 2/3/1). The dataclasses
(`semantic/facts.py:27-70`) carry semantics Semgrep has no word for: `SanitizerFact.quoted_only` (an
escape that only protects a quoted literal), `guard` (a check, safe only where it dominates),
`parameterized`, `literal_format_arg`; `SinkFact.prefix_fixes_origin`, `origin_anchors`; plus
`DispatchFact` (string-keyed hook registries) and `LayoutFact`. `semantic/taint.py:1` is "intra-file
taint on FileIR": per function, parameters start tainted (`:84`), sources match by substring
(`:222-227`), and the result is promote / demote / unadjudicated / coverage
(`semantic/overlay.py:32-50`), never a bare match. Obligation checks (`semantic/obligations/`, 1,635
lines; `ruleset/obligations/*.toml`, 37 tables) find a missing guard, an absence, not a pattern. The
facts tables also feed the Joern model layer (`model/candidates.py:216`, `model/layout.py:14`).

**Languages, gate, scorers, hook.** `preprocess.py:11-36` maps 15 languages (c, cpp, python,
javascript, typescript, go, rust, java, groovy, kotlin, ruby, php, csharp, swift, solidity);
`README.md:167-177` names the three scan modes. `gate.py:37-38` requires recall >= 0.90 and FP < 0.10
on the fixture manifests (`:30-35`), scored on `quick_scan_findings` (`:80-84`). The pair scorer
(`pairs.py:1089-1111`) matches an overlay record by `rule_id` in `proposal_id`, by sink id, or by CWE
inside the named function; obligations only by an `obligation:<kind>` tag (`:1114-1126`). The push
scorer (`benchmarks/unseen/score.py:49-91`) needs `cwe` (mapped to a family), `path`, `line`,
`function` on each quick finding. `push/quick.py:60-119` runs the rules over the head side of changed
files and keeps a hit only on a changed line or in a changed function (`:122-130`); advisory (`:35`).

**Steering.** `.kiro/steering/safety-net.md:85-88`: "Start with the existing detector, earn alert
admission per capability, and add scheduling sophistication only when it improves the measured
developer outcome. Do not rebuild a custom IR, add a second engine, or assume incremental Joern
updates as a shortcut to an unmeasured latency promise."

## 2. Licensing in 2026

- Engine: Semgrep CE is LGPL-2.1 (https://github.com/semgrep/semgrep/blob/develop/LICENSE); CE is
  "single-file analysis with single-function taint tracking" (https://docs.semgrep.dev/faq/comparisons/opengrep-1).
- Rules: everything Semgrep maintains in `semgrep-rules` (so `p/default`, `p/python`, `r/...` rows
  from that repo) moved on 2024-12-13 to the Semgrep Rules License v1.0
  (https://semgrep.dev/legal/rules-license/): "You may use the rules only for your own internal
  business purposes." "This license does not allow you to distribute the rules, or to make them
  available to others as a service." Semgrep's summary: "Vendors may not use them in competing
  products or SaaS offerings." Shipping them inside this Apache-2.0 tool (`pyproject.toml:10`) is
  distribution; not allowed. Third-party registry rules keep their own licences. Before the change
  the rules were LGPL-2.1 + Commons Clause (https://joshcgrossman.com/2025/01/28/whats-going-on-with-sem-open-grep/).
- Opengrep (https://github.com/opengrep/opengrep): LGPL-2.1 fork of Semgrep v1.100.0 backed by
  Aikido, Amplify, Endor Labs, Kodem, Orca. Releases 1.30.0/1.30.1/1.30.2 (Sep 7 to Oct 7 2026) plus
  `v2.0.0-nopython-interfile` alphas (https://github.com/opengrep/opengrep/releases). Adds
  `--taint-intrafile` (cross-function in one file), fingerprints, per-rule timeouts, signed single
  binaries, no pip (https://docs.semgrep.dev/faq/comparisons/opengrep). `opengrep-rules` is a
  2024-12-13 snapshot of semgrep-rules under LGPL-2.1 + Commons Clause, "for research, testing &
  benchmarking", archived 2025-11-28 (https://github.com/opengrep/opengrep-rules).

## 3. Install and runtime

- `pip install semgrep` 1.180.0 (2026-10-07): Python >= 3.10; Linux x86_64 wheel 70.6 MB, unpacking
  to a 256 MB static OCaml `semgrep-core` plus libssl (https://pypi.org/project/semgrep/; wheel
  listing checked locally). A release every 5-13 days (https://github.com/semgrep/semgrep/releases).
- Offline: `--config <dir> --metrics=off --disable-version-check`; "metrics are never sent" with `off`
  (https://docs.semgrep.dev/metrics, https://docs.semgrep.dev/cli-reference). No air-gap guarantee is documented.
- Measured here: startup on an empty tree 4.7 s, 136 MB RSS. 12 pilot checkouts
  (`~/ousast-results/valid/pilot/hist`, 407 Python files, 3 rules): 8.6 s at `-j 1`, 6.8 s default,
  so 5-10 ms per file after the fixed 4.7 s; a 1,000-file repo is roughly 10-15 s. Semgrep claims
  3x from its multicore engine (https://semgrep.dev/blog/2025/benchmarking-semgrep-performance-improvements).
  The fixed 4.7 s matters for the push hook, whose regex tier runs in-process in under a second.

## 4. Capability

- CE taint: `mode: taint` with `pattern-sources/sinks/sanitizers`, intraprocedural only ("can only
  analyze interactions within a single function", https://docs.semgrep.dev/semgrep-code/semgrep-pro-engine-intro);
  `pattern-propagators` and `--pro-intrafile` are Pro (https://docs.semgrep.dev/writing-rules/data-flow/taint-mode).
  Verified locally: PHP, JavaScript and Python taint rules fire with a `dataflow_trace`; a C rule
  `argv -> system()` did not fire through `strcpy` (needs a propagator). No Groovy parser: `generic` + regex only.
- JSON observed on 1.179.0 CE (docs list some as platform-only): `check_id, path,
  start/end.{line,col,offset}, extra.{message, metadata, severity, lines, fingerprint, metavars,
  dataflow_trace, engine_kind, is_ignored}`; SARIF 2.1.0 with `fingerprints`
  (https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif). `metadata` is free-form but
  rejects a float ("expected a list, dict, tree, int or str"): `precision_estimate` becomes a string.
- Changed-line scoping: `--baseline-commit` reports findings absent at a commit and "aborts run if not
  currently in a git directory, there are unstaged changes"; per file, so `push/quick.py:122-130` stays on top.

## 5. Rule conversion

Regex rule `python-shell-true` as a syntax pattern or a verbatim PCRE2 regex:
```yaml
- id: python-shell-true
  languages: [python]   severity: WARNING   message: Subprocess shell execution needs review
  metadata: {cwe: CWE-78, family: injection, tags: [syscall_entry], precision_estimate: "0.0", status: enabled}
  pattern: subprocess.$F(..., shell=True, ...)   # or pattern-regex: 'subprocess\.[a-zA-Z_]+\s*\([^\n]*shell\s*=\s*True'
```
Fact triple (`semantic/python.toml`: source `request`, sink `os.system`, a sanitizer) becomes:
```yaml
- id: python-os-command-taint
  mode: taint   languages: [python]   severity: ERROR   message: request data reaches an OS command sink
  metadata: {cwe: CWE-78, family: injection, sink: os.system, source: request}
  pattern-sources: [{pattern-either: [{pattern: request.args}, {pattern: request.form}, {pattern: request.get_json(...)}, {pattern: sys.argv}]}]
  pattern-sanitizers: [{pattern: shlex.quote(...)}]
  pattern-sinks: [{pattern-either: [{pattern: os.system(...)}, {pattern: subprocess.run(...)}, {pattern: subprocess.Popen(...)}]}]
```
Both validated and fired on a test file (two findings, with traces). Not expressible: `quoted_only`
(Semgrep's PHP rule silenced `ORDER BY " . mysqli_real_escape_string(...)`, the CVE-2024-1071 shape
the project keeps), `guard` dominance, `prefix_fixes_origin`, `DispatchFact` routing, every
obligation, `shadow` status and emit floors (a post-filter on our side), framework priors and
`fallback_for` (two rule files plus a selector), `uncovered_languages` (`findings.py:78-99`). Regex
rules on non-code files map to `languages: [generic]` + `pattern-regex`.

## 6. Risks

- Steering forbids "a second engine". Semgrep beside Joern is one; adopting it means amending
  `safety-net.md` with a measured reason, the rule's own test.
- LGPL: running `semgrep-core` as a subprocess and reading JSON is "communicate at arm's length"; the
  GNU FAQ says fork-and-exec with pipes or command-line arguments keeps two programs separate
  (https://www.gnu.org/licenses/gpl-faq.html#GPLPlugins, #MereAggregation; gnu.org rate-limited
  today, quoted via mirrors). No obligation on our Apache-2.0 code; shipping the binary in the Docker
  image obliges only passing on the LGPL text and a source offer.
- Supply chain: weekly releases, pin version and hash. Opengrep: signed binaries, 2.0 in alpha.
- Detection quality is unknown: the 52 rules carry measured floors and six shadow rules learned on
  PHP; gate and pair numbers restart from zero, and Semgrep's rules cannot be shipped to close the gap.

## 7. Comparison, options, recommendation

| | Ours | Semgrep CE | Opengrep |
|---|---|---|---|
| Licence | Apache-2.0 | engine LGPL-2.1; rules not open | engine LGPL-2.1; no own rules |
| Languages with taint | C, Java, JS, PHP, Python (facts) | all parsed languages, no Groovy | same, plus Apex/VB/Crystal |
| Changed-line scoping | spans + changed function | `--baseline-commit`, per file | same |
| Offline | yes | yes, three flags | yes |
| Install size | 0 extra (tree-sitter extra) | 70 MB wheel / 256 MB binary | one binary, similar |
| JSON / SARIF | own JSON + SARIF | both, with traces | both, with fingerprints |
| Interprocedural | no (Joern does that) | no (Pro) | within one file |

Lines a swap retires: `findings.py` 223 + `ruleset/*.py` 328 + `semantic/{taint,overlay,engines,
prove_filter}.py` 695 = about 1,250. Kept: `semantic/ir.py`, `cst.py`, `facts.py` (used by `source.py`,
`model/candidates.py`, `learn/slice.py`), obligations (1,635), policy, scorers.

- A. Semgrep CE, our rules converted, no registry. Effort L (TOML-to-YAML emitter, adapter to
  `StaticFinding`, re-measure gate and pairs, hook latency). Risk high: +4.7 s per hook run,
  sanitizer semantics lost, steering amended.
- B. Opengrep with our rules. Effort L plus binary packaging. Risk high: smaller project, 2.0 in
  alpha; gains in-file cross-function taint.
- C. Keep ours; Semgrep as a benchmark arm. Effort S. Risk low: nothing ships; it answers the one
  open question (does the engine catch more on the valid pilot?).

**Recommendation.** Do C. The engine is cheap and licence-clean, but this project's value is in the
facts and the policy around a match (quoted-only escapes, guards, shadow rules, obligations, the
rung), and none of that moves with the engine. A swap buys a slower hook and an unmeasured gate for
about 1,250 lines removed. Only a measured catch gap on unseen application repos justifies amending
the steering rule; C produces that number.

**First increment.** `benchmarks/valid/semgrep_arm.py`: emit `ours.yaml` from the 52 TOML rules and
five facts files (regex -> `pattern-regex`, facts -> `mode: taint`); run `semgrep scan --config
ours.yaml --metrics=off --disable-version-check --json` on each head checkout under
`~/ousast-results/valid/pilot/hist/`; map results to the `quick_tier` shape (`rule, cwe, path, line,
function, scope` via `head_spans`); write a second replay record; score both with
`benchmarks/unseen/score.py` (catches per family, false alarms, McNemar). Instrument rule: print
`paths.scanned` and bytes read per repo before believing a zero.
