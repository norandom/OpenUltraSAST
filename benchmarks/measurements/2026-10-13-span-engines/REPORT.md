# Function-span engines: lizard and tree-sitter-language-pack against ours

Date 2026-10-13. Script: `/home/mc/ousast-results/fossil/span-eval/span_eval.py` (raw numbers in `results.json`,
tables in `tables.md`, 12 s wall, 80 MB RSS, single process). Repository HEAD 062a7b7, nothing tracked was modified.

## Setup

- Corpus: every catalog-vendored pair file plus every `benchmarks/pairs/**/{vuln,fixed}.*` outside `private/`:
  610 files (cpp 352, python 102, java 66, javascript 48, typescript 36, perl 6). The six `*.in` pairs
  (`openssl-cve-2022-1292`, `openssl-cve-2022-2068-hash_dir`, `openssl-cve-2026-31790-rsasve_generate`) are `c_rehash.in` Perl
  (`sub link_hash_cert {`), although the catalog calls them cpp; they are scored as Perl for every engine.
- Labels: the catalog's `expected.function` per pair, applied to the vuln file and (with `fix_function` when set)
  the fixed file: 570 (file, function) pairs. Names are reduced to the last segment of `A::b` / `a.b`.
- Engines: `ours_parser` = `source.ranges` (tree-sitter, regex fallback, ValueError on rejection);
  `ours_line` = `declared_functions` + `function_bounds` (and `function_bounds` alone for the label);
  `lizard` 1.24.1 `FileAnalyzer(get_extensions(["nd"]))`; `tslp` = tree-sitter-language-pack 1.22.1 with a 60-line
  extractor of mine (function node kinds per language, declarator walk for C, parent-declarator name for JS).
  All spans 1-based inclusive, earliest declaration per name. 10 s SIGALRM cap per file per engine: nothing timed out.

## Install footprint and licences (project venv, `uv pip install`)

| candidate | version | wheel | installed | pulls | licence | state |
|---|---|---|---|---|---|---|
| lizard | 1.24.1 | 1.2 MB | 0.4 MB | pygments, pathspec (both already present) | MIT | works |
| tree-sitter-language-pack | 1.22.1 | 6.0 MB | 6.1 MB | tree-sitter>=0.23 (0.26.0 present); 372 grammars | MIT (grammars carry their own, mostly MIT) | works |
| tree-sitter-languages | 1.10.2 | 82 MB | 85 MB | tree-sitter (no upper bound) | Apache-2.0 | `get_parser` raises `TypeError: __init__() takes exactly 1 argument` under tree-sitter 0.26 (built for <=0.21); uninstalled again |
| universal-ctags | - | - | - | - | - | no pip build exists (`universal-ctags`, `ctags`, `ctags-bin` not on PyPI; `python-ctags3` only reads tags files); `/usr/bin/ctags` is GNU Emacs ctags 29.3, not evaluated |

## 1. Coverage of labelled functions (hit/total)

| language | ours_parser | ours_line | lizard | tslp |
|---|---|---|---|---|
| cpp | 287/346 (83%) | 346/346 (100%) | 343/346 (99%) | 290/346 (84%) |
| python | 82/82 (100%) | 82/82 (100%) | 82/82 (100%) | 82/82 (100%) |
| java | 56/56 (100%) | 56/56 (100%) | 56/56 (100%) | 56/56 (100%) |
| javascript | 44/44 (100%) | 44/44 (100%) | 38/44 (86%) | 42/44 (95%) |
| typescript | 36/36 (100%) | 36/36 (100%) | 36/36 (100%) | 36/36 (100%) |
| perl | 6/6 (100%) | 6/6 (100%) | 4/6 (67%) | 0/6 (0%) |
| all | 511/570 (90%) | 570/570 (100%) | 559/570 (98%) | 506/570 (89%) |

- The cpp gap of ours_parser and tslp is one cause: the tree-sitter **cpp** grammar rejects 56 files (28 pairs:
  `benchmarks/pairs/vfc/curl-cve-{2020-8284,2020-8286,2021-22890,2021-22901-ossl_connect_step1,2021-22924-servercert,2022-27775,2022-27776,2022-27778,2022-27782-curl_init_userdefined,2022-27782-nss_setup_connect,2022-27782-ossl_connect_step1,2023-38545,2023-38545-do_socks5,2026-9080}/{vuln,fixed}.c`
  and `openssl-cve-{2021-3449-init_sig_algs_cert,2021-3712,2021-3712-append_ia5,2021-3712-print_qualifiers,2022-1343,2022-3358,2022-3358-evp_cipher_init_internal,2023-0216,2023-0464,2023-0464-tree_init,2023-5363,2024-2511,2026-14456-expect_quic_for_value,2026-45447}/{vuln,fixed}.c`).
  20 of the 56 parse clean under the **c** grammar; ours maps `.c` to cpp. That is a grammar-selection fix in ours, not a library question.
- lizard's two cpp misses are label defects (`openssl-cve-2023-0216:STACK_OF`, `openssl-cve-2025-69421/fixed.c:OSSL_TRACE_BEGIN`
  are macros, not functions); ours_line "hits" them through the brace matcher. lizard has no Perl reader (its 4/6 are
  accidental brace matches at the wrong start line). tslp's Perl grammar rejects the `.in` files.
- lizard JS misses are real: `vfc-js/glance-3-0-0:Glance$serveRequest` (tokenised as `$serveRequest`),
  `vfc-js/hot-formula-parser-3-0-0:performAction` (`performAction: function anonymous(` is named `anonymous`),
  `vfc-js/static-eval-1-1-1:walk` (a named function nested in `module.exports = function` is reported as `(anonymous)`);
  `vfc-js/underscore-1-13-0-0:template` resolves to the wrong `template` (lizard does not name `_.template = function`).
  tslp misses `performAction` for the same reason (uses the `function anonymous` name over the property key; ours prefers the declarator).

## 2. Span agreement where both engines find the label

| pair | language | n | start= | end MAD | end<=1 |
|---|---|---|---|---|---|
| ours_parser~lizard | cpp | 286 | 100% | 0.00 | 100% |
| ours_parser~lizard | python | 82 | 100% | 0.00 | 100% |
| ours_parser~lizard | java | 56 | 0% (all -1) | 0.00 | 100% |
| ours_parser~lizard | javascript | 38 | 95% | 0.16 | 95% |
| ours_parser~lizard | typescript | 36 | 100% | 4.94 | 78% |
| ours_parser~lizard | all | 502 | 88% | 0.37 | 98% |
| ours_parser~tslp | cpp/python/java/javascript/typescript | 503 | 100% | 0.00 | 100% |
| ours_line~lizard | cpp | 343 | 100% | 0.00 | 100% |
| ours_line~lizard | python | 82 | 100% | 0.34 | 99% |
| ours_line~lizard | java | 56 | 100% | 1.00 | 100% |
| ours_line~lizard | javascript | 38 | 95% | 9.05 | 71% |
| ours_line~lizard | typescript | 36 | 100% | 2.89 | 78% |
| ours_line~lizard | all | 559 | 99% | 0.96 | 96% |
| ours_line~tslp | javascript | 42 | 100% | 8.05 | 79% |
| ours_line~tslp | typescript | 36 | 100% | 7.06 | 89% |
| ours_line~tslp | all | 506 | 89% | 1.34 | 97% |

- Java "0% start" is a convention, not an error: tree-sitter (ours_parser, tslp) starts a method on its `@Override`
  line, lizard and ours_line on the signature line; every case differs by exactly one line.
- ours_parser and tslp agree on every one of 503 spans: they run the same grammars.
- lizard's TypeScript ends are unreliable: `agent-vfc/melodix-playerprovider-089931/vuln.tsx:PlayerProvider` ends at
  46 where the arrow function ends at 127; `mercado-do-vale-news-catalogmetadataservice-9b5fcf/vuln.ts:fetchMetadata`
  ends 3 lines short; `supplieradvisor-mvp-route-a69e8f/vuln.ts:GET` 3 lines short.
- ours_line is the weakest on JS/TS ends: `vfc-js/clamscan-1-2-0/vuln.js:local_scan` 674-830 (parser and lizard: 674-714),
  `PlayerProvider` 13-27 (parser: 13-127), `apex-publish-static-files-2-0-0/fixed.js:publish` 16-44 (parser: 16-94).

## 3. Name-set Jaccard per file (mean)

| pair | cpp | python | java | javascript | typescript | perl | all |
|---|---|---|---|---|---|---|---|
| ours_parser~lizard | 0.97 (n=296) | 1.00 (n=102) | 1.00 (n=66) | 0.87 (n=47) | 0.96 (n=36) | 0.50 (n=6) | 0.97 (n=553) |
| ours_parser~tslp | 0.98 (n=296) | 1.00 (n=102) | 1.00 (n=66) | 0.94 (n=47) | 0.99 (n=36) | - | 0.99 (n=547) |
| ours_line~lizard | 0.00 (n=352) | 1.00 (n=102) | 1.00 (n=66) | 0.63 (n=47) | 0.91 (n=36) | 0.00 (n=4) | 0.38 (n=607) |
| ours_line~tslp | 0.00 (n=296) | 1.00 (n=102) | 1.00 (n=66) | 0.63 (n=47) | 0.94 (n=36) | - | 0.42 (n=547) |

`declared_functions` has no C/C++ pattern (returns `[]`), so the line engine enumerates nothing on 58% of this corpus;
it only resolves a C function when asked for it by name.

## 4. Runtime and failures (610 files, 7 GB host with a replay running)

| engine | s per 1,000 files | failures (parse rejections; no crash, no timeout) |
|---|---|---|
| ours_parser | 4.2 | 56 (cpp grammar, listed above) |
| ours_line | 1.2 | 0 |
| lizard | 6.2 | 0 |
| tslp | 2.9 | 62 (the same 56 + 6 Perl) |

ours_parser builds a `Parser` per call; tslp caches one per language, which is the 4.2 vs 2.9 difference.

## 5. lizard nesting / cyclomatic complexity against `measure_nesting` (file level, Spearman)

| set | n | rho(max `max_nesting_depth`) | rho(max CCN) | rho(sum CCN) | exact equal |
|---|---|---|---|---|---|
| python | 50 | 0.61 | 0.52 | 0.47 | 6/50 |
| javascript+typescript (48 JS files, padded with TS) | 50 | 0.64 | 0.60 | 0.65 | 11/50 |

`measure_nesting` is a file-level indent/brace depth (classes and `try` count); lizard's `max_nesting_depth` is
per-function control-flow depth. Moderate rank correlation, values rarely equal: it is not a drop-in for the
`_NESTING_COEFF` term without recalibrating `complexity.signals._score`. What lizard adds that ours lacks is CCN.

## 6. Module-level sentinel

lizard reports no module-level unit. Code lines outside every lizard unit: cpp 11%, javascript 24%, typescript 28%,
python 40%, java 55% (fields, imports, class bodies), 18% overall; 2 files have no unit at all (the Perl `.in`).
A sentinel would be what `source.ranges` already prepends: `FunctionRange("<module>", 1, len(lines), "module")`, with
`enclosing()` picking the innermost unit and falling back to it; lizard's nested units overlap so innermost resolution still works.

## Verdicts

**lizard: keep ours.** On C, Python and Java it matches the parser engine line for line (0.00 end MAD, Jaccard
0.97-1.00) and it survives the 56 excerpts the cpp grammar rejects, which is the one thing the parser engine cannot do.
But it loses 6 of 44 labelled JavaScript functions to naming (`$`, `function anonymous`, nested named functions,
assigned function expressions), its TypeScript end lines are wrong on 22% of labels (one by 81 lines), it has no Perl
reader, and it is the slowest engine here. It cannot replace the parser engine, and replacing the line engine with it
would trade the line engine's 100% label coverage for 98% while keeping a second code path for JS/TS. Its real value is
cheap per-function CCN and nesting as extra features, not spans.

**tree-sitter-language-pack: replace the grammar packaging, not either engine.** It is the same tree-sitter: 503/503
identical spans with ours_parser, the same 56 rejections, 1.4x faster only because it caches parsers. One 6 MB MIT
wheel replaces six `tree-sitter-<lang>` wheels and adds Go, Ruby, PHP (currently regex-only in ours) and Perl grammars.
The name-resolution logic (`declarator_name`, `ranges_from_ir`) and the regex fallback stay ours, so this is a
`grammar_for` change. Independently of the library: map `.c` to the c grammar first (20 of 56 rejections clear), and cache the parser.

**tree-sitter-languages: not usable** (ABI of tree-sitter <=0.21; 82 MB). **universal-ctags: not evaluable** without a
system install. **Line engine: keep**; nothing tested replaces its property of resolving a named function in
unparseable text, though its JS/TS ends are the worst of the four and its C name enumeration is empty.
