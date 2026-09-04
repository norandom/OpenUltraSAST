# Implementation Plan

- [x] 1. Foundation: optional extra and capability probe
- [x] 1.1 Declare the semantic extra without adding core dependencies
  - Core install dependencies stay empty.
  - Optional extra named semantic lists the parser runtime and grammars for Python, JavaScript, C, C++, and Java.
  - Typecheck ignores the extra modules the same way it ignores the existing optional agentic extra.
  - Pytest registers a semantic marker for extra-on tests.
  - Observable: a default sync still has an empty core dependency list; the extra is listed only as optional.
  - _Requirements: 1.1, 1.2, 6.3_
  - _Boundary: SemanticExtra_

- [x] 1.2 Probe the extra and load a grammar without importing wheels at package load
  - Capability check uses importability, not a host CLI binary.
  - Grammar load is lazy per language and returns nothing when the extra or that grammar is missing.
  - Importing the overlay package or CLI does not import parser wheels.
  - Host CLI on PATH does not make a grammar available.
  - Observable: with the extra absent, the probe is false and a JavaScript language request yields no grammar; importing the CLI in a fresh interpreter does not load tree_sitter.
  - _Requirements: 1.2, 1.3, 3.1, 3.2, 4.3_
  - _Boundary: SemanticExtra_
  - _Depends: 1.1_

- [x] 1.3 Stop treating a host parser CLI as overlay-ready
  - Overlay-ready means a grammar can be loaded for that language, not that a CLI exists.
  - Existing env override for tests can still force the probe off.
  - Observable: a machine with a parser CLI and no extra still reports no overlay grammar for JavaScript.
  - _Requirements: 4.3, 3.1_
  - _Boundary: SemanticExtra_
  - _Depends: 1.2_

- [x] 2. Shared structured parse into existing overlay IR
- [x] 2.1 Walk one syntax tree into assignments, calls, and functions
  - One walker serves Python, JavaScript, C, C++, and Java via a node-kind table, not a visitor per language.
  - Successful trees set engine to tree-sitter and fill the existing IR records overlay taint already consumes.
  - No new language-specific stdlib or regex AST is added for JavaScript, C, C++, or Java.
  - Observable: with a JavaScript grammar loaded, `eval(req.query.x)` produces a call record for eval with the query expression as an argument.
  - _Requirements: 2.1, 4.1, 4.2_
  - _Boundary: CstWalker_
  - _Depends: 1.2_

- [x] 2.2 Treat error trees as parse failure
  - If the tree reports an error, the IR is not parse_ok and the reason is parse_failed.
  - A syntax-broken file does not yield a fake clean tree for overlay.
  - Observable: incomplete JavaScript source returns parse_failed rather than a promote or demote.
  - _Requirements: 3.4_
  - _Boundary: CstWalker_
  - _Depends: 2.1_

- [x] 3. Integration: parse dispatch
- [x] 3.1 Prefer extra grammar, then Python stdlib, then unsupported
  - Parse order is grammar walk, else Python stdlib parse for Python only, else language_unsupported.
  - Host CLI output is never used as a successful overlay parse.
  - Missing extra does not fail a standard scan by itself.
  - Overlay still emits only promote, demote, unadjudicated, and coverage.
  - Observable: extra-free JavaScript inventory is unadjudicated language_unsupported; extra-free Python `eval(request.args)` still promotes via stdlib parse; extra-on JavaScript uses engine tree-sitter.
  - _Requirements: 2.1, 2.4, 3.3, 3.5, 4.2, 4.3_
  - _Boundary: ParseDispatch_
  - _Depends: 1.2, 2.1, 2.2_

- [x] 4. Validation: extra-free core, extra-on overlay, CI matrix
- [x] 4.1 Prove extra-free quick and fail-closed overlay
  - Quick scan completes without the extra and still emits inventory.
  - JavaScript, C, and Java stay unadjudicated language_unsupported or parse_failed without the extra.
  - Python stdlib parse remains the last resort when the extra is absent.
  - Observable: extra-free pytest covering quick plus JS unsupported is green; detection gate still ignores overlay Youden.
  - _Requirements: 1.1, 1.3, 3.1, 3.3, 5.5, 6.1_
  - _Boundary: ExtraTestMatrix_
  - _Depends: 3.1_

- [x] 4.2 (P) Prove extra-on JavaScript promote and C or Java demote
  - Marked tests skip when the extra is absent instead of failing the extra-free suite.
  - With the extra, JavaScript eval of request query promotes.
  - With the extra, a C or Java sink fed only by a constant or dominating sanitizer demotes rather than language_unsupported.
  - Evidence stays at static_corroboration or below; sandbox selection is still promotions only.
  - Observable: extra-on tests pass when wheels are installed and skip otherwise; JS promote and C or Java demote assertions fail if the walker is removed.
  - _Requirements: 2.2, 2.3, 3.4, 5.3, 5.4, 6.2, 6.3_
  - _Boundary: ExtraTestMatrix_
  - _Depends: 3.1_

- [x] 4.3 Run extra-on checks in CI without breaking extra-free CI
  - Default CI job stays extra-free and must remain green.
  - A second job installs the semantic extra and runs the semantic-marked tests.
  - Joern is not required; no language model is used as parse or taint.
  - Observable: extra-free job does not install parser wheels; extra-on job executes the marked JS and C or Java tests.
  - _Requirements: 5.1, 5.2, 6.1, 6.2, 6.3_
  - _Boundary: ExtraTestMatrix_
  - _Depends: 4.1, 4.2_

## Implementation Notes

- Extra wheels: tree-sitter 0.26 with grammar packages python/javascript/c/cpp/java. `OPENULTRASAST_TREE_SITTER_PROBE=0` simulates extra-absent even when wheels are installed locally.
- Host `tree-sitter` CLI is not overlay-ready; only lazy `grammar_for` produces FileIR.
- Default CI stays extra-free; job `semantic` runs `uv sync --extra semantic` then `pytest -m semantic`.
