# Brief: tree-sitter-overlay-extra

## Problem

AppSec scanning mixed working trees gets `language_unsupported` on JS/C/Java, and Python-only `ast` cannot follow the patterns those languages actually use. The overlay spec promised tree-sitter as the primary engine; the CLI probe never builds `FileIR`. Maintaining hand-rolled parsers would explode the codebase.

## Current State

`parse_tree_sitter_cli` returns `None` even on a successful parse. Python falls back to stdlib `ast`. JS/C/Java stay unadjudicated. `quick` is correctly zero-dep. SAST overlay Youden on the 11-pair textbook slice is 0% vs +9% inventory — not because regex got worse, but because Python overlay fail-closes on ConfigParser-style heap and C/Java never parse.

## Desired Outcome

With the extra installed, tree-sitter grammars produce `FileIR` for Python, JavaScript, C/C++, and Java. Existing taint/facts/dispositions consume that IR unchanged. Without the extra, behavior stays fail-closed unadjudicated. `quick` still has no parser wheels.

## Approach

Add optional extra `openultrasast[semantic]` (`tree-sitter` + official language packages). One CST walker extracts binds and calls into the current `FileIR`. Delete the dead CLI sexp stub. Do not add a fourth language-specific AST visitor.

## Scope

- **In**: extra, probe that prefers the Python API when importable, CST → FileIR, tests with and without the extra.
- **Out**: Joern queries, inter-file taint, CWE-121 buffer semantics, new pair corpora (owned by `real-world-vfc-slice`).

## Boundary Candidates

- Packaging extra vs core install
- CST walker vs taint engine (taint stays in `semantic/taint.py`)

## Out of Boundary

- Pattern rules, CWE policy, sandbox, mechanism JSONL schema, pair catalog harvest

## Upstream / Downstream

- **Upstream**: `propose-adjudicate-prove` overlay records and taint
- **Downstream**: `real-world-vfc-slice` overlay scoring on C/JS/Java pairs

## Existing Spec Touchpoints

- **Extends**: none (new spec). Does not reopen `propose-adjudicate-prove` tasks.
- **Adjacent**: `three-stage-scan` modes; `quick` must remain zero-dep.

## Constraints

No new required dependency. Missing extra → `language_unsupported` or Python ast, never crash. No LLM parse.
