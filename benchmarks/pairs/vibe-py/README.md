# vibe-py slice

Isolated Python web functions from [Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark)
(Apache-2.0 benchmark; each target repository keeps its own license).

- **Vuln side**: the function enclosing a labeled vulnerable finding (`is_vulnerable = true`).
- **Fixed twin**: a false-positive trap function (`is_vulnerable = false`) from the same repository.
  The scanner must stay silent there, so silent-on-fix here measures precision on traps.
- **Provenance**: `human` for the 26 human-authored apps, `agent` for the 40 LLM-generated apps.
  The LLM-generated repositories (`kolega-ai-dev/vc-*`) currently carry **no license file**,
  so they are skipped by `build_recipes.py` and not vendored (Req 5.4). Re-run with
  `--allow-unlicensed` only to inspect them locally; do not commit those excerpts.
- **Caveat**: the human corpus is educational and CTF style (DVPWA, VAmPI, vulpy, ...), not
  production code. Say so when reading numbers.
- **Matching**: every row names the function; the upstream scorer tolerates ±10 lines, ours
  requires the detection inside the function.

- **Excerpt shape**: line-range excerpts of methods keep their class indentation, so 27 of them
  fail stdlib `ast.parse` ("unexpected indent") while tree-sitter parses them with correct
  function ranges. `parse_failed 0` rests on tree-sitter; stdlib-ast parity would need dedenting.

Rebuild: see the docstring of `build_recipes.py`. Regenerate the catalog with
`python benchmarks/pairs/catalog_gen.py --slice vibe-py`. Maintainer only; CI never fetches.
