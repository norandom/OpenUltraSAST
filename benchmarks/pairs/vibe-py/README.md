# vibe-py slice

Isolated Python web functions from [Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark)
(Apache-2.0 benchmark; each target repository keeps its own license).

- **Vuln side**: the function enclosing a labeled vulnerable finding (`is_vulnerable = true`).
- **Fixed twin**: a false-positive trap function (`is_vulnerable = false`) from the same repository.
  The scanner must stay silent there, so silent-on-fix here measures precision on traps.
- **Provenance**: `human` for the 26 human-authored apps, `agent` for the 40 LLM-generated apps.
  The LLM-generated repositories (`kolega-ai-dev/vc-*`) carry **no license file**, so they
  are never vendored (Req 5.4): `build_recipes.py --pointers` appends them as `vendored = false`
  rows (80 pairs over the 40 repositories, `agent`, `review_tier = "seeded"`) that
  `ousast pairs --slice vibe-py --pointers` harvests into the local cache and scores (Req 10).
  The default run skips them with `pointer_pair_skipped`.
- **Caveat**: the human corpus is educational and CTF style (DVPWA, VAmPI, vulpy, ...), not
  production code. Say so when reading numbers.
- **Matching**: every row names the function; the upstream scorer tolerates ±10 lines, ours
  requires the detection inside the function.

- **Excerpt shape**: line-range excerpts of methods keep their class indentation, so 27 of them
  fail stdlib `ast.parse` ("unexpected indent") while tree-sitter parses them with correct
  function ranges. `parse_failed 0` rests on tree-sitter; stdlib-ast parity would need dedenting.

Rebuild: see the docstring of `build_recipes.py` (add `--pointers` for the LLM repositories). Regenerate the catalog with
`python benchmarks/pairs/catalog_gen.py --slice vibe-py`. Maintainer only; CI never fetches.
