# vfc-js slice

Server-side JavaScript function pairs harvested from the **upstream fix commits** that
[SecBench.js](https://github.com/cristianstaicu/SecBench.js) records in its package metadata
(`fixCommit`, `sink`). SecBench.js itself has no license file, so none of its files are vendored;
each excerpt carries the upstream package's license.

- Classes: command injection, path traversal, code injection first. Prototype pollution and ReDoS
  rows may be added with their own mechanism and `known_limit` until the engine can talk about them.
- Mode: `hunk` (the function enclosing the first changed hunk on each side).
- Provenance: `human`.

Rebuild: `python benchmarks/pairs/vfc-js/build_recipes.py --crawl /tmp/secbench.jsonl` then
`--from /tmp/secbench.jsonl`, `harvest.py --slice vfc-js --all --fetch`, `catalog_gen.py --slice vfc-js`.
