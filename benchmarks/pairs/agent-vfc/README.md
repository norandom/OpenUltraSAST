# agent-vfc slice

Security-fix commits carrying an AI coding agent co-author trailer or generation marker
(Claude Code, Codex, Cursor, Copilot, Devin), in JavaScript, TypeScript, or Python.
`provenance = "agent"`. Only repositories with a stated license are vendored; fixes in
unlicensed repositories are `vendored = false` pointer rows (`build_recipes.py --from ... --pointers`,
function label derived from the cached excerpt) scored by `ousast pairs --slice agent-vfc --pointers`.

## Review checklist (Req 5.3)

A recipe with `reviewer = "pending"` loads at `review_tier = "title"`: scored and reported by `pairs`; the improve loop's
profile gate uses only `seeded` and `reviewed` pairs (Req 9.3, task 8.2). Setting `reviewer` to your name promotes it to `reviewed`. Before doing so:

1. The parent excerpt really contains the vulnerability the title claims (not a refactor).
2. One mechanism from `benchmarks/pairs/mechanisms.toml` explains it; adjust `mechanism` and `cwe`.
3. The fixed excerpt removes it and the change is inside the vendored function.
4. No secret, token, or personal data is in either excerpt (run the redaction check).
5. The license header is present and matches the repository license.

Rebuild: `python benchmarks/pairs/agent-vfc/build_recipes.py --search /tmp/agents.jsonl` then
`--from /tmp/agents.jsonl`, `harvest.py --slice agent-vfc --all --fetch`, `catalog_gen.py --slice agent-vfc`.
