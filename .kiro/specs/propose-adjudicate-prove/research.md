# Research & Design Decisions

## Summary

- **Feature**: `propose-adjudicate-prove`
- **Discovery Scope**: Extension of `three-stage-scan` (MAP grows an overlay; STATIC and REGRESS stay)
- **Key Findings**:
  - Inventory already decides; MAP ranks; REGRESS can run. Nothing adjudicates flow.
  - Labeled SAST slice Youden is about +9%. Leaks are OWASP-false / Juliet `goodG2B` that still contain the sink. Misses are one-hop assignments and sink aliases.
  - Clearwing already does the split we want: tree-sitter callgraph + pattern taint tables, then ranker (surface/influence/reachability 0.5/0.2/0.3), then mechanism-memory embeddings. OpenUltraSAST already copied the rank formula and has `json-local` vectors; they are not wired as prove-budget.
- Tree-sitter CLI/API covers C/C++/Python/JS/Go/Rust (Clearwing grammars); Joern is the CPG sidecar when present. Stdlib `ast` is last-resort Python only. LLM hunter remains suspicion-only.
  - Real working trees will often fail parse or cross a file boundary. Those cases must stay **unadjudicated**, not demoted.

## Research Log

### Labeled vs unlabeled code

- **Context**: Operator: known-vuln corpora are “nice”; written code will not be.
- **Sources Consulted**: In-tree `LANGUAGE_MANIFESTS`, `benchmarks/pairs/`, OWASP Benchmark true/false files, Juliet `bad`/`goodG2B`/`goodB2G`, CWE-Bench-Java catalog.
- **Findings**:
  - Cheat-sheets: one CWE, named sink, often same-line source.
  - OWASP: true and false files both often contain `exec` / `eval`; the difference is source constancy or infeasible branches.
  - Juliet `goodG2B`: hardcoded source, **same sink**.
  - Juliet `goodB2G`: same source, **sanitized sink** (`printf("%s")`).
  - Working trees: syntax errors, generated bundles, wrappers (`helpers.db_sqlite.execute`), no labels.
- **Implications**: Overlay scored on sast slice; unlabeled scans must not pretend demote. Unadjudicated is a first-class disposition.

### Engine choice

- **Context**: Operator prefers tree-sitter + Joern look, embeddings before prove, still v1-focused.
- **Sources Consulted**: `clearwing/sourcehunt/callgraph.py`, `taint.py`, `ranker.py`, `mechanism_memory.py`; `openultrasast/rank.py`, `vectorstore.py`, `index.py`.
- **Findings**:
  - Clearwing tree-sitter is optional: missing grammar disables callgraph, does not crash.
  - Clearwing taint is intra-procedural, pattern tables for sources/sinks — same shape as our fact TOML.
  - Clearwing ranker fills reachability from the callgraph; taint_paths boost surface. Embeddings retrieve *mechanisms*, they do not decide taint.
  - Our `heuristic_rank` already uses surface·0.5 + influence·0.2 + reachability·0.3. Vector store bakeoff selected `json-local`. `VALID_NAMESPACES` already includes `mechanisms` but nothing writes Clearwing-style records into it.

### Clearwing vector-store reference (real-world bugs)

- **Context**: Operator: Clearwing’s store is effective on real bugs, not textbook files.
- **Sources Consulted**: `clearwing/sourcehunt/mechanism_memory.py`, `data/memory/semantic_memory.py`, `docs/architecture.md` steps 7–8; `openultrasast/index.py` namespaces.
- **Findings**:
  - Store **mechanisms**, not findings and not 80-line file windows. Example: “length field trusted before alloc; 16-bit value widened to size_t.”
  - JSONL is the source of truth (`~/.clearwing/sourcehunt/mechanisms.jsonl`). Chroma/sqlite embeddings are ephemeral caches rebuilt from JSONL.
  - Write path is **verified findings only** (after adversarial verify / crash). Suspicion never seeds the store.
  - Clearwing’s JSONL + verified-write + metadata filters are the reference. Its TF-IDF default is **not**: bag-of-words will not match paraphrased real bugs (`length field trusted before alloc` vs `user-controlled size_t in malloc`).
  - OpenUltraSAST already has `OpenRouterEmbeddingClient` and json-local cosine. Use that as the only semantic ranker; CWE/language/tags are hard filters. No TF-IDF, no Chroma, no local MiniLM.
  - Query is language + file tags + optional free text; same-language boost +0.5. Top-N injects hunter context and variant-grep seeds — it does not decide taint.
  - Variant loop then greps the *messy* tree for structural matches of that mechanism. That is how it leaves Juliet behind.
- **Implications**: Copy JSONL + verified-write + metadata filters. Rank with OpenRouter embeddings only. Do not copy TF-IDF. Do not embed 80-line file windows as the prove store. Seed from sandbox-proven mechanisms, not OWASP `BenchmarkTest00007`.
  - Joern CLI (`joern-parse` / scripts) is the only practical CPG without a Scala runtime in-process.
- **Implications**: Probe tree-sitter like Docker. Joern sidecar cannot demote. Embeddings order prove only.

### Decision: Python intra-file first

- **Context**: Zero-dep core vs multi-language trees.
- **Selected**: **Superseded.** Tree-sitter is the prio engine; stdlib `ast` is Python last resort; `quick` stays zero-dep.
- **Rationale**: Operator working trees are mixed-language; Python-only adjudication would leave JS/C/Java as perpetual unadjudicated.
- **Trade-offs**: `standard` needs a grammar or CLI on PATH; missing tools → unadjudicated, not skip the scan.

### Evidence ladder

- **Context**: Three-stage-scan forbids hunter JSON as corroboration.
- **Sources Consulted**: `verification.EvidenceLevel`, `tool_hunter` suspicion rule, `worth_fixing` gate.
- **Findings**: Overlay can justify promote at `static_corroboration`. It cannot skip to crash or exploit. Worth-fixing stays sandbox + reachability.
- **Implications**: Disposition is not an evidence rung. Do not add a seventh ladder value.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks | Notes |
|--------|-------------|-----------|-------|-------|
| Replace regex with CodeQL | External engine is the detector | Real dataflow | Breaks zero-dep, smoke gate, ledger shadows | Rejected |
| LLM hunter as adjudicator | Model reads file and votes | Flexible on messy code | Unstable Youden; violates suspicion rule | Rejected |
| Overlay on inventory | Regex proposes; tree-sitter taint adjudicates; embed ranks prove | Fits stages; multi-lang | Parser must be probed | **Selected** |
| Whole-program taint v1 | Inter-file | Closes wrappers | Too large; false demote risk | Defer; stay unadjudicated |

## Design Decisions

### Decision: Unadjudicated is not demote

- **Context**: Messy files and cross-file flow.
- **Alternatives**: Silent drop; treat as safe; force demote.
- **Selected**: Explicit `unadjudicated` with reason.
- **Rationale**: Operator writing code must not read silence as “clean.”
- **Trade-offs**: Reports stay noisy until languages and inter-file land.
- **Follow-up**: Count unadjudicated rate on unlabeled trees as an honesty metric.

### Decision: Score overlay on sast slice, inventory on smoke gate

- **Context**: +9% Youden vs 93% cheat-sheet recall.
- **Selected**: Two gates stay separate; overlay Youden cannot unblock smoke failure.
- **Rationale**: Same as detection-gate vs score in the improve loop.

## Risks & Mitigations

- False demote on real bugs (infeasible-branch OWASP tricks, wrappers) — never demote when flow is incomplete; only demote when the engine *has* a dominating constant or sanitizer.
- Youden chase via extra sinks — each coverage rule needs a false/good counterpart that must stay demoted or silent.
- Parse failures on operator WIP — unadjudicated, `quick` still works.

## References

- `.kiro/specs/three-stage-scan/design.md` — stage plan, sandbox, hunter suspicion
- `benchmarks/pairs/sast/README.md` — OWASP/Juliet slice
- NIST Juliet `goodG2B` vs `goodB2G` templates
- OWASP Benchmark expectedresults true/false protocol
