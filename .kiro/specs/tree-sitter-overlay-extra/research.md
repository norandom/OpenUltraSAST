# Gap Analysis: tree-sitter-overlay-extra

Requirements are **generated but not approved**. Analysis proceeds to inform design; it does not treat requirements as locked.

Steering `product.md` / `tech.md` / `structure.md` are absent. Context is the overlay package, `harness_ext` extra pattern, `pyproject.toml`, CI, and PyPI tree-sitter bindings.

---

## 1. Current State

### Assets that already exist

| Asset | Role today |
|-------|------------|
| `src/openultrasast/semantic/ir.py` | `FileIR` / `Bind` / `CallSite`; Python `ast` extractor (~170 lines); `parse_tree_sitter_cli` **always returns `None`** |
| `src/openultrasast/semantic/engines.py` | Probe: env flag, `importlib.util.find_spec("tree_sitter")`, or `tree-sitter` CLI on PATH |
| `src/openultrasast/semantic/taint.py` | Language-agnostic taint on `FileIR` (names, constants, fact tables) |
| `src/openultrasast/semantic/overlay.py` | Dispositions; already consumes `parse_file` |
| `src/openultrasast/ruleset/semantic/*.toml` | JS/C/Java facts already written |
| `src/openultrasast/harness_ext.py` | Pattern for optional extra: `find_spec`, lazy import, mypy override, cold-import tests |
| `pyproject.toml` | `dependencies = []`; only extra is `harnessx` |
| `tests/test_semantic_overlay.py` | JS unsupported without probe; JS IR only via **monkeypatch**, not a real grammar |

### Conventions

- Optional native/heavy deps stay off the default install; capability probe must not import at module load (`harness_ext`, Docker sandbox probe).
- mypy `ignore_missing_imports` for extras (`harnessx.*`).
- pytest marker already exists for `docker`; extra-enabled tests would follow that skip pattern.
- CI `checks` job: `uv sync --group dev` then pytest — **no optional extras**.

### Integration surfaces

- `parse_file(path, text, language) -> FileIR` is the only seam taint/overlay need.
- `tree_sitter_available()` is a **presence** probe, not “grammar produced IR”. Host CLI on PATH makes it True even with no PyPI wheels (this environment has `/home/linuxbrew/.../tree-sitter` and **no languages**).
- Pair eval already falls back to inventory when a language never promotes/demotes.

## 2. Requirements Feasibility

| Req | Need | Gap |
|-----|------|-----|
| 1 Extra-free `quick` | Empty core deps; no import of parser wheels at load | **Constraint met.** Missing extra cannot currently break `quick` because there is no extra. Must keep it that way. |
| 2 Structured parse for Py/JS/C/C++/Java | Real CST → `FileIR`; JS promote; C/Java demote on constant/sanitizer | **Missing.** CLI parse never builds `FileIR`. No `[semantic]` extra. No CST walker. |
| 3 Fail closed | `language_unsupported` / `parse_failed`; Python ast last resort | **Mostly present** via `parse_file` fallback. Syntax-error Python already `parse_failed`. JS/C/Java without IR already `language_unsupported`. |
| 4 One shared extract path | Not a visitor per language; CLI without extra must not fake success | **Missing walker.** CLI stub already returns `None` (does not fake success). Probe can still report “available” without IR — **constraint** for Req 4.3 wording vs `tree_sitter_available()`. |
| 5 Overlay contracts | No LLM parse; Joern not required; corroboration; promotions-only sandbox; gate inventory-only | **Present** in overlay/prove/gate. Do not reopen. |
| 6 Dual test matrix | Extra-free always; extra-on JS + C/Java; skip if extra absent | **Partial.** Extra-free tests exist. Extra-on tests are mocked. No pytest marker. CI does not install a semantic extra. |

**Complexity signal:** external native-wheel extra + one algorithmic CST walk + pytest/CI matrix. Not CRUD.

**Research needed (design phase, not blockers):**

1. Pin compatible `tree-sitter` + `tree-sitter-{python,javascript,c,cpp,java}` wheel ABIs (`Language(mod.language())` vs older `build_library`). PyPI: `tree-sitter` 0.26 (2026-06-30), `tree-sitter-javascript` 0.25.
2. Per-language CST node names for assignment, call, identifier, string, function (JS `assignment_expression` vs C `assignment_expression` vs Java `assignment_expression` vs Python `assignment`). Shared walker needs a small node-kind table, not four visitors.
3. C++: separate `tree-sitter-cpp` vs C grammar; `preprocess` maps `.cpp` to `cpp`.
4. Whether default CI should add a second job `uv sync --extra semantic` or only skip-marked tests on the extra-free job.

## 3. Implementation Approach Options

### Option A: Extend `ir.py` / `engines.py` only

Put extra pins in `pyproject.toml`, implement API parse + CST walk inside `ir.py`, tighten `tree_sitter_available()`.

- **Pros:** Few files; `parse_file` stays the seam.
- **Cons:** `ir.py` is already ~277 lines (Python ast + dead CLI). A walker + language table will bloat it and mix packaging probe with extract.

### Option B: New components only

New `semantic/cst.py` + `semantic/extra.py`; leave `ir.py` as Python ast; overlay calls a new entrypoint.

- **Pros:** Clean extra guard.
- **Cons:** Two parse entrypoints; easy to fork `parse_file` consumers.

### Option C: Hybrid (recommended for design)

- **New:** `semantic/cst.py` — one walker: tree-sitter `Node` → `Bind` / `CallSite` / `FunctionIR` using a node-kind map.
- **New or thin:** extra guard modeled on `harness_ext` (`has_semantic_extra`, lazy grammar load, never import wheels at module load).
- **Extend:** `pyproject.toml` `[project.optional-dependencies] semantic = [...]`; mypy override `tree_sitter*`; pytest marker `semantic`; CI extra-free job unchanged; optional second job or skip.
- **Extend:** `parse_file` prefers extra CST when a grammar loads; else Python ast; else `language_unsupported`. **Delete or stop calling** `parse_tree_sitter_cli` as a success path (Req 4.3).
- **Do not extend:** `taint.py`, `overlay.py`, facts, gate, pair catalog.

**Trade-offs:** Extra files, but `ir.py` shrinks (drop dead CLI), taint stays language-agnostic, extra follows an existing packaging seam.

## 4. Effort and Risk

- **Effort: M (3–7 days).** Extra pins + walker + dual tests. Overlay/taint reuse. Not a new adjudicator.
- **Risk: Medium.** Native wheels and grammar ABI pins; CST node-name drift across languages; CI without extra must stay green. Mitigate with skip markers and a version pin table in design.

## 5. Design-phase recommendations

- Prefer **Option C**.
- Treat `FileIR` as frozen contract; do not add dispositions.
- Decide probe semantics: `tree_sitter_available` should mean “can produce FileIR for this language”, not “CLI binary exists”.
- Carry research items 1–4 into design (ABI pins, node-kind map, cpp package, CI job vs skip).
- Do not pull Joern, pair harvest, or CWE-121 into this spec.

---

## Summary (design discovery)

- **Feature**: tree-sitter-overlay-extra
- **Discovery Scope**: Extension of `parse_file` / overlay IR; optional extra packaging
- **Key Findings**:
  - Official PyPI wheels: `tree-sitter` (0.26), `tree-sitter-python`, `tree-sitter-javascript` (0.25), `tree-sitter-c` (0.24.x), `tree-sitter-cpp` (0.23.4), `tree-sitter-java`. API is `Parser(Language(mod.language()))`; `build_library` is gone.
  - `FileIR` is the only overlay seam; taint does not need language visitors.
  - Host CLI presence must not count as a successful overlay parse (Req 4.3).

## Research Log

### PyPI ABI and load API

- **Context**: Pin wheels that work on Python 3.11+ without compiling grammars in CI.
- **Sources Consulted**: https://pypi.org/project/tree-sitter/ ; https://pypi.org/project/tree-sitter-javascript/ ; https://pypi.org/project/tree-sitter-cpp/ ; py-tree-sitter 0.23 release notes (Language capsule, Parser constructor).
- **Findings**: Grammars ship abi3 wheels. Load with `Language(tree_sitter_<lang>.language())` then `Parser(language)`. Do not use `Language.build_library`.
- **Implications**: Extra lists core + five grammar packages. mypy ignores `tree_sitter*`.

### Probe vs grammar

- **Context**: `tree_sitter_available()` is true when CLI is on PATH with zero grammars.
- **Findings**: CLI parse cannot populate `FileIR` without a walker. Extra Python API is the product parse.
- **Implications**: Split `has_semantic_extra()` from per-language `grammar_for`. Remove CLI as a success path.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks | Notes |
|--------|-------------|-----------|-------|-------|
| A Extend ir.py only | Walker + extra inside ir.py | Few files | Bloats 277-line module | Rejected |
| B New entrypoint | Overlay calls cst.py directly | Clean extra | Forks parse_file | Rejected |
| C Hybrid | Extra guard + cst walker; parse_file dispatch | Matches harness_ext; FileIR frozen | Node-kind table | **Selected** |

## Design Decisions

### Decision: Adopt official grammar wheels, build one walker

- **Context**: Avoid per-language AST visitors (Req 4).
- **Alternatives**: tree-sitter CLI sexp; py-tree-sitter-languages (unmaintained); hand-rolled JS/C parsers.
- **Selected**: `openultrasast[semantic]` = `tree-sitter` plus python/javascript/c/cpp/java grammar packages. One CST walk keyed by a node-kind map.
- **Rationale**: Wheels are MIT, maintained, match in-scope languages. Taint stays language-agnostic.
- **Trade-offs**: Native wheels in the extra; ABI pins. Core install stays empty.
- **Follow-up**: Verify Parser constructor against the pinned `tree-sitter` minor at implement time.

### Decision: Extra-free CI stays default; extra-on is a second job plus skip marker

- **Context**: Req 6 dual matrix.
- **Selected**: pytest `semantic` marker skips when extra absent. GitHub Actions adds a job `uv sync --extra semantic --group dev` that runs marked tests. Default `checks` job unchanged.
- **Rationale**: Default CI must not fail without wheels. Extra-on tests must actually run somewhere.
- **Trade-offs**: Two pytest invocations in CI.

### Decision: has_error implies parse_failed

- **Context**: tree-sitter is error-tolerant; Req 3.4 wants fail-closed on syntax errors.
- **Selected**: If `tree.root_node.has_error` (or ERROR children), return `FileIR(parse_ok=False, reason=parse_failed)`.
- **Rationale**: Partial IR would invite false demote.

## Synthesis

- **Generalization**: One `parse_file` dispatch; extra is a grammar source, not a second overlay.
- **Build vs adopt**: Adopt tree-sitter wheels; build only the FileIR projection (binds/calls).
- **Simplification**: No CLI sexp walker; no second parse API; no taint/overlay changes.

## Risks & Mitigations

- Grammar ABI mismatch — pin extras together; extra-on CI job catches import/parse failure.
- Node-type drift — table in cst.py; tests assert JS eval and C printf on real trees.
- CLI still on PATH — must not set parse_ok.

## References

- https://pypi.org/project/tree-sitter/
- https://github.com/tree-sitter/py-tree-sitter/releases
- `src/openultrasast/harness_ext.py` extra guard pattern

