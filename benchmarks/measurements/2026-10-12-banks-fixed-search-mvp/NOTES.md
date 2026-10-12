# Banks fixed-search MVP — "no wrong targets, only wrong searching"

Date: 2026-10-12 · Host: clean (local docker, replay-task image) · Repo HEAD: `7ab5c2a`
Target: `masci/banks` @ `5e7093c9b3c2bbe2e0bc281f5a3602bbdabf00b9` (the "library" that gave the static engine ZERO path findings in the engine-on pilot).

## Thesis under test

The governing principle (maintainer, 2026-10-12): we have a **search-with-proof** architecture, so there
are **no wrong targets, only wrong searching**. Banks produced zero path-family findings in the engine-on
pilot not because it is a wrong target but because the SEARCH was not annotated for it:

1. the **source** — `prompt.name`, a function parameter — is not recognised (`entry:false`, so
   `_parameters_are_input` returns False and parameters are not treated as untrusted); and
2. the **sink** — `Path.write_text` / `Path.read_text` at a joined path — is not in the shipped
   path-family sink list.

Inject exactly those two annotations (what a per-target LLM steer would supply) and check whether the engine
now traces `prompt → path-join → write_text` where the shipped search produced nothing.

## Instrument (verified before believing the number)

Per AGENTS.md "verify the instrument": the first MVP attempt (single-query `cpg.run("taint", …)` path)
returned 0/0, but that was an **instrument failure**, not a result — every query died on
`cpg query taint failed` (see the filed bug `taint-sc-single-query-signature-skew.md`). This record uses the
**batch path** (`cpg.run_batch("taint", {requestsFile JSON})`), the same invocation the real engine-on scans
use. Confirmed it ran: CPG built, `run_batch` available, and the fixed search returned **concrete sink
strings** (`prompt_file.write_text(prompt.raw)`) — the opposite of the v1 failure's empty rows. Harness:
`banks_mvp2.py`. Raw output: `results.out`.

## Setup

Same target, same CPG; only the search changes.

- Functions probed: `from_prompt_path`, `set`, `_load`, `_scan` in `src/banks/registries/directory.py`.
- BASELINE = shipped `path` taint spec, `parameter_sources=False`.
- FIXED = shipped spec + `write_text`/`read_text` added to path sinks, `parameter_sources=True`.

## Result — flow-row counts

| Function          | Baseline (shipped)   | Fixed search (annotation ON)                                  |
|-------------------|----------------------|---------------------------------------------------------------|
| `from_prompt_path`| 1 row (`sink=None`)  | **4 rows** — incl. `sink=prompt_file.write_text(prompt.raw)  source=prompt` |
| `set`             | 1 row (`sink=None`)  | 1 row (`sink=None`)                                           |
| `_load`           | 1 row (`sink=None`)  | 2 rows (`sink=None`)                                          |
| `_scan`           | 2 rows (`sink=None`) | **4 rows** — incl. `sink=self._index_path.write_text(...)`    |
| **Total**         | **5**                | **11**                                                        |

### What the counts actually mean (honest read)

The raw totals (5 vs 11) **overstate** the effect. All 5 baseline rows have `sink=None, source=None` — they
are census/evidence rows, **not** resolved source→sink path flows. That is consistent with the engine-on
pilot producing zero path-family findings on banks. The result that carries the thesis is the
**resolved-flow delta**:

- **Baseline: 0 resolved `prompt → write_text` flows.**
- **Fixed search: the engine resolves `prompt → path-join → prompt_file.write_text(prompt.raw)` in
  `from_prompt_path`** (`source=prompt`), plus a second `write_text` sink in `_scan`. These appear **only**
  with the two injected annotations.

## Verdict

On the exact target that gave the static engine zero, the engine traces the real flow once the search is
corrected. It needed exactly **two** annotations: the parameter-as-source and the missing file-write sink.
This demonstrates **"no wrong targets, only wrong searching"** on a concrete case, and names the precise
inputs the per-target LLM steer (DSPy-optimised, framework-seeded) must learn to supply.

## Caveats (not papered over)

1. One `from_prompt_path` row shows `source=path` rather than `prompt` — the parameter-source annotation
   fires broadly, not yet pinned to the untrusted parameter. A precision knob for the steering loop, not a
   blocker.
2. This shows the engine *traces* the flow; it is **not** the runtime differential proof. Proving
   attacker-reachability remains the async BLOCK lane (search-with-proof verifier).
3. The single-query taint path is broken (filed separately); this record uses the batch path deliberately.
