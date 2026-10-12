# BUG: `taint.sc` single-query path broken by exec-signature skew

Filed: 2026-10-12 · Repo HEAD at filing: `7ab5c2a` · Severity: **high (silent zero)** · Status: **FIXED (2026-10-12)**

## Resolution (2026-10-12)

Fixed via **option 1** (filter params to the declared signature) in `src/openultrasast/cpg/backend.py`:

- New `_declared_exec_params(source)` parses the `@main def exec(...)` parameter names from a shipped script
  (brace-aware, tolerant of an unfindable signature → empty set → "do not filter").
- New memoised `JoernBackend._declared_params(query)` reads+caches a script's declared names.
- `JoernBackend.query()` now drops any param the script does not declare before building the `--param` list
  (disposable route) and the in-session named-arg call (session route). This is faithful, not lossy: the
  single-request branch of `taint.sc` (line 1542) calls `rowsFor(...)` with top-level params only and lets
  `fixedOrigin`/`originAnchors`/`quotedSanitizers`/`guards`/`fieldParameterSources` default — it never could
  consume them. The batch path keeps carrying them as JSON the script parses itself.
- No-op for `config`/`dominance`: their own `request_params` emit only params their `.sc` declares (verified),
  so nothing is dropped. Only `taint` sheds the 5 extras.

**Verified end-to-end** (patched backend mounted into the replay image, single-query path on banks): the
queries now RUN (no `cpg query taint failed`); baseline = 0 findings, fixed search (annotation) = 2 scored
`path`/`model_entailed` findings (`from_prompt_path` → `prompt_file.write_text(prompt.raw)` L45; `_scan` →
`self._index_path.write_text(...)` L155). Regression test:
`tests/test_cpg_backend.py::test_a_single_query_passes_only_params_the_script_declares` (fake runner, no Joern
— asserts the 5 undeclared params never reach the command line and the query parses).

## Summary

Any call on the **single-query** taint path — `cpg.run("taint", request_params(...))` — fails on **both**
of its sub-routes, returns `None`, and is read upstream as "no flows / clean". `request_params()` emits five
keys that `taint.sc`'s `@main def exec(...)` does not declare, and the single-query dispatch passes every
param straight to the script. The **batch** path (`run_batch` → `requestsFile` JSON) is unaffected, which is
why the engine-on scans ran while the single-query MVP did not.

This is exactly the failure shape AGENTS.md warns about: a tool that could not read/execute its input reports
a plausible zero that is indistinguishable from a clean result.

## Mechanism

`request_params()` (`src/openultrasast/model/taint.py`) always emits, among others:

- `fieldParameterSources` (line 54)
- `fixedOrigin` (line 65)
- `originAnchors` (line 66)
- `quotedSanitizers` (line 67)
- `guards` (line 68)

`taint.sc`'s signature (`src/openultrasast/cpg/queries/taint.sc:41` `@main def exec(...)`) declares **none**
of those five. Its 19 params are: `cpgFile, sources, sinks, sanitizers, function, file, callDepth,
boundedSinks, parameterSources, fieldSources, evidenceOnly, hookCallbacks, dispatchApply, dispatchValue,
contextFilter, contextPaths, requests, requestsFile, trace`.

`backend.query()` (`src/openultrasast/cpg/backend.py:1266`) dispatches a single query two ways, **both** of
which choke on the undeclared keys:

- **Disposable / CLI route** (lines 1276–1278): appends `--param {key}={value}` for every param. joern errors
  `Unknown arguments: --fixedOrigin --guards --quotedSanitizers --originAnchors --fieldParameterSources`
  (and, as a knock-on, `Missing argument: --cpgFile`). Observed verbatim via `banks_debug.py` on 2026-10-12.
- **Session route** (lines 1321–1326): defines `def ousast_taint(...)` by renaming `@main def exec(` and then
  calls `ousast_taint(key = value, ...)` with named args. The same five keys are not parameters of that
  method → the Scala named-arg call fails to compile. (By construction; the rename preserves the exact
  `exec` parameter list.)

Why the batch path survives: `run_batch` writes the per-request params **inside** the `requestsFile` JSON
object, and `taint.sc` parses that JSON itself (`requestsJson`, taint.sc:67). The extra fields ride as JSON
keys, never as `exec` arguments, so they are tolerated.

## Blast radius

Broken (single-query taint):

- `taint._usable_flows` (`taint.py:124`) → `verdicts()` (`taint.py:131`) → `verdict()` (`taint.py:99`).
- `pipeline.scan_region` dispatches taint families to `taint_verdict` (`pipeline.py:121`) → so **per-region
  single-query taint via `scan_region` is dead** whenever the disposable or session route is taken.

Unaffected:

- The push/scan **batch** path: `scan.py` uses `run_batch("taint", …)` (scan.py:1259, 1264, 1387). This is
  why the engine-on pilot produced results.
- `config` and `dominance` single-queries (`config_value.py:46`, `dominance.py:54`) — their `.sc` signatures
  are presumed to match what their specs emit (confirm separately; not exercised here).

Open question to close: enumerate every production path that reaches `scan_region`/`verdict()` taint rather
than the batch route, to state whether any shipped push/replay flow silently loses taint flows today, or
whether the single-query path is only hit by pair measurements and ad-hoc harnesses.

## Evidence

- `benchmarks/measurements/2026-10-12-banks-fixed-search-mvp/` — the batch path works (11 flow rows,
  `write_text` sinks); the v1 single-query attempt returned 0/0 on `cpg query taint failed`.
- Raw joern error captured by `banks_debug.py` (scratchpad): `Missing argument: --cpgFile; Unknown
  arguments: --fixedOrigin --guards --quotedSanitizers --originAnchors --fieldParameterSources`.

## Suggested fix (not yet applied)

Pick one, lowest-risk first:

1. **Make `backend.query()` filter params to the script's declared signature** before building `--param` /
   named-arg lists (parse the `@main def exec(` arg names once, intersect). Fixes every current and future
   signature skew for all single-query scripts, symmetrically with how the batch path already tolerates
   extras. Preferred.
2. Add the five params to `taint.sc`'s `exec` signature as ignored passthroughs (mirrors batch semantics but
   duplicates the JSON parsing already in the script; narrower).
3. Route `_usable_flows` through `run_batch` with a one-element request (makes single-query taint share the
   tolerant path; changes the call shape upstream).

Add a regression test under the joern-gated suite: `cpg.run("taint", request_params(path_spec, …))` must
return a parsed payload (not `None`) on a fixture CPG, asserting the instrument actually executed.
