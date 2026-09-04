# Research & Design Decisions

## Summary

- **Feature**: `real-world-vfc-slice`
- **Discovery Scope**: Extension of the existing pair catalog and pair eval CLI
- **Key Findings**:
  - Pair eval already concatenates `benchmarks/pairs/catalog.toml` with `sast/catalog.toml`. A third file `vfc/catalog.toml` is the smallest seam.
  - CLI `--slice` choices are a closed set (`all`, `local`, `github`, `sast`). `vfc` must be added there and in tests that assert slice names.
  - `sast` already scores overlay with inventory fallback when nothing is promoted or demoted. `vfc` should use that path as the primary scorer and add a second inventory-only figure for the honesty dashboard.
  - `pair_gate` evaluates the full catalog but fails CI only on `local` 100%. Adding vfc pairs does not change the fail condition if names stay out of `LANGUAGE_MANIFESTS`.
  - Seed commits with public VCS snapshots exist: OpenSSL Heartbleed (`tls1_process_heartbeat`), Firefox libmar (`mar_insert_item`, CVE-2020-15667), Chromium FileReader (`ArrayBufferResult`, CVE-2019-5786). All three keep a sink-shaped call after the fix, so overlay/inventory may LEAK — that is the dashboard, not a 100% gate.
  - mozilla-central / gecko-dev must not be cloned. Phabricator and GitHub raw blobs are enough to extract one function. FixFox stays embargoed.

## Research Log

### Existing pair catalog and scoring

- **Context**: Brownfield extension; must not invent a second eval engine.
- **Sources Consulted**: `src/openultrasast/pairs.py`, `cli.py`, `pair_gate.py`, `tests/test_pair_corpus.py`, `benchmarks/pairs/catalog.toml`, `benchmarks/pairs/sast/catalog.toml`, `benchmarks/pairs/README.md`
- **Findings**:
  - `PairCase.slice` is a free string in the catalog loader; the closed set lives only in argparse and tests.
  - Overlay pair eval is gated on `case.slice == "sast"`.
  - GitHub pairs already use provenance comments plus catalog fields (`repo`, `commit`, `commit_url`, `cve`, `license`).
  - Pair names must not appear in `LANGUAGE_MANIFESTS`.
- **Implications**: Add `vfc` as a concatenated catalog; extend the overlay branch to `sast` **or** `vfc`; keep the gate local-only.

### Harvestable public commits (OpenSSL, Firefox, Chromium)

- **Context**: User asked for those three projects and a labeled corpus that can actually be tested.
- **Sources Consulted**:
  - OpenSSL `96db9023b881d7cd9f379b0c154650d6c108e9a3` (parent `0d7717fc9c83dafab8153cbd5e2180e6e04cc802`), `ssl/t1_lib.c` `tls1_process_heartbeat`, CVE-2014-0160
  - Firefox hg `b79b6cc78248eea7fda10bfb76aa273c19c9fa65` (parent `0c0f777161a9499dd149853ff62d356f75d16c2a`), `modules/libmar/src/mar_read.c` `mar_insert_item`, CVE-2020-15667 / Bug 1653371; Phabricator raw diff
  - Chromium `ba9748e78ec7e9c0d594e7edf7b2c07ea2a90449` (parent `9f3fccdba567f30ea39b08f57d8d5b49cd832b4a`), `FileReaderLoader::ArrayBufferResult`, CVE-2019-5786
  - Rejected: CVE-2019-11730 (SOP/file URI policy, not a sink pair); FixFox (embargoed to 2030); MFSA text without a commit
- **Findings**:
  - Heartbleed fix adds a record-length check; `memcpy(bp, pl, payload)` remains. Inventory `c-unsafe-memory-copy` will fire on both sides (LEAK) until CWE-121 semantics exist.
  - Firefox fix is `int namelen` → `uint32_t namelen`; `memcpy(item->name, name, namelen + 1)` remains. Same LEAK class.
  - Chromium fix copies the ArrayBuffer on partial results (UAF). No memcpy/eval sink; expected MISS on inventory and overlay. Still a labeled pair.
  - GitHub raw and Phabricator `?diff=1` return the function text without cloning.
- **Implications**: Seed three reviewed pairs. Tests assert presence and that the slice **runs**, not that pair_correct is 100%. Memory-safety pairs are allowed as known leaks (Req 6.3).

### Dataset pointers versus vendored dumps

- **Context**: `datasets.toml` already lists CVEfixes, MoreFixes, SVEN, CWE-Bench-Java. Roadmap asked for Firefox/Chromium/OpenSSL pointers.
- **Findings**: Pointers are metadata only. CI must stay offline on vendored excerpts.
- **Implications**: Add dataset rows for OpenSSL, gecko-dev / mozilla-firefox/firefox, and Chromium. Do not fetch dumps in tests.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| Concatenate a `vfc` catalog like `sast` | Third TOML file, same `[[pair]]` schema | Matches existing loader; no new types | CLI choices and tests must be updated | **Selected** |
| Stuff vfc rows into `catalog.toml` | One file | Fewer paths | Mixes local/github with large-project VFCs | Rejected; sast already split |
| New eval package | Separate scorer | Clean isolation | Duplicates pair eval | Rejected |
| Clone megarepos in CI | Scan real trees | Maximum fidelity | Multi-GB, scrubbed commit messages, not isolated | Explicitly out of scope |

## Design Decisions

### Decision: Concatenated `vfc` catalog, overlay primary, inventory sidecar

- **Context**: Need a labeled corpus that is offline, isolated, and honest about overlay versus regex.
- **Alternatives Considered**:
  1. Inventory-only like `github` — misses the overlay question the user is evolving.
  2. Overlay-only like `sast` without a sidecar — cannot see whether overlay helped or hurt.
  3. Dual scoreboard with overlay primary and inventory sidecar — **selected**.
- **Selected Approach**: `slice = "vfc"` uses the overlay pair path (inventory fallback when unadjudicated). `PairEvalResult.scorers["vfc"]` holds both `overlay` and `inventory` metrics. Pair gate still fails only on `local`.
- **Rationale**: Reuses `sast` overlay machinery; satisfies Req 4 without making Youden a merge gate.
- **Trade-offs**: Pair gate runtime grows by three small overlay scans. Acceptable.
- **Follow-up**: Do not retune memcpy rules to force these pairs to PASS.

### Decision: Maintainer harvest script, vendored seed, no CI fetch

- **Context**: Grow the catalog later without cloning mozilla-central.
- **Selected Approach**: `benchmarks/pairs/vfc/harvest.py` plus `recipes.toml`. CI never runs harvest. Seed files are committed excerpts with provenance headers.
- **Rationale**: Req 5 and Req 7 (offline testability).
- **Trade-offs**: Harvest needs network when a maintainer grows the set; tests mock extraction locally.

### Decision: Public hg counts as a version-control commit

- **Context**: Firefox canonical history is hg.mozilla.org; gecko-dev git SHAs are not the hg SHAs; GitHub 422s on hg identifiers.
- **Selected Approach**: Record the hg revision and Phabricator/hg URL. Dataset pointers still list gecko-dev and mozilla-firefox/firefox.
- **Rationale**: Brief forbids MFSA-without-commit, not hg. The MAR fix is a public VCS snapshot.
- **Follow-up**: If a git SHA is later mapped, add it as an extra catalog field without changing the excerpt.

## Synthesis

- **Generalization**: `vfc` is another honesty slice, not a new product. Overlay-versus-inventory is a report field, not a new engine.
- **Build vs adopt**: Adopt pair catalog schema, overlay eval, provenance comment style. Build only harvest extract + dual scoreboard payload.
- **Simplification**: No Joern, no megarepo, no 90% gate, no rule changes to chase Youden on three memory/UAF pairs.

## Risks & Mitigations

- Overlay/inventory LEAK on Heartbleed and MAR memcpy-after-fix — document as known; tests must not assert PASS.
- Chromium UAF is a MISS — still required so the corpus is not only memcpy.
- `pair_gate` currently scans the full catalog; three extra pairs are small. If the catalog grows, gate should keep evaluating local-only for the fail condition (already true) and may later skip overlay slices for speed.
- License: OpenSSL (OpenSSL License / SSLeay), Firefox MPL-2.0, Chromium BSD-3-Clause — headers must state them.
- gecko-dev is archived; harvest should accept hg.mozilla.org and github.com/chromium/chromium / openssl/openssl as hosts.

## References

- [OpenSSL Heartbleed fix](https://github.com/openssl/openssl/commit/96db9023b881d7cd9f379b0c154650d6c108e9a3) — CVE-2014-0160
- [Firefox MAR heap overflow](https://bugzilla.mozilla.org/show_bug.cgi?id=1653371) — CVE-2020-15667, hg `b79b6cc78248`
- [Chromium FileReader UAF](https://github.com/chromium/chromium/commit/ba9748e78ec7e9c0d594e7edf7b2c07ea2a90449) — CVE-2019-5786
- `.kiro/specs/real-world-vfc-slice/brief.md`
- `.kiro/steering/roadmap.md`
