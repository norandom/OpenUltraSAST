# Implementation Plan

- [x] 1. Foundation: vfc catalog load and slice command
- [x] 1.1 Load a vfc catalog and accept slice vfc on the pairs command
  - Default pair catalog load includes a vfc catalog file the same way it already includes the sast catalog.
  - The pairs command accepts slice `vfc` in addition to all, local, github, and sast.
  - Dataset pointers name OpenSSL, Firefox/gecko-dev, and Chromium without vendoring those trees.
  - An empty or seed-ready vfc catalog file exists so load does not skip the slice by omission.
  - Observable: `ousast pairs --slice vfc --json` exits 0 and the loaded slice set can contain `vfc`.
  - _Requirements: 1.1, 1.3, 7.2_
  - _Boundary: VfcCatalog_

- [x] 2. Core: reviewed seed pairs
- [x] 2.1 Vendor the OpenSSL Heartbleed function pair
  - Isolated `tls1_process_heartbeat` before and after the public Heartbleed fix, same relative path.
  - Provenance header and catalog row include repo, commit, parent, public commit URL, CVE-2014-0160, and license.
  - Expected CWE/sink/evidence are stated; memcpy remaining after the fix is an accepted honesty leak, not a reason to change inventory rules.
  - Observable: catalog load yields a vfc pair whose name identifies OpenSSL and whose vuln and fixed files exist.
  - _Requirements: 1.2, 1.4, 2.1, 2.2, 2.3, 2.4, 6.1, 6.2, 6.3, 6.4_
  - _Boundary: SeedExcerpts_
  - _Depends: 1.1_

- [x] 2.2 Vendor the Firefox libmar function pair
  - Isolated `mar_insert_item` before and after the public CVE-2020-15667 commit, same relative path.
  - Provenance records the mozilla-central revision and public commit URL (hg or Phabricator is acceptable; MFSA-only is not).
  - License is MPL-2.0; expected CWE/sink/evidence are stated.
  - Observable: catalog load yields a vfc pair whose name identifies Firefox and whose files exist.
  - _Requirements: 1.2, 1.4, 2.1, 2.2, 2.3, 2.4, 6.1, 6.2, 6.3, 6.4_
  - _Boundary: SeedExcerpts_
  - _Depends: 1.1_

- [x] 2.3 Vendor the Chromium FileReader function pair
  - Isolated `ArrayBufferResult` before and after the public CVE-2019-5786 commit, same relative path.
  - Provenance header and catalog row include chromium repo, commit, parent, commit URL, CVE, and BSD-3-Clause.
  - UAF-without-inventory-sink is an accepted honesty miss; do not vendor exploit HTML.
  - Observable: catalog load yields a vfc pair whose name identifies Chromium and whose files exist.
  - _Requirements: 1.2, 1.4, 2.1, 2.2, 2.3, 2.4, 6.1, 6.2, 6.3, 6.4_
  - _Boundary: SeedExcerpts_
  - _Depends: 1.1_

- [x] 3. Harvest without megarepos
- [x] 3.1 (P) Add a maintainer harvest procedure that extracts one function
  - A recipe names parent commit, fix commit, path, function, CVE, and license; advisory-only recipes are rejected.
  - Harvest fetches blobs over HTTP and writes provenance-headed excerpts; it does not clone mozilla-central, gecko-dev, or Chromium.
  - FixFox and other embargoed dumps are not referenced as fetch sources.
  - Function extract is unit-tested on a local string so CI stays offline.
  - Observable: harvest extract on a fixture function round-trips the function body; pytest does not perform a live fetch.
  - _Requirements: 1.4, 5.1, 5.2, 5.3, 5.4, 5.5, 7.3_
  - _Boundary: HarvestTool_
  - _Depends: 1.1_

- [x] 4. Integration: overlay versus inventory scoreboard
- [x] 4.1 Score vfc with overlay primary and inventory sidecar
  - vfc pairs use the overlay pair path with inventory fallback when overlay does not adjudicate.
  - Machine-readable pairs output includes `scorers.vfc.overlay` and `scorers.vfc.inventory`.
  - Primary `per_slice.vfc` matches the overlay scorer.
  - Pair gate fail reasons stay local-only; vfc Youden is not a merge condition.
  - Observable: `ousast pairs --slice vfc --json` contains both scorer objects and the OpenSSL, Firefox, and Chromium pair names.
  - _Requirements: 3.3, 3.4, 4.1, 4.2, 4.3, 4.4, 7.2_
  - _Boundary: DualScorer_
  - _Depends: 1.1, 2.1, 2.2, 2.3_

- [x] 5. Validation: honesty gates and offline tests
- [x] 5.1 Prove vfc is testable and is not a smoke or merge gate
  - Default catalog load sees slice `vfc` and every vfc file on disk.
  - vfc pair names are absent from the stage-1 detection fixture list.
  - Pair efficiency gate still passes on local 100% with vfc present.
  - Tests do not require 100% vfc pair_correct or a Youden floor.
  - Extra-free evaluation still completes.
  - Observable: extra-free pytest covering catalog load, gate pass, and vfc JSON is green.
  - _Requirements: 3.1, 3.2, 3.4, 5.5, 7.1, 7.3, 7.4_
  - _Boundary: VfcTestMatrix, PairGatePolicy_
  - _Depends: 4.1_

## Implementation Notes

- Seed commits: OpenSSL `96db9023b881d7cd9f379b0c154650d6c108e9a3` (parent `0d7717fc9c83dafab8153cbd5e2180e6e04cc802`); Firefox hg `b79b6cc78248eea7fda10bfb76aa273c19c9fa65` (parent `0c0f777161a9499dd149853ff62d356f75d16c2a`); Chromium `ba9748e78ec7e9c0d594e7edf7b2c07ea2a90449` (parent `9f3fccdba567f30ea39b08f57d8d5b49cd832b4a`).
- Do not retune `c-unsafe-memory-copy` to make Heartbleed or MAR pair_correct.
- Do not clone mozilla-central; do not vendor FixFox.
