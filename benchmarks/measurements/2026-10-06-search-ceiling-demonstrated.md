# Search-with-proof: first `demonstrated` (ceiling proof), 2026-10-06

First end-to-end `demonstrated` verdict for the search-with-proof verifier. No model, no cluster, $0.
Run locally in-process via `openultrasast.search.verify.verify` (non-task bubblewrap lane, userns, node v18.19.1).

- Pair: glance (jarofghosts/glance), family **path**, index.js `Glance$serveRequest`.
- Verdict: **demonstrated** — owned effect in 3/3 affected runs, 0/3 safe runs (zero false proof on the fixed side).
- Vulnerable side: canary observed 3/3 (parent traversal reaches the out-of-root nonce file; app reflects it).
- Fixed side: 0/3 (the fix commit's parent-escape guard returns 403; the traversal cannot escape).
- Wall ~65 s for both sides x 3 runs; ready ~2 s/side.

## What this proves
The execution harness, the path oracle, and the differential verifier are correct and CAN produce a
`demonstrated` verdict on a real third-party app. The method's ceiling is reachable. Every prior pilot
`inconclusive` on this pair was an instrument artifact, not a method verdict.

## Two defects that had masked this (both isolated, neither is the method)
1. **Broken build.** `filed@0.1.0` depends on an unpinned `mime >=1.2.6`; the checkout's regenerated
   lockfileVersion-3 pins `mime@4.1.0`, where `.lookup()` was removed. glance crashes serving ANY file
   (`TypeError: mime.lookup is not a function`). Directory listing (readiness GET /) survives; the first
   file serve kills the process, so the nonce never reaches the response. Fixed here by installing a
   compatible `mime@1.6.0` before the run.
2. **Wrong demo target.** The stored agent demo traversed to a filename that is not the canary, so it
   404s even on the vulnerable side. The path oracle is the only owned oracle that hides its target from
   the demo author. The corrected demo targets the conventional `canary` file one level above the served
   root (same convention the known-good probe uses).

## Reproduction
Demo schema + driver stored (gitignored) at `benchmarks/search/private/ceiling-proof-2026-10-06/`.
Prepared checkouts need their npm symlinks stripped (the verifier refuses links) and a compatible
`mime@1`. Payloads stay on disk per the classifier-safety note; never echoed.

## Follow-on for honest qualification at scale (not covered by this $0 proof)
- Keystone: positive-control in `verify.py` so a broken app yields `could_not_run`, never `inconclusive`.
- Build-repro: distrust generated npm locks; pin/override incompatible transitive deps; audit all 20 pairs.
- Demo-authoring: document the path-oracle target convention so the search AGENT can author a hitting demo.
