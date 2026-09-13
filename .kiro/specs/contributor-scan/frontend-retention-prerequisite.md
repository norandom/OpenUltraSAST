# Frontend input retention prerequisite

Date: 2026-09-13. Status: approved by the maintainer ("approved"); task 2.18 verified complete after independent review.
Owner: contributor-scan. Blocks pre-push-safety-net task 3.4.

## Confirmed problem

The partition adapter supplies readable, original first-party JavaScript files,
including tests, but Joern 4.0.625 silently removes tests during graph generation.
The packaged probe read `server/api.js` (51 bytes) and `tests/probe.js` (41 bytes)
from the physical frontend input. The resulting graph contained only the server
file and its handler. Both autodetection and direct `jssrc2cpg` invocation failed
the same assertion. This is separate from the earlier PHP closure/query failure.

Two upstream layers filter tests:

- Pinned ASTGen 3.50.1 excludes test directories independently of user exclusions:
  [defaults](https://raw.githubusercontent.com/joernio/astgen-monorepo/javascript-astgen/v3.50.1/javascript-astgen/src/Defaults.ts)
  and [application](https://raw.githubusercontent.com/joernio/astgen-monorepo/javascript-astgen/v3.50.1/javascript-astgen/src/FileUtils.ts).
- Joern also unconditionally filters `.test.js`, `.spec.js`, `.mock.js` and `.e2e.js`:
  [pinned frontend implementation](https://raw.githubusercontent.com/joernio/joern/v4.0.625/joern-cli/frontends/jssrc2cpg/src/main/scala/io/joern/jssrc2cpg/utils/AstGenRunner.scala).

Installed help and versioned configuration provide no supported inclusion override.
Failure evidence is retained in
`benchmarks/measurements/2026-09-13-partition-retention-blocker.json`.
An independent Kiro debug investigation returned `STOP_FOR_HUMAN`: a foundation
prerequisite is missing from the approved downstream implementation sequence.

## Approved prerequisite

Establish a reproducible frontend input policy that retains explicitly supplied
first-party JavaScript source, including test directories and filename patterns.
The foundation owns any versioned dependency adaptation required in both ASTGen
and jssrc2cpg. Record the exact sources, checksums, build recipe and invocation
policy; a frontend upgrade or patch must preserve the existing native PHP and
JavaScript engine regressions. Prefer a supported upstream inclusion mechanism if
one becomes available; the pinned version currently has none.

Keep source paths, bytes, imports and graph semantics intact. Do not rename test
files, split them into disconnected graphs, restore vendor code, or weaken the
retention criterion to make a smoke pass. Continue treating tests as unshipped
ranker candidates. Report actual frontend omissions as incomplete coverage.

## Acceptance and handoff

1. A packaged census proves exact file and method nodes for ordinary first-party
   source, `tests/` contents and `.test.js`, `.spec.js`, `.mock.js`, `.e2e.js` files.
   The fixture must read and print the original input byte counts first.
2. Declared vendor and node_modules paths and their unique methods remain absent.
3. Existing native PHP/JavaScript graph, query, context and deadline regressions
   pass; unsupported constructs still produce explicit coverage limits.
4. Rebuild the image and rerun `ops/smoke_partitions.py`, then independently review
   and verify pre-push task 3.4 before checking it off or starting dependent work.

The maintainer approved this prerequisite and its dependency adaptation on 2026-09-13.
Task 2.18 owns reproducible implementation and verification; downstream task 3.4
remains incomplete until its own review passes. Capability admission remains later work.
