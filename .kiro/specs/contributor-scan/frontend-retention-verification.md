# Frontend retention verification

Date: 2026-09-13. Task: contributor-scan 2.18. Status: VERIFIED (TASK), independent review APPROVED.

The maintainer approved the frontend-retention prerequisite after real graph
inspection showed that supplied JavaScript tests were missing. Verification must
establish retained source paths and method nodes, vendor exclusion, unchanged
ordinary engine behavior and explicit adaptation identity.

The approved implementation adapts the two pinned upstream filters, preserving
original source bytes and paths. The existing ranker still marks tests unshipped;
the frontend inclusion policy does not select or admit findings. The installed
manifest distinguishes this adaptation from stock Joern 4.0.625 for future graph
compatibility checks.

Completion requires independent review and a passing packaged census, including
the test-directory fixture and four filename suffixes. A test-disabled control
must reproduce the former omission. Native PHP/JavaScript graph and change-context
regressions must pass before downstream task 3.4 resumes.

## Evidence

`benchmarks/measurements/2026-09-13-frontend-retention-smoke.json` retains the
installed manifest, source/output integrity checks and complete runtime results.
The graph includes all six JavaScript files (255 source bytes) and two PHP files
(97 bytes), with exact test method witnesses and no vendor nodes. Disabling the
policy reproduces the original test omission with exit 1. The mixed scan uses
one selected question across both supported frontends and names unsupported Go.

The PHP and JavaScript cross-file change-context regressions both complete with
one finding at the unchanged helper. The shared lab allowance is 900 seconds;
the mixed runtime took 260.93 seconds while concurrent checks were running. These
are controlled runtime checks, not hook latency measurements.

The independent full suite passed 1,141 tests with nine skipped in 125.68 seconds.
Ruff, formatting (229 files), mypy (109 files) and diff checks passed. Independent
installer checks verified an offline idempotent skip and corruption rejection.
The original-backend RED reproduction is retained and explicitly distinguished
from the implementer's initial reported failing run.

One backend comment changed after packaging; same-parser Python AST equality
proves no executable difference. Remaining listed modules match byte-for-byte;
installed dependency hashes match the manifest.

Task 2.18 is complete. Pre-push task 3.4 requires its own final review and verification.
