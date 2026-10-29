# Terminology

[Purpose: name tool and report behavior concretely; avoid virtue words that stand in for a specification]

## Rule

Do not use "honest", "honesty", or compounds of them ("-honesty", "honest read") in new documents,
specs, measurement NOTES, commit messages, or summaries. The word asserts a character trait of the
tool; what the project actually builds are specific, testable behaviors. Name the behavior:

| instead of | write |
|---|---|
| instrument honesty / honest instrument | failure visibility (a failure is reported as itself, never folded into a clean-looking zero) |
| honest `unadjudicated` / honest silence | `unadjudicated` reported, not reported as clean |
| honest dashboard | measurement dashboard (not a CI gate) |
| honest read / the honest answer is | the measured reading is / the stated limit is |
| honest degradation | degradation with its reason |

The steering rule "verify the instrument before you believe the measurement" already carries the
substance; "honesty" adds no information to it.

## Unchanged (do not rewrite)

- The `pair-corpus-honesty` spec: its name, directory, and documents keep the term; it is a
  historical identifier, referenced by other specs.
- Committed documents before 2026-10-29 keep their wording; correctness of the record beats style.
- Verbatim quotes of older documents stay verbatim.

## Added

2026-10-29, after the access-control-prover requirements amendment used "instrument honesty" and the
maintainer rejected the phrasing.
