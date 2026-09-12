# Historical ranking measurements

The eight JSON artifacts dated 2026-09-10 and 2026-09-11 are preserved as recorded.
They predate the scoring correction in pre-push-safety-net task 1.3 and must not be
interpreted as end-to-end detection or pre-push acceptance results.

An audit on 2026-09-12 read all eight artifacts. Each records VAmPI-SQLI with
`position: null`, `reached_transitively: true` and a repository `budget_at_recall`
of 16. The old position instrument assigned that transitive label solely because
it could not locate a matching region, then omitted the target from the budget
calculation. These artifacts contain no queried witness establishing that label.
This does not negate separately demonstrated VAmPI detections; it means this
particular metric cannot establish them.

Other recorded positions, scores, and elapsed stage costs remain historical
observations under their recorded setup. Rank coverage is not detection recall,
and a stage duration is not total hook latency. Use the corrected instrument and
an explicit frozen profile for new comparisons. Retain unknown and unanswered
cases, and require a queried target witness before counting transitive detection.
Do not rewrite these files to make an earlier run appear to use the new semantics.
