# Hunt baseline on the 12 pilot positives (task 3.2), 2026-10-13

The first DSPy hunt program (today's hunter prompt plus the changed hunks and the four producers' annotations,
ReAct over read_file, grep_repo and find_refs, at most 8 steps, deepseek-flash at temperature 0) run over the 12
verified pilot positives as a report run. Records: `~/ousast-results/hunt/baseline-positives/records{,-v2}/`.
Scorer: `benchmarks/unseen/score.py`, the same as the pilot.

| Run | Answer check | Search recall | Parse failures | Cost (tokens at our prices) |
|---|---|---|---|---|
| Pilot hunter (2026-10-12, hand-written prompt, no hunks) | none | 6 of 12 | - | - |
| Baseline run 1 | counted only the rendered function as shown (bug) | 1 of 12 | 2 | about $0.65 |
| Baseline run 1, as reported by the model | (family as the model gave it) | thefuck x2, jupyterlab-lsp, contentful at the right family | - | - |
| Baseline run 2 (fixed check: tool-read lines count as shown) | fixed | 3 of 12 (jupyterlab-lsp, ckan-mcp-server, malla) | 2 | about $0.44 |

What this says:

- **The instrument bug was real and is fixed** (commit 602ec23): 7 of 8 suspicions in run 1 cited lines the model
  had read through `read_file` and were wrongly scored as `unknown`.
- **Run 2 was meant to replay run 1 from the response cache and did not.** The answers and per-change times
  differ (thefuck: two path findings in run 1, none in run 2; md-editor: a hit in the pilot, a parse failure in
  run 2). At temperature 0 the provider's answers are not stable from run to run, and the DSPy cache did not
  serve the second run. The per-run cache is now configured through `dspy.configure_cache` (602ec23); whether it
  replays has to be checked before any run is called a replay.
- **One run per program is not a measurement.** On 12 positives a single run moves by several hits between
  identical programs. Any comparison between programs or masks has to repeat each arm (k runs, paired by change)
  and report the paired bootstrap and McNemar from `openultrasast.stats`. The acceptance rule (requirements 6.2,
  6.5) already demands intervals; this run shows why the variance has to be inside them.
- The two programs are not yet equal on the same footing: the baseline adds hunks and annotations to the pilot
  hunter's prompt and runs a different loop. 3 of 12 against 6 of 12 is not a significant difference on this n
  (one run each) and is not read as one.

Next: verify cache replay on one change (two runs, identical output and zero new tokens), then k = 5 runs of the
baseline and of the pilot hunter's prompt on the 12 positives, paired by change.

## Cache replay, verified after the fix (2026-10-13)

One change (nvbn/thefuck), program without tools, three runs into one per-run cache configured through
`dspy.configure_cache`: runs 1 and 2 gave the same answer, run 3 used zero tokens and the same answer. Replay now
works; the earlier failure was the cache directory being set after DSPy had chosen its default. Repeated runs for
variance therefore have to use separate cache directories (or `cache=False`), or they measure nothing.
