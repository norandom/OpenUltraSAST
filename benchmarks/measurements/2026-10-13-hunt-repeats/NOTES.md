# Hunt baseline against the pilot hunter: 5 paired repeats on the 12 pilot positives (2026-10-13)

## The question

On the first single runs, the baseline DSPy hunt program found 3 of the 12 pilot positives and the pilot hunter
found 6. One run per arm cannot separate the arms, because the provider's answers vary even at temperature 0.
These five repeats measure the gap.

## Setup

- **Changes:** the 12 fix-site positives of the valid pilot (`benchmarks/valid/pilot/pool-valid.toml`, `--only vulnerability`).
- **Arm A, the pilot hunter:** `benchmarks/valid/hunter_arm.py`, classifier on, exactly as it ran in the pilot.
- **Arm B, the DSPy baseline:** `python -m openultrasast.hunt.cli run`, with the baseline instruction, all annotations, ReAct over the three
  repository tools and `--max-iters 8`. Each run had its own empty response cache, so no run replayed another.
- **Runs:** five repeats per arm, paired by change, run one after another on 2026-10-13 from 13:20 to 15:27.
- **Analysis:** `analyse.py` was committed before any result existed (26720ed) and was not changed afterwards.
  - The unit is one change in one repeat (60 per arm).
  - A hit uses `benchmarks.unseen.score.catches`.
  - Failed and unparsed hunts stay in the denominator as misses.

## Results

| | Pilot hunter (A) | DSPy baseline (B) |
|---|---|---|
| Recall | 31/60 = 52% (95% Wilson 39-64%) | 18/60 = 30% (95% Wilson 20-43%) |
| Hunts with an unparseable answer | 0 | 7 of 60 (12%) |
| Instrument failures | 0 | 0 |
| Suspicions raised per change | 5.8 | 0.6 |

- **Paired difference, B minus A:** -0.22. The 95% interval, from a bootstrap that resamples whole changes (5000 resamples), is -0.38 to -0.05.
- **Exact McNemar:** 14 units were caught only by the hunter and 1 only by DSPy, with 45 concordant (p = 0.001).

The pilot hunter is ahead, and the gap does not come from run-to-run noise. The DSPy baseline is the starting point for
the learning loop, not a candidate to ship, so this is the bar the loop has to clear.

Per-change hit rate over the five repeats (hunter / DSPy):

| Repository | Hunter | DSPy |
|---|---|---|
| imzbf/md-editor-v3 | 1.0 | 1.0 |
| zenitram/malla | 1.0 | 0.8 |
| nvbn/thefuck | 0.8 | 1.0 |
| jupyter-lsp/jupyterlab-lsp | 1.0 | 0.4 |
| ondata/ckan-mcp-server | 1.0 | 0.2 |
| fastapi-users/fastapi-users | 0.6 | 0.0 |
| webpack/webpack-bundle-analyzer | 0.4 | 0.0 |
| contentful/contentful-mcp-server | 0.2 | 0.2 |
| i18next/i18next-http-middleware | 0.2 | 0.0 |
| bytebase/dbhub | 0.0 | 0.0 |
| matrix-org/matrix-appservice-bridge | 0.0 | 0.0 |
| zereight/gitlab-mcp | 0.0 | 0.0 |

Neither arm ever caught three of the changes (dbhub, matrix-appservice-bridge, gitlab-mcp).

## Where DSPy loses

- **It is too cautious.** It raises about a tenth as many suspicions as the hunter. Its misses are mostly
  empty answers, not wrong ones.
- **The tool loop sometimes breaks.** 7 of its 60 hunts (fe1cccd1 three times, then 415e1c7c, a318f3e3, a70b5501 and
  090e3500 once each) failed because of format, not search. The raw responses in the per-run caches show the cause:
  - On one step, the model copies the headings DSPy uses for earlier steps. It writes `tool_name` instead of
    `next_tool_name`, or writes a whole fake history (`thought_1` .. `thought_42`).
  - DSPy then retries the step in JSON. When that retry also fails, DSPy 3.4.1 raises `AdapterParseError`.
  - The tool loop only stops early on a `ValueError` (`dspy/predict/react.py:104`), and `AdapterParseError` is not a
    `ValueError`. So the error escapes the loop, the findings step never runs, and the hunt is recorded as empty.

  Even with all 7 counted as hits, DSPy would be at 25/60. The gap to the hunter is mostly search, not format.

## Cost

- **DSPy arm:** 17.3M prompt tokens (94.8% served from the provider's prompt cache) and 0.94M completion tokens over the five runs. That is
  $1.89 at the registered deepseek-flash prices.
- **Pilot hunter arm:** these records do not carry its token usage, so its cost is not stated here.

## Files

- `analyse.py`: the pre-registered analysis.
- `analysis.json`: its output on the five repeats.
- Raw runs (records, logs, per-run caches): `~/ousast-results/hunt/repeats/{dspy,hunter}-{1..5}`.
