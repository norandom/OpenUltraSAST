# Search-with-proof — handoff (2026-10-06)

State at handoff, for resuming on the search problem and abstract interpretation.

## The one open question

The full chain runs end to end on kube-ax. Every execution layer is cleared. The **first `demonstrated` has not
happened yet**, and the remaining gap is narrow and reproducible at **$0 model cost** via `demo_replay`.

No-model replay of pilot pair 6 (path / Node / npm build), both sides, image `aa54880`:
- Both sides **build, start, and run** (ready ~18–20 s, "fresh task run completed", no `could_not_run`).
- Oracle observed **no effect on either side** → `inconclusive`, "no consistent differential".

Both-sides-false means it is **not the harness** any more. It is one of:
1. The demo's attack step as written does not trigger the effect even on the vulnerable revision, or
2. The oracle does not capture the app's output where the effect would show.

## How to close it (no model spend)

- Control: the **probe path app** (`src/openultrasast/search/probe_apps/`) is known-good and *does* observe through the
  same verifier code path. Diff its behaviour against the real app: how the served directory is wired
  (`${served_root}` substitution in `start.arguments`), and where the oracle reads the nonce from (app stdout/response
  capture in `oracles.py` `PathOracle.observe`).
- Re-run with `python -m benchmarks.search.demo_replay --both --demo <stored demo.json> --family path --lane ax
  --image <digest> ...`. Stored demos live under `benchmarks/search/private/runs/*/<pair>/demo/demo.json` (gitignored).
- **Classifier note:** keep exploit payloads on disk. Hand Codex file-path tasks that treat demo contents as opaque;
  print outcomes / phase timings / error *classes*, never request strings, env values, or step bodies. See memory
  `search-with-proof-direction` and the classifier false-positive note. Code changes never tripped it; echoing
  payloads or step-by-step attack prose did.

## What is done and merged (main)

- Trust-domain split: model key on the VM only; executor and verifier tasks carry no secrets; exchange via presigned
  objects. Declarative demos (data, not agent code). gVisor is the cluster boundary.
- Verifier + 5 oracles pass inside a gVisor task (probe: 5/5 demonstrated, gaming demos inconclusive).
- Shared task base image, code-last layers; `plane/task-base.digest` pins it; `engine-image.yml` builds only on
  dispatch / tags / Dockerfile / pin changes. Measured unpacked: search 2.07 GB, engine 3.61 GB.
- Pilot driver (`benchmarks/search/pilot_run.py`), budgets with reservation, named exhaustion limits, `demo_replay`.
- Per-host egress live: exec → any 443; verify/probe/pass → files host; replay → files + github. Task names carry
  the right prefixes.

## Plumbing defects fixed along the way (each cost one run)

step allowance → family-vs-oracle mapping → build memory (256 MB SIGTRAP) → manifest path appended positionally →
startup env + data files → dead-end intent dedupe → archive size (edge ~100 MB, now split+gzip) → two-interpreter
image (pip 3.13 vs venv 3.12 → use `sys.executable`) → checkout root on sys.path → `node_modules` path.

## Next, once a demo demonstrates

1. Fan out the pilot across all 20 pairs, both sides (feasibility: demonstrated rate per family, zero false proofs on
   fixed sides). Exit: ≥1 family with ≥5 demonstrations and zero false proofs (Req 6.2).
2. BLOCK qualification per family: 0 false proofs over ≥73 negatives from ≥73 repos (Req 6.3).
3. G1 arm on the unseen pool vs the triage/decision arms at equal false-alarm budgets (Req 6.5).

## Cluster / spend facts

- kube-ax: **2 tasks in flight, one per worker** (operator `--max-actors=1`). Dispatcher caps AX concurrency at 2;
  raise it only when the operator raises worker count. "no free workers available" = retry, not failure.
- `/workspace` ~3 GiB free per node until the volume move; scratch guard 2 GiB/task.
- Pilot spend to date ~$11 across 9 paid runs; the decisive replay was $0.

## Decision model vs search — current read

- Decision/classification: measured, **promising as triage** (within-pair AUC 0.762; trained logistic ties at 0.721),
  **capped as a blocker** (cannot prove 95% precision). Reframed as triage (`learned-decision-engine` Req 6.5).
- Search-with-proof: **not yet demonstrated**, but no observation so far argues against the idea — every failure was
  our execution, now cleared. The pair-6 demo/oracle question is the first verdict on the method itself.
