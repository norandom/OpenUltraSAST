# Search-with-proof — handoff (2026-10-06)

State at handoff, for resuming on the search problem and abstract interpretation.

## RESOLVED 2026-10-07 — the one open question is CLOSED: first cluster demonstration achieved

The "first `demonstrated`" question below is answered. search-with-proof produced its first autonomous
`demonstrated` finding end to end on kube-ax, and a blind negative confirmed no false proof.

- **Pair:** hanxi/xiaomusic (pilot pair 13), family `path`, vulnerability class **prefix-check bypass**
  (`startswith(root)` without a trailing separator; the fix adds `os.sep`). Image `e2c8b460`.
- **Vulnerable side:** `demonstrated` — owned effect in 3/3 affected runs, 0/3 safe runs. $0.37, 55 calls.
- **Fixed side (blind negative, Req 6.3):** `inconclusive`, **0 false proofs**. $0.56, 85 calls.
- **Pair total:** $1.22. Record: `benchmarks/measurements/2026-10-07-search-first-cluster-demonstration/`.

**The original pair-6 both-sides-false was a TWO-part diagnosis, both now fixed:** the demo did not reach the
observable (demo/agent), and — the decisive one — the path oracle only modelled **classic parent traversal** while
many real path CVEs (xiaomusic included) are **prefix-bypass**, which reaches a sibling that string-extends the served
dir, not the parent. The oracle now also plants a prefix-sibling canary.

**Fix chain that enabled the demonstration (each merged to main and validated by a paid run):**
1. Parity — agent is told the observable's location (path oracle reached parity with command/ssrf).
2. Verify-time-only — the observable is injected at verify time and absent during exploration; stop the explore-time
   reachability trap that burned budget without authoring a demo.
3. Fair-share pilot budget — each search gets a fair share of `--ceiling-usd` with rollover, so one expensive search
   no longer starves the rest.
4. Served-root guidance — the demo MUST set the app's served directory to the `${served_root}` placeholder.
5. Oracle prefix-bypass coverage — plant a sibling canary for the `startswith`-without-separator class.
6. Control-signal feedback — the keystone control (does the app serve `${served_root}`?) is fed back to the agent as a
   `served-root` hint so it self-corrects its wiring. This was the decisive last step.

**Keystone (honest measurement), merged earlier:** the verifier runs a benign positive control; a broken or mis-wired
app yields `could_not_run`/annotation, never a silent clean-looking `inconclusive`.

**Next toward the pilot exit (Req 6.2):** fan out the path family to ≥5 demonstrations with 0 false proofs, then the
≥73-negative BLOCK qualification (Req 6.3). The glance pair (classic traversal) also demonstrates once its npm
dependency build-break (`filed`→`mime@4`) is pinned.

---

## The one open question (HISTORICAL — resolved above)

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
