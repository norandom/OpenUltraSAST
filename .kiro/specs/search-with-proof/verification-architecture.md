# Search-with-proof: where each stage runs (verification architecture)

Recorded 2026-10-07. search-with-proof has two stages across a trust boundary: a Cairn-inspired
directed state-space **search**, then a DAST-style **proof (verification)**.

## The two stages

1. **Search (Cairn-inspired).** A blackboard of facts, intents and hints. A reasoner proposes
   independent, non-overlapping intents; tool-using explorers each confirm one fact against the
   code. The goal is a declarative demo (a candidate PoC), never proof by itself.
2. **Proof (DAST verification).** The verifier builds and starts the app, drives the demo's steps
   through the app's real interface, and watches a verifier-owned canary for a **differential**
   between the vulnerable and fixed revisions: the owned effect appears on the vulnerable side and
   not on the fixed side (3/3 vs 0/3). Only this differential earns `demonstrated`.

## Trust boundary — what runs where

The brain runs on the VM; the agent's tool executions and the DAST proof run as isolated tasks in
the kube-ax cluster. Secrets never enter the cluster.

| Component | Location | Notes |
|-----------|----------|-------|
| Coordinator, board, budgets | VM (host) | Orchestrates the search; owns the global budget. |
| Reasoner + explorer **model calls** | VM (host) | The model key lives only on the VM. This is the brain. |
| Explorer **tool runs** (`list_files`, `read_file`, `grep`, `run`, build) | kube-ax AX Task (gVisor) | Carry no secrets; inputs/results via presigned object links. |
| **DAST proof / verification** | kube-ax AX Task (gVisor) | Builds, starts, attacks and observes the app. One task per revision. |

- **gVisor is the isolation boundary.** The proof runs untrusted exploit code against a running
  app, so it is sandboxed per-task in the cluster.
- **Secrets stay on the VM.** Executor and verifier tasks carry no credentials; they exchange
  checkout archives, demos and results through presigned object-store links. Per-host egress is
  restricted (verify tasks reach the files host only).

## Verification lanes (the `--verify-lane` choice)

- **`ax` (default for paid pilot runs):** verification runs **inside kube-ax** as gVisor AX Tasks,
  one per side. This is how every paid pilot run this session executed the proof.
- **`vm` (local):** verification runs in **Bubblewrap on the host**, no cluster. Used for the
  zero-cost ceiling proofs (a hand-authored demo verified locally with no model and no cluster),
  which is how glance and xiaomusic were confirmed demonstrable before any spend.
- **`docker` (replay):** `benchmarks.search.demo_replay` runs a stored demo with no model calls in
  a local Docker lane.

## Why the proof is dynamic, not abstract interpretation

Abstract interpretation (the static engine and the decision model) is the cheap, generalizable
**triage/ranker**: it selects and orders candidate regions across any repo without executing. It
plateaued as a **blocking** gate because it could not prove the required precision. search-with-proof
is the **dynamic** confirmation: a demonstrated finding is ground truth by execution, so it earns a
block without calibration. The per-app harness cost (building and running the app, wiring its served
directory or database to the oracle fixture) is the price of the dynamic proof and is why proof pays
off where a runnable harness exists, with abstract interpretation remaining the static backbone.
