# Roadmap

## Roadmap to detection with the decision engine on kube-ax (2026-10-04)

This section supersedes the ordering below it. The older sections stay as history.

### Destination

On every push, from a hook or CI, OpenUltraSAST answers for the changed code. The answer is advisory for every
family, and BLOCK only for families whose precision has been proven on repositories the system never saw.
Each environment handles different parts of the work:

- The kube-ax cluster (operator k3s, Agent Substrate v0.3.0, AX v0.3.1, 2 nodes) runs the Joern engine as AX Tasks.
  No API keys and no store credentials in the cluster; tasks read and write through short-lived presigned links.
- The VM or CI runner handles candidate selection and the decision engine's model calls (DeepSeek). It also hosts
  the memory store and the fallback engine lane (2.5 GB heap) for pins that do not fit the cluster's 1.7 GB heap.
- **kind** stays the local development profile, with the same code and manifests.

### The question everything answers

The A/B experiments test whether the safety net works on repositories it has never seen. Every phase below must
answer that question. Almost every push on an unseen repository is an ordinary change. Two numbers measure whether
the safety net is useful, based on the hook's advisory output as a user sees it:

1. How often does it flag real vulnerability-introducing changes in unseen repositories (recall)?
2. How often does it flag anything on ordinary changes in the same unseen repositories (false-positive rate)?

Within-pair AUC on known fix pairs answers neither. It stays a development signal, not the goal.

### Where we are (2026-10-04)

| Area | State | Evidence |
| --- | --- | --- |
| Generalisation measured so far | The classifier ranks above chance on repository-held-out folds (within-pair AUC about 0.76) but cannot reach the block bar; the engine-based scan failed fresh populations (v1 1/11, v2 0/17); push-level catch and false-alarm rates on unseen repositories have never been measured | exp-003/004/005, `results-v1.json`, `results-v2.json` |
| Pre-push hook | Operational and advisory on any repository | `2026-10-02-pre-push-operational-1/record.json` |
| Labelled data | 710 complete real fix pairs | `2026-10-04-decision-engine-harvest-3/record.json` |
| Engine | Almost blind to fixes (paths differ between sides in 2 of 105 both-asked pairs) | `2026-10-04-joern-slice-leak-audit/record.json` |
| Infrastructure | Engine runs on kube-ax as AX Tasks with a VM fallback; kind for development | memory `kube-ax-cluster` |

Correction recorded 2026-10-04: most work in the previous two days went into infrastructure and engine internals
without improving a generalisation number. Further work on those areas must remove a bottleneck for the
measurements below.

### Where we are (2026-10-11)

**The frozen-SZZ-pool scoring approach is not feasible. Its catch/false-alarm numbers are retired as a
metric (2026-10-12 maintainer call).** The SZZ-derived labels place the vulnerability in the wrong location
~half the time (audit: path 1/7, output_encoding 1/8 sound). Only ~24% of entries are app-shaped
(reachability in-repo). Catch/false-alarm figures from this pool are invalid as a baseline.
Record 07's "3/92" and every pool catch/FP number are **not quoted and not a release gate**. Before any
detection number is valid, the pool must have **sound labels** and entries classified as app-shaped or library.
Until then, no pool-scored metric is cited anywhere.

| Area | State | Evidence |
| --- | --- | --- |
| Unseen pool (G0.1) | **Frozen.** `pool-p1.toml` = 100 repos (slice 1); `freeze-p1.json` guard=0, dropped=0; deterministic (manifest `6bd2fa5d`). License 49 permissive / 51 private; methods 81 introducing / 19 last_touch. | `benchmarks/unseen/pool-p1.toml`; archived `ousast-corpus/unseen/20260601/pool/` |
| Labels | 100 machine-derived (SZZ), **unchecked**. Record 07 is a **machine-label baseline** (caveat stated); a human label pass is a later refinement, before any published claim. | `freeze-p1.json` label_check_counts |
| Harvest | Rebuilt to converge. Pure GitHub-API harvesting is a dead end for this benchmark (it needs the SZZ introducing commit + 12 stratified history negatives, not one commit). The fix: a full-objects clone (drop `--filter=blob:none`, which caused ~600 per-blob lazy fetches) + bucket-first durability + a get_repo cache that paid the 4,499-name used-set canonicalization once. Yield ~2.2%; **GitHub-rate-limit bound, not CPU**. | 95bed70, 857263d, 21aebe8, 7b711a6 |
| Persistence | **Bucket-first, not local disk.** `ousast-corpus` is the source of truth: enumeration, resolution, get_repo, and accept/reject decisions all stream to and resume from it. The host disk (~9-13 GB free) is the scarce resource; RustFS/S3 has the room, so run artifacts and **replay outputs go to RustFS too**, not `~/ousast-results` on local disk. | `storage-streaming.md`, `bank.py` |
| Replay image | Provenance pinned. CI `engine-image.yml` builds `ousast-replay-task` (harness with `/app/benchmarks/unseen/replay_entry.py`) + `ousast-engine-task` (Joern hook), publicly pullable by digest. The old `ousast-runner:dev` (248 MB ax-runner, no `/app/benchmarks`, no Joern) is the **wrong** image for replay. | CI run 38116281676 |
| Baseline (G0.2) | **RETIRED as a metric.** A replay (record 07) ran end-to-end on the docker lane, which proves the pipeline works — but its catch/false-alarm figures are **not a usable baseline** (scored against ~half-mislocated SZZ labels on a mostly non-app-shaped corpus) and are **not quoted or used as a gate**. The pool must be cleaned to sound labels first. | pipeline proven; metric not used |

Sourcing and engine-image work took time. The pipeline and these docs now record bucket-first persistence and
pinned image provenance, along with the measured yield. The next pool or arm can reuse that work.

### Readiness plan — build a VALID benchmark first

The frozen-SZZ-pool approach is retired (above). The replay pipeline works end-to-end, and the harvest/freeze/bucket
machinery remains available. The engine/replay images are pinned. No catch/false-alarm figure from that pool is used.

Next, define and build the valid benchmark. Use sound, verified positives with in-repo reachability and ordinary
negatives on unseen repos. Measure the whole tool with metrics an engineer understands. The design is in
`.kiro/specs/valid-detection-benchmark/brief.md`. Only once that benchmark exists does any detection number
(recall, false alarms per 100 pushes, exploit-verified findings) mean anything. The kube `ax` lane is still the place the
engine tier runs at scale, but it is infrastructure, not the gate.

### Restoring the kube `ax` lane (for G1, operator-owned)

The AX executor is **built and smoke-tested** (`benchmarks/ax/batch.py`, `engine_trace.py` `ax`/`mixed-ax`
lanes, OOM→docker fallback; an engine smoke test dispatched to the 2-worker cluster end-to-end on 2026-10-04).
What remains before the G1 engine-arm replay:

- Use the working `ax` binary, `~/go/bin/ax`. `~/.local/ax-v0.3.1/ax` hits the AX-lane blocker
  (recorded in the unseen spec `tasks.md`, 2026-10-11). The coordinator commands in the READMEs are being
  corrected to this binary.
- `benchmarks/ax/batch.py` expects a public-HTTPS DNS, presign-capable S3 store endpoint reachable
  from the cluster; the cluster carries no model/store credentials (it reads/writes via short-lived presigned
  links). This and the cluster's store access are operator/AX-owned.
- **Run the open spec tasks** that gate G1: **4.4** (engine smoke on kube-ax → record 04) and **5.4** (replay
  proof on kind, then kube-ax → record 05), both marked `(coordinator, network)`. Then the full engine-arm
  replay (`--lane ax`).

### Phases

**G0. A VALID detection benchmark** (spec `valid-detection-benchmark`; supersedes the retired
`unseen-repo-evaluation` frozen-SZZ-pool approach)

1. Use real vulnerabilities labelled *from the fix*: the pre-fix code at the file/function the fix changed,
   without an SZZ blame-walk. Keep only those reachable from an in-repo entry point. Confirm each case through
   LLM adjudication and a human spot-check so the positives are sound, app-shaped and verified.
2. Ordinary negatives: everyday non-fix commits from the same application repos, a set much larger than the
   positives (false alarms discourage adoption).
3. Measure the **whole tool** (all tiers on) on **unseen** repos, and report metrics an engineer reads:
   **recall**, **false alarms per 100 pushes** (false-positive rate), **precision**, and **exploit-verified**
   findings (demonstrated with a working proof of concept, label-free). See the brief for the full definition
   and why the SZZ pool was not feasible.

Exit: the benchmark exists (frozen, verified) and the whole tool has a first measured result on it.

**G1. Score the arms on the valid benchmark**

Quick rules, engine evidence, the LLM-guided arm, and their combination, each a registered decision rule,
scored by recall at a fixed false-alarms-per-100-pushes budget, with exploit-verified findings where available.

Exit: one measured table of arms on unseen app-shaped code; keep only what generalises. (No number is quoted
until it comes from this benchmark, never the SZZ pool.)

**G2. Improve what moves the unseen-repo numbers**

Candidates, each admitted only if it improves the pool metric on a fresh slice: fix mechanisms in the engine
(approved plan, now one arm, not the spine), engine coverage and TypeScript, decision-engine prompt and retrieval
changes, more labelled pairs from more distinct repositories.

Active G2 workstreams (2026-10-11; progress tracked in `.kiro/specs/engine-change-scoped-analysis/brief.md`):

Priority #1 after record 07: run semantic detection within the pre-push budget. The record-07 baseline
is **regex only**. The push arms hardcode `model="disabled"`, `max_model_calls=0`, and the engine never
ran (`engine_covered=0`); measured `catch≈2.5%`. Pattern rules alone are insufficient; otherwise `grep` would do.
The two detection tiers did not run: the **engine** (Joern dataflow) and the **LLM adjudication**
(disabled in the push path). The workstream measures **efficiency barriers** with a per-tier budget ledger
against a realistic pre-push window (≤120 s target, 300 s hard):
  - Engine: E1/E2 DONE (2026-10-12, clean host), see brief "E1/E2 RESULTS". CORRECTION: the engine's
    `query=0` wall was **host contention** (the baseline replay), not an intrinsic floor. On a clean host the
    shipped engine **runs dataflow** (query 0→35 s, selected 0→**356 regions**). The evidence/taint batch (~225 s)
    is **invariant to session and preload**; graph-load is cheap (~35 s incl `importCpg`). The real barrier is
    `taint.sc`'s ~160 s per-batch flow work, so `build(~30)+evidence(~225)≈255 s` of 300 s defers 1009/1365
    regions. Reduce the work by **scoping the family/file set to the change** (not session/preload). E3 analysis
    per-pair cost; E4 build vs repo size remain.
  - **ENGINE-ON PILOT DONE (2026-10-12, clean host, 5 public repos), see brief "ENGINE-ON PILOT RESULTS".**
    **regex 1/5, engine 0/5.** The engine added no catches over the regex floor. The budget hypothesis is
    refuted: 3/5 repos finished their queue (deferred=0) and still emitted no finding, so change-scoping will not
    improve recall. The engine ranked the vuln region in all 5 and found the right sink on 2 (socketio deser,
    launch-editor, score 2.0), but withholds any finding it cannot anchor 1:1 to changed lines: all 5 hit
    `ambiguous_line_correspondence` → `witness_unresolved` → `coverage_status=incomplete`, suppressing even the
    scored sinks. This is not a shallow-clone artifact. Detection does not meet release requirements.
  - Corrected after inspecting `head.findings`: the engine produced no vuln-family findings (path/
    injection/deser) on all 5, only config_secrets. The tier1/score2.0 "sink" was the ranker's static candidate,
    not a taint finding. `ambiguous_line_correspondence` does not explain the missing findings (nothing to anchor), so the
    region-level witness fix (old "Option A") was **refuted before implementation**. The **LLM tier was disabled**
    (model_calls=0). The cause is that pilot repos are libraries whose untrusted input is public-API parameters;
    Python taint sources are web/CLI only, and the param-as-source mode fires only for entry points (vuln regions
    are `entry:false`). Widening it statically would reintroduce the WordPress/PMPro false-SQL-injection flood.
    The workstream follows the maintainer's "#2 guided by #1" directive: the LLM adjudicates which library parameter is a trust boundary
    (static rules can't without FPs), the taint engine then traces that source→sink as proof, and repeated source
    shapes get promoted to guarded static facts. First increment (pending budget): wire the disabled LLM tier on the
    5 pilot regions in LLM-guided-source mode; measure source naming, traced finding, catch lift vs regex 1/5, and
    false-alarm on ordinary changes; stage 5–10 → ~10–20 → full on lift. #3 change-anchoring deprioritised until
    tiers yield findings.
  - **BANKS FIXED-SEARCH MVP DONE (2026-10-12), "#2 guided by #1" closes on an unseen target.** See brief
    "BANKS FIXED-SEARCH MVP" + `benchmarks/measurements/2026-10-12-banks-fixed-search-mvp/`. On banks (the
    library that gave the engine zero), injecting the two annotations an LLM steer would supply (param-as-source
    + `write_text`/`read_text` sink) makes the engine resolve `prompt → path-join → write_text` where the
    shipped search resolved nothing. This supports the principle "no wrong targets, only wrong searching" and
    identifies the inputs the DSPy-optimised steer must learn. Filed instrument bug:
    `.kiro/specs/engine-change-scoped-analysis/bugs/taint-sc-single-query-signature-skew.md` (single-query taint
    path dead on an exec-signature skew; batch path unaffected).
  - LLM: L1 model latency and calls per push; L2 the recall lift of the LLM tier over regex+dataflow on the pool.
  - Deliverable: a barrier table (budget × tier combo → fits? measured recall/FP) → the minimal releasable config.

- The pilot lowers the priority of change-scoped engine analysis again. Branch `engine-change-scoped-evidence-pass`
  (unmerged). Fitting the budget does not produce catches (3/5 pilot repos finished the queue with zero findings),
  so this is not required to improve recall. Keep only as a latency optimisation once detection works.
- **Line-correspondence (merged c39fbb8).** `ambiguous_line_correspondence` fires on 5/5 realistic diffs, but the
  pilot's corrected diagnosis shows it does not block detection here. The static tiers produce no vuln-family
  findings to anchor. A region-level witness fallback only matters once #1/#2 yield findings.

**G3. Decide BLOCK per family** on the pool's false-alarm rate and the pooled precision bound (Req 6.4).

**G4. Detection on push for any repository** (`plane-on-kubernetes` P4 work: `ousast plane scan --base --head`,
engine pins on kube-ax, model calls on the VM or CI), sized by what G1-G3 kept.

G5. Qualification and rollout: adopt, commit `prediction-v3.json`, spend population v3 once, advisory rollout,
BLOCK only for families that passed.

### Cross-cutting rules

- No hand-tuning per miss. Every detection change is a registered experiment or an admission by held-out
  separation.
- Records carry counts, digests and pattern names, never repository names: the reserved-repository guard covers
  every population.
- Instrument first: a zero from an unread input is a failed run (AGENTS.md).
- Cluster stability: sandbox deaths are retried once, then sent to the VM lane; the operator owns workers, egress
  and Substrate.

### Spec map

| Spec | Role in this roadmap | State |
| --- | --- | --- |
| `unseen-repo-evaluation` (new) | G0, G1: the pool and the push-level metric | To specify |
| `learned-decision-engine` | G1-G3, G5; fix-mechanisms plan is one G2 arm | Implementation; experiments 3-5 recorded |
| `plane-on-kubernetes` | G4; the engine executors for kube-ax | Groups 1-2 done (kind); production path re-scoped to the operator's kube-ax (AX Tasks), groups 3-8 to re-plan |
| `pre-push-safety-net` | the hook replayed in G0-G1; M4-M5 in G5 | Operational increment 1 done; M4-M5 open |
| `ai-service-plane` | The plane the above runs on | Complete |

## Status, 2026-10-02

The milestone table below dates from 2026-09-14. Since then (`.kiro/specs/pre-push-safety-net/release-milestones.md`):
M1a and M1b are met, M2 is measured NO-GO, and M3 is next, with M4 population preparation in parallel; none of
M1-M5 is verified and rollout remains NO-GO. Populations v1 and v2 were evaluated and failed every M4 gate
(`benchmarks/independent/results-v1.json`, `results-v2.json`); v3 (PHP) is frozen for the one-time final check.

Work since then moved to: the ax plane as the only agentic executor (`ai-service-plane`, HarnessX retired
2026-09-30 by `harnessx-removal`), and the learned decision engine (`learned-decision-engine`, task 6 in
progress, not adopted). See `overview.md` for the current-state summary.

## Release path as accepted 2026-09-14

Build an actionable pre-push security safety net for AI-accelerated development.
The maintainer accepted the following order: **prove one useful detection, make it
fast, prove cross-language transfer, qualify independently, then enable a narrow advisory
rollout**. The executable outcome contract lives in the existing
[pre-push-safety-net release milestone spec](../specs/pre-push-safety-net/release-milestones.md).

**We are at M1b. M1a is met; no other release milestone is verified yet.** The published
`v1.2.0-alpha.1` and 28/29 completed implementation tasks show that the machinery is implemented.
They do not demonstrate a useful safety net. Task 8.3 and rollout remain NO-GO.

| Order | Milestone | Observable exit | Current state |
|---|---|---|---|
| M1a | Show the NodeGoat detection with every admission veto recorded, not applied | Raw finding with witness on the vulnerable revision; analyzed fixed twin and unchanged control quiet; per-finding veto list. One-week time box | MET 2026-09-16 |
| M1b | Repair only the vetoes M1a showed to matter | Supported evaluation finding through production rules, exact change/base evidence and repair direction; fixed twin and unchanged control stay quiet | IN PROGRESS: comparison half verified on all three revisions; the consequence and repair rendering (10.10) remains |
| M2 | Make that same analysis fast | Equivalent evidence; representative warm changed-code p95 <=30s, cancellation/report <=2s, >=95% supported completion | Pending M1 |
| M3 | Prove the shared design transfers | PMPro/PHP and VAmPI/Python vulnerable/fixed evidence; unchanged core rules; Node replay after any PMPro core change | Pending M2 |
| M4 | Qualify on independent cases | Reviewed untouched vulnerable/fixed/benign populations pass joint quality, coverage and latency gates per capability | Pending M3 |
| M5 | Enable a narrow advisory rollout | Exact passing eligibility and packaged acceptance; only qualified capabilities enabled | Pending M4 |

### Immediate next action

Finish M1b by rendering the experimental evaluation finding with its consequence and repair
direction (10.10), through an explicitly unreviewed declaration and with eligibility still
disabled. The comparison half is verified: the production rules classify the vulnerable, fixed
and unchanged NodeGoat revisions correctly, and admission rejects the vulnerable one on the
eligibility gate alone. What is missing is the explanation, which no declaration currently
supports, and inventing it is exactly what admission exists to prevent. Then M2 runtime.
Do not start another broad speed campaign before this outcome exists. See the
[M1a evidence](../specs/pre-push-safety-net/m1a-recorded-vetoes.md) and the
[owner diagnosis](../specs/contributor-scan/release-remediation-research.md).

### Approach and boundaries

The existing ranker owns scope. Vendor code stays out of targets and graphs. Framework
facts and frontends supply evidence to a language-agnostic core. Unknown dependencies
remain explicit; removing global completeness vetoes requires question-owned evidence,
not dropped safety checks. Advisory and blocking share the same actionability bar.

Graph persistence now works: identical-tip replays take 18.5–18.9s. All 18 other measured
transactions still time out and 0/24 target checks complete. A local Joern session census
probe shows promise, but full-query equivalence and hook performance are unverified.
These findings inform M2; they do not complete M1. No second IR/engine, new heuristic
scope selector, differential graph mutation or unrelated backlog is part of this path.

## Existing Spec Updates

- [ ] pre-push-safety-net, Execute the accepted M1–M5 release milestone amendment.
  Owns immutable replay, comparison, admission, evaluation and reporting. Preserve the
  existing completed tasks; task 8.3 remains blocked until qualification passes.
- [ ] contributor-scan, Supply the required query/operation/context fixes for M1,
  followed by equivalent bounded session execution for M2 and shared transfer evidence.
  Frontend retention 2.18 and named census repair 2.19 are already verified.
- [ ] flow-aware-ranking, Preserve ranker-owned scope and normalized cross-language
  behavior. New ranking research is not a prerequisite for the first useful comparison.
- [ ] zero-with-a-reason, Adjacent diagnostics work; finishing its whole backlog is
  not required before M1.

## Specs (dependency order)

- [ ] pre-push-safety-net, Existing approved implementation, dependent on contributor-scan.
  Groups 1–7 and tasks 8.1, 8.2, 8.4 are verified; 26/27 executable tasks complete.
  Remaining release work follows [M1–M5](../specs/pre-push-safety-net/release-milestones.md).
  This amendment creates no duplicate implementation spec and resets no prior approvals.

### Progress reporting

Lead with the current milestone, the demonstrated developer outcome, the blocker and
the next action. Keep implementation counts separate from release readiness. Preserve
prior evidence and review limits in the [implementation records](../specs/pre-push-safety-net/status.md).
The earlier PHP-first and runtime-first narrative below is historical and does not
supersede this accepted sequence. Blocking deployment follows a later explicit decision.

## Historical roadmap narrative — September 9–11

The sections below preserve prior plans and measurements. Statements about the current bottleneck,
PHP coverage, rollout order or feature readiness are superseded by the current section above.

**Rewritten 2026-09-09.** The previous version (kept as `.kiro/archive/steering/roadmap-2026-09-04.md`, outside steering) described a pre-Joern world,
"adjudication is still Python-`ast` plus a tree-sitter CLI stub", "Joern-as-required deferred". Joern was
adopted. The model layer was built and wired, then measured. Two repositories have been scanned. See
`overview.md` for what is true today; this is what happens next and in what order.

## The target: a first release for small projects

> "a first release that is ready for smaller projects like libpng or wordpress"

Neither works today. They fail for different reasons, so both are useful targets.

| target | why it fails now | what a release needs |
| --- | --- | --- |
| **WordPress** (php) | `taint_specs(language="php")` returns **zero families**. Joern's `php2cpg` parses it; we say nothing. | Fact tables and entry-point mapping. The engine is right for this: PHP web bugs are the classic taint families, which is what the taint arbiter already decides well. |
| **libpng** (c) | `c/memory` models string functions; libpng overflows through *arithmetic*, and its library never calls a sink we model. | Either a second abstraction (size arithmetic — a constraint problem) or an honest, stated limit. |

So "ready for" has to mean two different things, and the release criteria say which applies where:

* For a project whose bug class a family **can** decide (WordPress, vibe-code): find the known vulnerability.
* For one it **cannot** (libpng today): run inside its envelope, report nothing false, and *state the limit*
  rather than returning a quiet clean bill of health.

A tool that says "I do not model this class" is usable. Silent failure to find anything teaches developers to
distrust SAST.

### Release criteria (v0.1)

1. Runs unattended on a pinned checkout of each target within a stated time and memory envelope.
2. **Zero known-false entailed findings** on every pinned checkout.
3. Finds the known vulnerability wherever a family can decide it in principle (Req 4.6).
4. States what each family cannot decide, in the report (Req 5.6).
5. The report is proportionate: no rule repeats itself past a stated count (Req 5.5).
6. Installs and runs without the user having Joern, a JVM, or a PHP interpreter (docker compose + wrapper).
7. A committed regression baseline per target, so the next change is measurable rather than argued about.

### What that reorders

PHP moves up: it is the shortest path from here to a target the maintainer named, and it is the case the
existing arbiter is best suited to. The C decision moves up with it, because criterion 4 needs `c/memory`
either earning its place or being scoped, and scoping it is cheap.

## The one test everything is ordered by

> "it must find the bugs, otherwise it's SAST noise. most devs know codeql / semgrep have dataflow
> capabilities but never use it"

So the ordering principle is: **make the output worth reading, then make it find more.** A better arbiter
behind an unreadable report changes nothing, and a second language before the report is fixed doubles the
noise.

## Now — make a repository scan finish at all

The output work previously listed here is done. PHP detection exceeded the plan: the graph entailed three
CVEs on real WordPress plugins without a model, and each finding disappeared on the fixed side. The remaining
problem is getting scans to finish.

A 637-file plugin builds in 76 seconds and then the taint query does not complete. Everything below is
ordered by one question: what is the shortest path to a scan of a real plugin that reports its CVE?

1. For **5.14**, stop asking questions that cannot have an answer. 53% of taint requests are put to a family
   whose sinks do not appear in scope; every one of PMPro's 487 `deserialization` requests is asked of a
   repository that never calls `unserialize`. This is an arithmetic check and cannot lose a finding.
   4.6 hours → 2.2. Do this first because it makes every later measurement cheaper to run.
2. For **5.12**, add ranking. Currently 84% of regions share one rank and are ordered alphabetically. Two thirds of the
   budget is spent arbitrarily. Fifty well-chosen regions are better than five hundred; combined with (1) that is the
   difference between hours and minutes. The ranker is an LLM job, and it is safe as one because ranking
   cannot manufacture a finding. It decides what is looked at, never what is reported.
   The loop is closed and that is a design requirement, not a caveat: a region the ranker excludes is
   never arbitrated, so it never produces a label, so the ranker never learns it was wrong. An exploration
   slice and a small fully-labelled corpus are what make the signal unbiased.
3. For **5.13**, reduce the 6.63 s/request itself if (1) and (2) are not enough. `callDepth=3` over 7,061 methods is
   the term that makes a request cost seconds; the two-stage joins are not the cost (measured: 22%, and they
   found two of the three CVEs).

Only after a scan finishes is there any point tuning what it finds.

## Next — the families that cannot be asked

4. For **5.9**, add PHP obligation facts. `dominance_specs(language="php")` is empty, so missing-capability checks
   are not asked on any WordPress scan. Not a miss; nothing was measured.
5. For **5.6**, associate each sanitizer with the family it cleanses. The list is flat, so `esc_sql` reads as sufficient
   for XSS and `esc_html` as insufficient for SQL. Wrong in both directions, so no `output_encoding` verdict
   currently means anything.
6. **File the php2cpg defect upstream.** A `global` inside a closure yields a CPG Joern's own dataflow
   overlay rejects, bisected to four lines. Worked around here (0.2% of files, detected and excluded and
   reported), but it costs the WHOLE graph rather than the file, and other users will hit it.

## Then — close the deferred engine questions

8. For **2.14**, check control dependence. It is absent from both CPGs, so every guard question runs on CFG dominance. Find
   out whether Joern's CDG pass can be applied from the query script and what it costs. If it cannot, that is
   a real bound on what this engine can reason about and should be recorded as one.
9. **2.13** covers a destination allocated to size. It is deliberately blocked on 6, so the rule can be measured for what
   it *silences* as well as what it clears.
10. Ship **Group 3–4**: contributor output, the Docker image, the memory-family decision, and retirement of
    `evidence_level` now that the rung carries the meaning.

## Alongside — keep the codebase from growing into the problem

> "we should make sure our code base here doesn't explode. for example we have a custom IR."

`.kiro/specs/ir-consolidation/` (brief, unapproved) separates two questions with opposite answers:

* The source IR already exists in the project. `semantic/` is 3,218 lines, or 16% of the
  codebase. It holds a hand-written IR and flat taint engine measured at **2.2% entailment against the CPG's
  41.3%**, still running as a proposer. Vine and Ghidra P-Code are *binary* IRs and do not help here; the
  work is subtraction. This is a candidate ~1,000-line deletion supported by a measurement.
* **The missing abstraction is C arithmetic**, and there an existing IR is exactly right. GhidraPAL's
  three-valued-logic abstract interpreter over P-Code decides "can this index exceed this allocation", which
  is the class `c/memory` cannot see and every libpng overflow is. Vine is dormant since 2009 and is not the
  candidate.

The order matters: **question 1 lands before question 2 starts**, or adopting an IR makes
the growth problem worse rather than better.

## After — the feedback loop

11. **`finding-feedback-loop`** (design generated, awaiting approval). Its ledger and dismissals are useful
    immediately; its *evolution* should not be trusted until step 5 or 6 lands a second true-positive
    checkout. The boundary is fixed: an optimiser may evolve the **question**, never the **facts**.

## Not now, and why

- `authorization-obligations` (24 open tasks, approved): the dominance arbiter delivered its substance by
  another route. It should be reconciled or retired rather than worked, and carrying it as "approved, not
  started" misrepresents both.
- `reachability-flow-model` (23 open, nothing approved) was largely delivered by adopting Joern. Same
  treatment.
- `constrained-detector` (4 of 20, tasks unapproved) is parked.
- More corpus volume is deferred. 198 of 238 OWASP pairs were left unvendored deliberately: volume without
  readability makes every number worse, and the corpus is not the binding constraint. Reachability is.
- A second CPG engine and an execution rung are deferred, as is server mode. Server mode was measured and rejected (6% of a
  scan). The other two have no evidence calling for them yet.

## How to know it is working

The scoreboard in `overview.md`, and one question: **can a developer run this on a repository they did not
write and get something they act on?** Today that is true for one Python application and false for one C
library, and the specs above are ordered by what changes that.

A release is ready when it answers **yes for WordPress and honestly for libpng**. It must find the vulnerability
where the engine can decide the class, and state the limit where it cannot. Both are release criteria; only one
of them is a detection claim.
