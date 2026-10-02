# Where we stand

State as of 2026-10-02 (v2.0.0). This page answers five questions in one place. How far is
detection from its gates. How does the project now try to close that gap. How does the model work
run on ax. What did the tokens cost before and after that move. What is still open. Every figure
is quoted from a committed record whose path stands next to it; detail tables stay on the pages
linked from each section.

The goal has not changed: a safety net on repositories the tool has never seen, which says
BLOCK or ADVISORY about the code a push would change and stays silent on fixes and on benign
commits. Two independent populations have been spent against that goal, with engine recall 1 of
11 and then 0 of 17. The hand edits that closed misses on the first population did not carry to
the second. So the question is no longer which rule to add next. It is how a change to detection
can be shown to work on code it was not tuned on, at a cost per candidate that can be paid for
every push.

The answer this page records: the pre-push safety net is NO-GO against every M4 gate, and the
project has stopped trying to reach the gates by hand. Every detection change now has to win a
controlled measurement on held-out repositories, run on an agentic plane whose cost per candidate
is known. The pieces of that method exist and have been measured. None of them has produced a
BLOCK decision yet.

## 1. Detection capability and goals: NO-GO, measured

No M4 gate is met on an independent population. The qualification milestone for the pre-push
safety net (M4) requires, together: at least 95% actionable precision, at least 90% supported
recall, at least 95% supported-check completion, the runtime gates, and zero fixed-side or benign
false alerts. A population is frozen before any
case is scanned, scored once under a pre-registered protocol, then spent; it can inform changes
but can qualify nothing afterwards ([Evaluation](evaluation.md#independent-populations-and-the-m4-gates)).

| Gate | Required | Latest independent result | Record |
| --- | --- | --- | --- |
| Supported recall | >= 90% | engine 0 of 17 declared sites on population v2 | `benchmarks/independent/results-v2.json` |
| Actionable precision | >= 95% | engine 0 of 17 (`precision`); the tool hunter on the same population 2 of 14 | `results-v2.json`, `results-v2-hunter.json` |
| Supported-check completion | >= 95% | 13,206 of 108,374 | `results-v2.json` |
| Fixed-side and benign alerts | zero | 0 fixed-side, which the record calls met trivially since nothing was detected; 3 benign alerts | `results-v2.json` |

Three later measurements narrow the picture without changing the verdict.

- The plane reproduces the script pipeline's agreement at a known cost. On the model-driven
  pipeline's validation set (46 candidates, 15 cases of v2, 20 declared vulnerable sites), the
  plane's verify passes a and b plus a tie-break on the 10 disputed candidates agreed on 16 of 20
  declared sites. The script reference agreed on 16 as well. The cost was $0.0205 per candidate
  (`benchmarks/independent/plane-increment-2.json`). The record carries two caveats. The tie-break
  was chosen after seeing the first measurement on the same set, so this compares plane with
  script and qualifies nothing. And the passes flag fewer declared sites than the reference in
  any pass, 17 against 19; that count is a correction in `plane-increment-1.json`, whose first
  reading took agree's `declared_sites_matched` (19, coverage by candidates) for "found in either
  pass".
- The learned decision engine ranks, but may not block. On six families, evaluated on
  repositories the compiled program was not shown, the pooled AUC of its score runs from 0.77
  (injection) to 0.96 (access control). The stricter reading is the within-pair AUC, which asks
  whether the vulnerable side of a fix scores above its own fixed side: 0.72 to 0.93. BLOCK is
  offered for no family; calibration holds only for output encoding, and there no fold reaches
  the required precision (`benchmarks/measurements/2026-10-02-decision-engine-slice-2/record.json`).
  The per-family table is on [Decision engine](decision-engine.md#second-slice-six-families-2026-10-02).
- PHP coverage is in-sample. The PHP quick rules were written and tightened while looking at
  the pins and fixtures they are scored on, so the record says so itself (`provenance.in_sample` in
  `benchmarks/measurements/2026-09-30-php-quick-rules/measurement.json`): a development check, not
  a recall estimate. On real PHP code the Joern engine is the instrument.

What has not been touched: population v3, 15 PHP cases, frozen as the one-time final check. No
development or analysis work reads its cases, a test fails when anything in the tree names one
of its repositories, and it runs once, after a prediction is committed.

## 2. Our approach to detection, step by step

The path changed because hand edits did not transfer. Every gain before 2026-09-30 was a hand
edit after a miss: a rule, a taint vocabulary entry, a guard, a prompt line, a tie-break. Each was
tuned on the cases that exposed it, and the tuning measured on population v1 did not carry to v2
(1 of 11, then 0 of 17). The conclusions drawn: hand edits do not transfer. The data that could
teach a better decision cannot be produced by hand at the scale needed, so it has to be harvested
and labelled by machinery with a boundary around it. Framework knowledge (which function is a sink in which
framework) is useful as a prior but must stay optional, or the engine learns the vocabulary
instead of the code. A reader might object that a classifier is slower to show gains than the
next rule. It is. The difference is that its gains are measured where rules were not: on
repositories it never saw.

The chain, one job per step. The design is on [Memory and detection](memory-and-detection.md);
this is the order of operations.

1. Instruments produce signals, never verdicts. Quick rules, the Joern engine, model sink
   classification, the plane's verify passes a and b with the tie-break c, repository facts
   (callers, spans) and model source/sink/sanitizer roles each write one block of a candidate's
   record. None decides alone.
2. Feature records are allow-listed, and missing is not zero. A candidate is `(path, function,
   family)` of one repository and pin. An instrument that did not run, had no coverage or failed
   records that state; "silent" and "did not look" stay distinguishable. Input profile v1 withholds
   the engine block and the function length, which a leak audit found separate the two sides of a
   pair by construction (`benchmarks/measurements/2026-10-01-decision-engine-leak-audit/`), and
   since 2026-10-02 the plane's `verify.flag_b` and `ms.operation`, flagged the same way by the
   audit of the plane profile (`2026-10-02-decision-engine-harvest-advisory/record.json`,
   `src/openultrasast/learn/schema.py`).
3. Labels come from ground truth only. A fail-closed allow-list (`src/openultrasast/learn/sources.toml`)
   names the sources: the spent populations' declared sites and fix ranges, the vulnerable and
   fixed sides of pairs, including the 97 real public fixes in `benchmarks/pairs/advisory-fixes/`,
   benign controls and recorded adjudications. Assumed-benign commits are their own source,
   weighted 0.5 and reported separately. A plane verdict is a feature, never a label: "rejected by
   the plane" is not a negative, or the engine would learn to reproduce the plane's mistakes.
4. Retrieval finds similar labelled cases. A Gower distance over the signal profile, re-ranked
   by cosine similarity of code embeddings (OpenAI `text-embedding-3-small` through OpenRouter,
   cached by excerpt hash). The evaluation boundary is the only door into a prompt: never the
   candidate's own repository group, never a group the fold evaluates.
5. A classifier compiled in house, DSPy-style. `retrieve -> classify(k)`: an instruction and
   compiled demonstrations (a fixed prefix, so the provider's cache hits), the retrieved examples,
   then the candidate's excerpt and signals. The model answers vulnerable, not vulnerable or
   unsure with a rationale that cites a line; `k` samples give a score. One program is compiled
   per profile and family on a compile split that is never evaluated.
6. Calibration on held-out repositories. Platt scaling of the score, cross-fitted by
   repository group so no map is checked on the fold that fitted it. Calibration holds when the
   slope interval contains 1, the intercept interval contains 0 and ECE <= 0.05.
7. Two operating points. BLOCK only where calibration holds and a fold reaches the required
   precision; otherwise ADVISORY. An unsure majority can never BLOCK.
8. A/B experiments are the only way a change is adopted. Prompts, models, pass counts,
   features and sampling are compared under a pre-registered manifest with frozen units, paired
   arms, a repository bootstrap and two looks. exp-002 is the first to finish: a retrieval
   ensemble (five samples over disjoint example sets at temperature 0) against today's
   temperature sampling. It raised re-run agreement a little (0.906 against 0.875, interval
   spanning zero) and lowered the within-pair AUC from 0.815 to 0.741 at 2.4 times the cost per
   candidate ($0.0051 against $0.0021). Decision: REJECTED
   (`benchmarks/experiments/exp-002-retrieval-ensemble/result.json`).
9. Extrapolation with intervals. Every number carries a 95% repository-cluster bootstrap
   interval; the pooled and the within-pair readings are both reported, and the stricter one is
   named.
10. The one-time v3 check. When a program is adopted and a prediction is committed, population
    v3 is scored once under `benchmarks/independent/protocol-v3.md`.

## 3. AI integration: ax on the server

All model work runs as Tasks on google/ax over Agent Substrate, in a single-node kind cluster on
the maintainer's host, each Task in its own gVisor sandbox. There is no local subprocess path.
The reconciler (`ousast plane run`) is a host process: it applies a Run's Workspaces and Tasks,
resumes each Task, sends its start signal, collects its artifacts and records state. Flow and
contract: [The plane on ax](plane.md); bring-up and the host's lessons: [ax on this host](ops/ax/README.md).

What each Run guarantees:

- One Model and one budget per Task. A Task binds at most one ax Model (`deepseek-flash` for
  chat, `openrouter-embedding` for embeddings) and `budget: {usd, calls}`. The metered client
  refuses the next call at the ceiling; the task ends unfinished and resumes on a rerun. Model-free
  tasks run with a zero budget, so a stray call fails loudly.
- Credentials exist only in the start request. Agent Substrate boots each template once as a
  golden actor, so the runner never starts by itself. It waits for `POST /ousast/v1/start`, which
  the reconciler sends through `atenet-router` to that actor alone. The key is read from the
  operator's environment or `.env`, kept in memory by the runner, passed to the command and
  redacted from echoed stderr; no manifest, rendered Task or file carries it.
- Per-task egress. One EgressPolicy per actor through the `atenet-egress` gateway, deny by
  default, hostnames only: plain HTTP to the artifact receiver, TLS passthrough to the Workspaces'
  Git hosts and the Model's declared hosts. Deleted with the actor.
- Artifacts come back through the gateway. The runner posts its output directory as a tar to
  the receiver, an HTTP server inside the reconciler process on the host, reached through a Service
  with an EndpointSlice to the host. That delivery is the task's completion; ax has no Completed
  phase.
- Memory on S3-compatible RustFS. `OUSAST_MEMORY=s3://sast-memory` on a RustFS server. The
  store verifies the bucket at every start (versioning, lifecycle, tags, S3 Select) and refuses to
  start when anything is missing; there is no local or fetch-and-filter fallback. Each row kind
  has a fixed set of queryable fields, enforced at write time
  ([Memory](memory.md#verify-at-startup-no-fallback), [RustFS setup](rustfs.md)).

Lessons the host taught, each from a failed live run (the full list is on
[ax on this host](ops/ax/README.md#what-this-host-taught-each-one-cost-a-failed-live-run)):

- Substrate installs no WorkerPool, and actor images must be pinned by digest.
- A release `ax` CLI skews from the server; build it from the deployed checkout.
- ax has no Completed phase, so completion is our artifact delivery.
- The golden boot means the runner must wait for a start request.
- The egress gateway dials the address the actor connected to, so the receiver is a Service
  dialled by ClusterIP with its name as Host.
- ax's snapshot bucket must exist in your S3 server. When it did not, deleted golden actors piled
  up in `DELETING` and filled the disk during a 600-task harvest on 2026-10-01.

Deployment status, in the two words [Deployment](deployment.md) uses strictly. Implemented:
ax as the only executor, per-task EgressPolicy, credentials only in the start request, per-task
budgets and attribution, the S3 store verified at startup, local bring-up, doctor and smoke Run,
re-pinning generated Tasks to another registry. Planned, not done: deployment to any cluster
other than this host's kind cluster, a configurable kube context (`kind-` is hard-coded in
`doctor.py`, `egress.py`, `router.py`), the receiver as an in-cluster Deployment, the
reconciler in-cluster with Secrets injected, presigned-URL delivery to the store.

## 4. Token economics, before and after

Before the plane, the script pipeline cost $0.022 per candidate for two verify passes
(`benchmarks/independent/verifier-batched-check-2026-09-29.json`), and the maintainers' own
coding sessions spent about 90% of their tokens on tool input and output rather than reasoning.
After it, the per-candidate costs below are what the records show. The mechanisms (one budget
per Task, pay-once reuse, cheap-before-expensive ordering, replay at $0) are on
[Token ergonomics](token-ergonomics.md); this table is the before and after.

| Item | Before | After | Record |
| --- | --- | --- | --- |
| Verification, two passes per candidate | $0.022 (script pipeline) | $0.0205 over 46 candidates with the recorded triage, including the tie-break pass on 10 disputed; 2,385,152 of 3,820,395 prompt tokens were cache hits in increment 1 (62%) | `verifier-batched-check-2026-09-29.json`, `plane-increment-1.json`, `plane-increment-2.json` |
| Decision per candidate (classifier, k = 5) | none existed | $0.0032 per evaluated candidate on the injection slice; $0.0027 to $0.0032 across six families | `2026-10-01-decision-engine-injection-slice/record.json`, `2026-10-02-decision-engine-slice-2/record.json` |
| An A/B arm, per candidate | none existed | $0.0021 (temperature sampling) against $0.0051 (retrieval ensemble); the cheaper arm won | `benchmarks/experiments/exp-002-retrieval-ensemble/result.json` |
| Harvest of plane signals for the engine | none existed | `verify` $2.5373 over 1,961 calls and 474 tasks; `roles` $1.4036 over 1,034 calls and 151 tasks | `2026-10-01-decision-engine-harvest/record.json` |
| Development transcript, tool I/O share | 90% | 85.5% over 2,701 tool calls (`dev_token_report`) | `plane-increment-1.json` |

Two notes from the records. The meter prices every call at the Model's list price
(`plane/models/deepseek-flash.yaml`); the DeepSeek account moved less, about one third of the
metered amount on the injection slice ($0.30 for $0.91 metered), and budgets and gates are set
against the meter, never against the balance. And the development share barely moved: 90 to 85.5
is a small gain, and the remedies (a read guard, a bulk reader, scripts in files) target file
contents because that is where the tokens go.

## 5. Open items

Five groups, each item with its record: the engine's own gates, data, measurement debt,
infrastructure, and instrument gaps.

The engine's gates.

- BLOCK is reachable for no family: calibration fails for five (ECE 0.071 to 0.119) and the
  sixth reaches no fold with a Wilson lower bound of 0.95 on precision (slice-2 record).
- Re-run agreement is below 0.9 for three families: injection 0.77, access control 0.83,
  untrusted destination 0.87. exp-002 tried the obvious variance fix and lost on the ranking.

Data.

- Positives-only groups: 98 (family, group) pairs in the 904-example memory hold positive examples
  and no negative. 94 of them exist because the fixed side no longer has the function (the vibe-py
  pairs). No advisory-fixes group is among them
  (`benchmarks/measurements/2026-10-02-decision-engine-negatives-gap/record.json`). There are no
  single-label negatives, so every family's pooled AUC is inflated by positives that never had to
  be told apart from their own fix (slice-2 record, `paired_groups_check`).
- The model has seen public fixes. A verify pass named the advisory's CVE id for a public fix, an
  observation the engine's design specification (maintainer tooling) records as visible
  memorisation. Excerpts now redact advisory ids and security-worded comments
  (`src/openultrasast/learn/excerpt.py`), but labels drawn from public advisories are partly in the
  model's training data, and the within-pair numbers carry that.
- PHP is covered by the engine on real code and by in-sample quick rules; the population that
  would measure it (v3) is reserved.

Measurement debt.

- exp-001 (known callers) is registered and has not run; the model-free candidate generation on
  the 41 development repositories that its units need is not built
  (`benchmarks/experiments/exp-001-known-callers/registration.json`).
- Leave-one-source-out, leave-one-framework-out and the memory-size curve points (0, 25, 50%)
  have not run; one paired point exists (724 against 904 examples, injection, AUC 0.76 against 0.77).
- The plane-profile leak audit flagged `verify.flag_b` and `ms.operation`; they are withheld from
  profile v1, and whether they track the label on unseen code has to be decided before any
  plane-profile program runs (`2026-10-02-decision-engine-harvest-advisory/record.json`).
- Population v3 waits for `benchmarks/independent/prediction-v3.json`, which does not exist. It is
  written only after a program is adopted.

Infrastructure.

- Deployment to a separate Kubernetes cluster is planned, not done; the code changes it needs are
  listed with file paths on [Deployment](deployment.md#what-is-implemented-and-what-is-planned).

Instrument gaps.

- A missing provider key is a quiet path in a scan. The plane refuses to start a Task whose Model
  names an unset variable (`plane/router.py`, `StartError`). A scan without a key asks the model
  nothing, reports only the graph's entailed findings, and records `learning_endpoint_unavailable`
  in `manifest.json` (`cli.py`, after `resolve_chat_endpoint` returns nothing); `report.md` has no
  line for that reason yet, so the report does not say the model layer was skipped.
