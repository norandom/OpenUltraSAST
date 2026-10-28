# Trace-component ablation -- misses and false alarms (gate 3)

Date: 2026-10-28. Roadmap: `.kiro/steering/roadmap.md`, "measure the trace first", gate 3.
Inputs: gate 1 records (`~/ousast-results/prover/ac-train-1/`), gate 2 judgments
(`~/ousast-results/prover/ac-judge-1/`), ground truth
`benchmarks/valid/train/catalog_access_control.toml` + `pool-train.toml`, clones under
`~/ousast-results/valid/train/hist/`. Selection, not fitting: every label below was
assigned by reading the catalog's pre-fix snippets, the prover records, and the code at
each `base` commit. No model calls, nothing tuned.

## Miss side: all 8 prover misses labeled

Labels say which trace component's absence caused the miss. Coverage counters are
record-level (per fix-change); they are not the same unit as the per-repo aggregates in
gate 1's summary. `reached`/`checked` semantics are read off the records, not re-derived
from prover code.

| repo (CWE) | fix site | coverage shape | class |
|---|---|---|---|
| apache/seatunnel (306) | JettyService ctor, SeaTunnelServer.init -- Jetty built programmatically | 0 entry points, frameworks {} | A: entry facts absent |
| friendsofflarum/byobu (863) | Flarum JS User.js controls gating (client-side) | 0 entry points, framework_unrecognised | A: entry facts absent (JS; arguably outside the server-side trace's object space) |
| jenkinsci/git-plugin (306) | GitStatus.doNotifyCommit build trigger | 26 ep, 1 reached, 0 checked | B: operation facts absent |
| jenkinsci/p4-plugin (862) | P4Hook.doChange/Submit/doEvent, ReviewAction.doBuild* | 60 ep, 5 reached, 0 checked | B: operation facts absent |
| jenkinsci/analysis-core (862) | DefaultGraphConfigurationView.persistValue | 8 ep, 1 reached, 0 checked | B: operation facts absent |
| jenkinsci/global-build-stats (284) | doJson/doPython data exposure | 25 ep, 2 reached, 0 checked | B: operation facts absent |
| jenkinsci/crx-content-package-deployer (285) | doFillCredentialsIdItems form-fill | 2 checked, 2 discharged: dominating [ownership_check, path_guard] | C: guard too coarse (real fix adds form-fill ACL) |
| kimai/kimai (284) | InvoiceController preview/create, voter | 2 checked, 2 discharged: dominating [path_guard] | C: guard too coarse (real fix adds voter); 4 of 6 locations in JS/repo/voter layers also uncovered (mixed A) |

**Miss taxonomy: A (entry facts) = 2, B (operation facts) = 4, C (guard too coarse) = 2.**
B-class shape is consistent: Stapler entry found and reached, zero operations recognized
inside -- the doX-method side effect (build trigger, data exposure, persistence) is not
in the operation table. C-class: a guard is resolved and discharges the trace, but it is
weaker than the check the fix actually added.

## False-alarm side: 12 of 64 judge-kept false pushes sampled (seed 20261028)

One kept finding per push, code read at `base`. One skipped and resampled: crx
6a035b60, whose finding cites BuildPackageBuilder.java, absent from the analyzed tree --
itself an instrument defect (stale path anchor), observed once, outside the counts.

| repo | base[:8] | label | evidence (condensed) |
|---|---|---|---|
| dependency-track | e307ddf5 | guard_present_unmodeled | doTestConnectionJob's guard (checkPermission ADMINISTER/CONFIGURE, lines 254-258) is one call deeper in private testConnection(); hops stopped at the do* wrapper |
| shopperlabs/shopper | b4495d0a | guard_present_unmodeled | save() writes auth()->user()->update() -- receiver IS the ownership check; mount() dereferences auth()->user() already |
| triggerdotdev/trigger.dev | 1cfc296c | guard_present_unmodeled | admin.server.ts throws unless user?.admin (lines 30-32); the trace even recorded this guard (guards_before_call) and still demanded identity_constraint |
| mage-ai x3 | 3dec0c58 / e2ad8de9 / 1c2b5d30 | operation_not_privileged | protected_read projected onto abstract BaseDetailHandler.get; only concrete route is the internal event-matcher config read -- no tenant/credential boundary |
| ec2-plugin | b480e51e | actually_suspicious | doValidateAmi takes caller AWS keys, no checkPermission anywhere; upstream added exactly that + @POST in 2022 (clone commit 5f88eb5d) |
| jiratestresultreporter | d8121222 | actually_suspicious | doValidateProjectKey queries Jira with stored global creds, zero checks in file |
| job-import-plugin | e014efaa | actually_suspicious | RootAction doQuery fetches caller-chosen URL with caller credentials, no ADMINISTER gate -- SSRF-shaped |
| blueocean | 23902bda | instrument_noise | Apache HttpClient.execute labeled sql-access; internal @Restricted client, private ctor |
| hashicorp-vault | 228dd8de | instrument_noise | overload misresolution: flagged VaultAccessor.retrieveVaultCredentials, executed chain goes through VaultHelper's same-name method |
| p4-plugin | e27902ea | instrument_noise | doAutoCompleteStreamName calls no-arg getConnection() (cached field); flagged iserver.connect() in the ConnectionConfig overload -- never on this path |

**Counts: guard_present_unmodeled 3, entry_not_attacker_reachable 0,
operation_not_privileged 3, actually_suspicious 3, instrument_noise 3** (n=12; Wilson 95%
on each quarter: 0.06-0.44 -- wide, treat as shape not rate).

## Synthesis: one lever, both sides

The mirror hypothesis (FAs = guards present but unmodeled) held for only 3/12, and
reachability played no role (0/12). The cross-cutting cause is **interprocedural
resolution**: call depth (guard one call beyond the do* wrapper), overload disambiguation
(vault, p4, blueocean's HttpClient-as-sql-access), honoring guards already recorded
(trigger.dev), and not projecting operations onto abstract base classes (mage-ai). The
same mechanism explains B-class misses (operation never linked to the reached entry) and
C-class misses (coarse guard resolved instead of the precise one). Resolution depth and
precision, not new fact families, is the highest-yield trace component; entry facts
(A-class, 2 repos) are second and partly out of scope (client-side JS).

Label hygiene: 3 of 12 "ordinary" pushes carry genuinely missing permission checks by
modern Jenkins standards (two are the classic descriptor form-validation pattern; one
upstream-fixed in 2022). If a quarter of the 64 kept false pushes are mislabeled, true FA
would be ~10.4/100 -- reported as context only; headline numbers stay as measured.

## Decision input (gate 5)

1. Recall lever: operation recognition through deeper resolution (4 B-class misses) plus
   finer guards for C-class; entry facts only for seatunnel (Jetty programmatic) and
   byobu (JS, scope question).
2. FA lever: resolution precision (overloads, wrapper depth, recorded guards) and
   base-class projection; not the judge (gate 2 showed it inert).
3. Pool defect to carry forward: pre-2019 "ordinary" baselines contain missing-check
   bugs; a later pool refresh should re-audit negatives, or FA numbers will overstate.
