# Evaluation protocol v2 for the independent population v2 (pre-registered)

Written and committed on 2026-09-26, BEFORE the first scan of any case in `population-v2.toml`. It fixes what is
measured, how a result is scored and what is reported, so that no rule of the scoring can be chosen after seeing
an outcome. Changing it after the first scan makes the run exploratory, and it must then be reported as such.

Differences from protocol v1, each decided by the maintainer before any v2 case was scanned, and each a lesson
of the v1 run rather than of any v2 case:

- **Declared sites.** v1 credited a finding only in a file the fix changed. alerta and YesWiki (v1) execute their
  SQL in a helper the fix does not touch, so a correct report where the query runs could never count. Each v2
  case therefore declares, from its advisory and before any scan, the `sites` (`path::function`) where the
  vulnerable operation happens; a finding there is credited too.
- **Two runs.** The engine's path selection is not deterministic: on v1 retunes one verdict flipped in 2 of 4
  identical runs, and a PMPro finding came and went between runs. The vulnerable and the fixed pin are scanned
  twice each, and the difference is reported.

## What is under test

- The analyzer at the commit that introduces the v2 evaluation runner, exported with
  `benchmarks/push/freeze_source.sh`; its hash is recorded in the result.
- Per case, only the case's own family (`injection`, `untrusted_destination` or `config_secrets`), through the
  production discovery and scan (`benchmarks/push/finding_dump.py`), unbounded region count (5,000), a 2,400 s
  deadline per scan, one engine container at a time.
- Six scans per case: the vulnerable pin twice (runs a, b), the fixed pin twice (a, b), the benign base and the
  benign tip once each. Each checkout is a `git archive` of the pin, with no project tooling run on it.

## Scoring, per case

A finding MATCHES the case when its family is the case family and either
1. its file is one the fix changes (`git diff --name-only vulnerable fixed`) and either its function is one the
   record names in `sites`, or its line lies within 10 lines of a hunk the fix changes on that side (v1's rule);
   or
2. its `path::function` equals one of the record's declared `sites` (`<global>` for file scope).

- **Detected** (recall): a matching finding in BOTH vulnerable runs.
- **Unstable detection**: a matching finding in exactly one vulnerable run. Reported; counts as NOT detected.
- **Fixed-side false alert**: a matching finding in EITHER fixed run.
- **Benign false alert**: any finding of the case family at the benign tip whose (file, function) has no finding
  at the benign base.
- **Unanswered**: neither vulnerable run completed a question covering a file the fix changes or a declared site
  file. It counts as NOT detected, and the reason is reported. A scan with no questions at all, or unreadable
  input, is an instrument failure: it is rerun once, and if it fails again it is reported as a failure, never as
  a clean result.

## Stability

Per pin with two runs, the findings present in exactly one run divided by the findings present in either is
reported, per case and pooled. It is not a gate; it says how far a single run can be trusted.

## Precision

All findings of the case family present in BOTH vulnerable runs, across the population, are pooled and sorted by
(case, site). Every third one, starting from the first, is adjudicated against the source, as are all of them if
the pool holds 15 or fewer. Findings present in only one run are counted and reported, not adjudicated. The
standard is v1's:

- **True**: attacker-controlled data reaches the sink without a sufficient guard.
- **True, privileged**: the same, reachable only with a privileged role.
- **False, guarded**: a guard makes the flow safe.
- **False, not attacker**: the value does not come from an attacker.

The matched case findings are part of the pool and are adjudicated like any other.

## What is reported

Per case: detected / unstable / unanswered, fixed-side and benign false alerts, completion (questions completed /
total) for each of the six scans, stability, and seconds. Overall:

- recall with a Wilson 95% interval;
- sampled precision with a Wilson 95% interval;
- total fixed-side and benign false alerts;
- completion over all scans;
- pooled stability.

These are reported against the M4 profile: at least 95% precision, at least 90% recall, at least 95% completion,
and zero fixed or benign false alerts. A gate that is not met is reported as not met.

## What may not happen

- No rule, fact, query or scoring change informed by these results before the result is committed.
- Any change made after it is a retune. A retune can only be qualified on a NEW untouched population.
- No result of a case whose licence is marked "verify" is published until the licence is checked.
  - 2026-10-02: the five v2 cases that carried the "verify" marker were checked read-only at their pinned
    vulnerable commits (LICENSE / license.txt / plugin header `License:` line via the GitHub API) and the
    `license` field now records the SPDX id with the evidence: pgadmin-maintenance-sqli is PostgreSQL;
    wp-gopay-log-filter-sqli is GPL-2.0-or-later; wp-user-registration-login-redirect, wp-directorist-avatar-ssrf
    and wp-groundhogg-confirm-redirect are GPL-3.0-or-later. All five are OSI-approved. The OpenCVE case in v1
    is BSL-1.1, which is not OSI-approved; non-production use is permitted by its Additional Use Grant, and its
    change date is 2030-08-14 (to Apache-2.0).
