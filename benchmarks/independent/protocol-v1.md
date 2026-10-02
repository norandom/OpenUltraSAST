# Evaluation protocol v1 for the independent population (pre-registered)

Written and committed on 2026-09-24, BEFORE the first scan of any case in `population-v1.toml`. It fixes what is
measured, how a result is scored and what is reported, so that no rule of the scoring can be chosen after seeing
an outcome. Changing it after the first scan makes the run exploratory, and it must then be reported as such.

## What is under test

- The analyzer at the commit that introduces the evaluation runner, exported with
  `benchmarks/push/freeze_source.sh`; its hash is recorded in the result.
- Per case, only the case's own family (`injection`, `untrusted_destination` or `config_secrets`), through the
  production discovery and scan (`benchmarks/push/finding_dump.py`), unbounded region count (5,000), a 2,400 s
  deadline per scan, one engine container at a time.
- Four scans per case: the vulnerable pin, the fixed pin, the benign base and the benign tip. Each checkout is a
  `git archive` of the pin, with no project tooling run on it.

## Scoring, per case

A finding MATCHES the case when its file is one the fix changes (`git diff --name-only vulnerable fixed`), its
family is the case family, and either its function is one the record names for the sink or fix site, or its line
lies within 10 lines of a hunk the fix changes on that side.

- **Detected** (recall): at least one matching finding at the vulnerable pin.
- **Fixed-side false alert**: a matching finding at the fixed pin.
- **Benign false alert**: any finding of the case family at the benign tip whose (file, function) has no finding
  at the benign base.
- **Unanswered**: the scan completed no question covering the sink file's function. It counts as NOT detected,
  and the reason is reported. A scan with no questions at all, or unreadable input, is an instrument failure: it
  is rerun once, and if it fails again it is reported as a failure, never as a clean result.

## Precision

All findings of the case family at the VULNERABLE pin, across the population, are pooled and sorted by
(case, site). Every third one, starting from the first, is adjudicated against the source, as are all of them if
the pool holds 15 or fewer. The same standard as the PMPro adjudications applies:

- **True**: attacker-controlled data reaches the sink without a sufficient guard.
- **True, privileged**: the same, reachable only with a privileged role.
- **False, guarded**: a guard makes the flow safe.
- **False, not attacker**: the value does not come from an attacker.

The matched case findings are part of the pool and are adjudicated like any other.

## What is reported

Per case: detected / unanswered, fixed-side and benign false alerts, completion (questions completed / total)
for each of the four scans, and seconds. Overall:

- recall with a Wilson 95% interval;
- sampled precision with a Wilson 95% interval;
- total fixed-side and benign false alerts.

These are reported against the M4 profile: at least 95% precision, at least 90% recall, at least 95% completion,
and zero fixed or benign false alerts. A gate that is not met is reported as not met.

## What may not happen

- No rule, fact, query or scoring change informed by these results before the result is committed.
- Any change made after it is a retune. A retune can only be qualified on a NEW untouched population, as
  release-milestones M4 requires.
- The OpenCVE case is not published until its licence is checked. Checked 2026-10-02: BUSL-1.1 (not OSI; non-production
  use permitted; converts to Apache-2.0 on 2030-08-14). The maintainer decided to publish the case record, which holds
  metadata only (repository, pins, detection) and no OpenCVE code.
