# Valid detection benchmark

Created 2026-10-12. This brief **supersedes the frozen-SZZ-pool evaluation** (`unseen-repo-evaluation`), which is retired.
SZZ guessed its labels and placed the vulnerability in the wrong location about half the time (audit: path 1/7,
output-encoding 1/8 sound). Also, ~76% of entries are library-internal (reachability not in-repo). Recall and
false-alarm numbers from that pool are not valid benchmark results. This brief defines a benchmark with
sound ground truth and metrics that engineers and managers can understand.

## The two questions the benchmark answers

A pre-push security check must answer two questions:

1. **If I'm about to push a real vulnerability, does it stop me?**
2. **If my change is fine, does it leave me alone?**

The benchmark measures the **push path** as a developer uses it. The LLM detection tier (the hunter) is
required on pre-push. Today the shipped hook runs quick rules and the engine only, so the benchmark
reports the hook as shipped and the hook plus the hunter arm separately until the hunter is wired in
(see `requirements.md` R6). The repositories are ones the tool has **never seen**.

## What makes the data valid

### Positive cases: "should catch" (real, verified, reachable vulnerabilities)
- Take the label from the security fix, never from SZZ. Use the code *just before* the fix, at the file/function
  the fix changed. The fix establishes the vulnerability location without a blame walk-back or mislocation.
- Keep only app-shaped cases where the vulnerability is reachable from an entry point *inside the repo*. This
  can be a web route or a request handler; a CLI argument also qualifies. Drop library-internal vulnerabilities
  that depend on a caller outside the repo. A pre-push tool cannot see that trust boundary, so scoring it is unfair.
- Verify each case through LLM adjudication and a human spot-check. Confirm (a) that the pre-fix code is
  vulnerable and (b) that the fix addresses it. Also confirm (c) that it is reachable in-repo.

### Negative cases: "should not alarm" (ordinary safe changes)
- Use everyday commits from the **same** application repositories that are not security fixes. They are plentiful
  and cheap to collect. Almost every real push is ordinary, so false alarms determine whether developers keep
  using the tool. The negative set must be much larger than the positive set.

### Held out
- None of these repositories were used to build, train, tune, mine or harvest the tool.

A few dozen vulnerabilities with sound labels and in-repo reachability, each verified, are better than hundreds
of SZZ guesses. SZZ is wrong about half the time. Curating this set takes manual work, supported by the LLM-audit
tooling that found the SZZ pool's defects. Dozens of good cases are enough.

## Metrics someone understands

These are the standard detector metrics. Each row leads with the name a security engineer already knows and
gives the plain-English question it answers.

| Metric | Plain-English question | Example |
|---|---|---|
| **Recall** (true-positive rate) | Of real vulnerabilities, how many did it flag? | "Caught 18 of 20 (90%)" |
| **False-positive rate** | On safe changes, how often does it alarm? | "Flagged 3 of 100 ordinary pushes" |
| **Precision** (positive predictive value) | When it alarms, how often is it real? | "When it speaks up, it's right 8 of 10 times" |
| **Exploit-verified rate** | Of what it flags, how much can it demonstrate with a working proof of concept, not just suspect? | "12 of 18 catches came with a working proof of concept" |

Report the false-positive rate as **false alarms per 100 pushes**, which reflects a developer's experience.
Vulnerabilities are rare among real pushes. Precision depends on that ratio, so a 50/50 test set overstates it.

Report the first two metrics together:

> "On unseen application repos: catches 90% of real vulnerabilities while false-alarming on 3% of ordinary
> pushes."

This wording is easier for a manager to understand than "3/92, Wilson95 1.1–9.2%".

## The gold-standard metric, and the project's edge

**Exploit-verified findings** do not depend on labels. The search-with-proof / differential-exploit arm
demonstrates the bad effect on the vulnerable code and its absence on the fixed code. A working proof of concept
is the ground truth. The headline to aim for is:

> "On unseen app repos: caught and exploit-verified N of M real vulnerabilities, with K false alarms per 100
> ordinary pushes."

The architecture is built to produce this kind of benchmark.

## Why the old approach was not feasible (recorded so it is not re-tried)

- SZZ ground truth is machine-guessed and ~half wrong → every recall or false-positive number off it is noise.
- Library-heavy corpus → most cases are unreachable in-repo, so a pre-push tool is scored on things it
  structurally cannot see.
- Scoring regex-only (engine and LLM off) measured a tier nobody would ship alone.
- Automated harvesting prioritized pool size over sound ground truth and in-repo reachability.

## Open questions for the spec phase

- How many verified positives are enough for a credible recall interval (target set size)?
- The negative:positive ratio that reflects real push traffic (for an honest false-alarms-per-100-pushes).
- Curation workflow: how LLM adjudication + human spot-check are recorded and frozen per case.
- Language/framework coverage of the positive set (be explicit about what is and isn't represented).
