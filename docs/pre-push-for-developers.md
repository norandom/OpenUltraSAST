# Pre-push security for developers

You push code. This checks it for security regressions first. You do not annotate
anything, you do not need a security background, and you do not change how you work.

## The short version

Install a git pre-push hook once. On every push it reads the code you changed,
compares it against the known risks of the frameworks you already use, and warns
you before the push leaves your machine. Where it can build and run your app, it
goes further and proves an issue with a demonstration: a check that triggers the
problem on your change and stops triggering once the problem is fixed. By default
it only advises; it never blocks until you turn blocking on.

## Why this matters now

Your backlog is full and your schedule is not yours. Security findings compete
with feature tickets, and a vague "possible vulnerability" loses that fight every
time: no one gets capacity to chase a maybe. Meanwhile you and your coding agents
ship quickly, and an agent writing code does not pause to audit itself. A
pre-push check is the place to catch a regression that you, or an agent acting
for you, introduced, before it reaches the remote. In an agent-driven workflow it
is the oversight step: the gate that reviews what the agent wrote, every push,
without you having to become the security reviewer.

## From a finding to capacity

The point of the proof is the prioritization conversation, not just your terminal.

A theoretical warning dies in the backlog. A demonstrated proof does not: it is a
reproducible check that triggers the problem on the current code and stops once
the code is fixed. That is the thing you take to a product owner or to the
business when you need capacity. It turns "security thinks this might be a
problem" into "here is the exact input, the exact behavior, and the one-line
difference that stops it," which is something a product owner can weigh against a
feature with real information instead of fear.

So the output is built to drop into your ticket system as evidence: a location, a
concrete repair direction, and, where the app is runnable, the reproduction
itself. That is what gets a fix scheduled rather than deferred.

## What you do

1. Install the hook in a repo: `ousast pre-push install`.
2. Push normally. Findings print at push time.
3. Optionally set model keys and a spend cap in `.env`; nothing else is required.

No code annotations. No markup. No per-project security config.

## How it decides, without annotations

- **The tool brings the security knowledge.** It ships framework facts: the
  sources, sinks, sanitizers, and guards for common frameworks. Your code does
  not declare any of this.
- **It looks only at your change.** It builds a graph of the changed code and
  checks it against those framework facts, scoped to the diff, not the whole repo.
- **It can prove, not just warn.** When the app is runnable, the proof arm builds
  and runs it and demonstrates the issue by execution, so a finding is a
  reproducible fact, not a confidence score.

## What you control

- **Advisory or blocking.** Advisory by default; `OUSAST_PUSH_MODE=blocking`
  turns it into a gate. Adopt in advisory mode, build trust, then block.
- **Budget and deadline.** One budget covers the whole push; if it runs out you
  get an honest "incomplete coverage" notice, never a made-up verdict.
- **Where proof runs.** Local sandbox, a container, or a shared cluster.
- **Models and spend.** Keys and caps live in `.env`.

## Honest limits

- **Coverage follows support.** It helps where the tool has framework facts and a
  language grammar; outside that it is weak, and third-party or vendor code is not
  analyzed.
- **Large repositories can be slow.** On big codebases the deep analysis can
  exceed a comfortable push deadline today; that is an open engineering problem.
- **Generalization is being measured, not asserted.** Whether it reliably catches
  real regressions and stays quiet on ordinary changes in repositories it has
  never seen is under active measurement. We consider the tool wrong if it misses
  real regressions or alarms on ordinary changes on unseen repositories, and that
  is exactly the catch-rate and false-alarm number the unseen-repo evaluation is
  producing now. Treat the advisory output accordingly until that number exists.

## Where this is going

An MCP agent and skills so your editor or your coding agent gets the same check
earlier, inline, before the push, so feedback arrives while you are still writing
rather than at the gate. See the follow-up spec `mcp-shift-left-agent`.
