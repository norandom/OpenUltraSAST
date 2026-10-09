# Operator notifications (Discord)

Recorded 2026-10-09 from the maintainer's direction. OpenUltraSAST notifies the operator on
Discord about the status and results of its own processes, and especially when a process is
**stuck or otherwise impaired**. This is an operator channel, not a developer or infrastructure
one.

## Audience

The **system operator** and the **AI operator** who run and oversee the tool. Not developers
debugging the code, and not an infrastructure on-call. The messages answer "is the work moving,
did it finish, what did it produce, is it stuck" for someone supervising a run, not "why does this
function throw".

## Scope: OpenUltraSAST processes and their results

Notify on the actual OpenUltraSAST workloads and what they produce:

- scans and pre-push checks (a completed check and its verdict/degradations),
- unseen-repo sourcing / draft, freeze, and replay / baseline runs,
- learning and evaluation runs (compile, evaluate, experiments) and their recorded results,
- fusion / adjudication and any long-running job.

**Not** k3s or ax cluster infrastructure. Cluster, node, and ax-task health is a separate
infrastructure concern monitored elsewhere; this channel does not carry it. The line is: a message
here is about an OpenUltraSAST process or result, never about the plane's plumbing.

## When to notify

- **Completion:** a process finished, with a one-line result summary (counts, status, digest).
- **Stuck or impaired (the important case):** a stall, a clean-but-short result
  (`insufficient_*`), an abort or `instrument_failure`, a timeout or deadline hit, budget
  exhaustion, or a resource limit (disk, memory). These @mention the operator so a supervised run
  does not sit silently broken.

Advisory and low-volume by design: a start/finish and the impaired cases, not per-step chatter.

## Transport and secrets

A Discord webhook, with credentials referenced by name only and stored in gitignored `.env`, like
every other credential (`.env.example` lists the names, blank):

- `DISCORD_WEBHOOK_URL` — the operator channel webhook.
- `DISCORD_OPERATOR_ID` — the account to @mention on a stuck/impaired alert.

The webhook URL is a secret (anyone holding it can post to the channel): it never enters a tracked
file, a prompt, a log, or a commit, and it is rotated if exposed. Notifications are **off** when the
webhook is unset, so the tool runs the same with or without it.

## Content discipline

Messages carry status, counts, and digests only, under the same redaction as the hardening and
measurement-record conventions: no exploit payloads or request strings, no secrets, no customer
content, no repository contents. A notification is safe to read in a shared channel.

## Status

Policy recorded; the notifier (reading the env-named webhook, quiet when unset, honoring the
redaction above) is to be wired into the process entry points and may be specced separately. Until
then this steering states the intended behavior for any process that adds notifications.
