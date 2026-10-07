# Brief: MCP shift-left agent + skills

Status: brief / not yet specced. Proposed 2026-10-07. Delivery surface for the
qualified safety net; builds on the existing `ousast mcp` server and the product
skills. Related: `proof-arm-opencode` (the proof model), `pre-push-safety-net`
(the gate), `unseen-repo-evaluation` (the qualification).

## Motivation

The pre-push hook is the gate. Developers and their coding agents want the same
security feedback **earlier**, while the code is still being written, not only at
push. And in an agent-driven workflow, a mandatory security check is how a human
oversees agents: the agent's output has to clear it before it ships.

Proposal: expose the safety net through an MCP agent and a small set of skills so
an editor or a coding agent can ask for a security read of the changed code on
demand, shift-left, and so a coding agent can be required to pass it before it
proposes a push.

## Shape

- **Transport:** extend the existing narrow MCP server (`ousast mcp`, stdio) that
  OpenCode and other agents already speak. No new network surface; same
  no-secret, bounded contract.
- **What the agent offers:**
  1. Scan the current diff with the static arm (fast, no model, no cluster) and
     return findings scoped to the change, with location and a concrete repair
     direction, not a confidence label.
  2. Triage a finding: explain it in plain terms and whether it is reachable.
  3. Prove on demand: hand the top candidate to the proof arm when a runnable
     harness exists, and return the demonstrated proof-of-concept.
- **Skills:** the existing `openultrasast-scan` and `openultrasast-triage`
  product skills, plus shift-left additions (scan-the-diff, explain-a-finding,
  suggest-a-fix-direction) that a coding agent invokes mid-task.
- **Oversight mode:** a coding agent can be configured to call the scan as a
  required step before it finalizes a change, so security review is automatic
  rather than remembered.

## Control (same model as the hook)

Advisory by default; blocking is opt-in. Budget and a push/call deadline bound
the work. The inline path runs the fast static arm only; heavy proof is explicit
and lane-selected. Models and spend caps stay in `.env`.

## Open questions for the spec

1. Inline latency budget: in-editor feedback must return in seconds, so the
   static arm must be fast on a single diff. What is the time contract, and does
   the large-repo latency problem block it?
2. Return contract: exactly what a coding agent gets back (findings, locations,
   repair direction, optional proof) and how it decides pass/fail in oversight
   mode. The return should be ticket-ready evidence a busy developer can paste
   into the issue tracker to win capacity in a prioritization discussion with a
   product owner, since a reproducible proof is what moves a security fix out of
   the backlog.
3. Does oversight mode need a signed/attestable result so a reviewer can trust
   that the agent actually ran the check?
4. Reuse: the `ousast mcp` tool set already exists; which tools are enough and
   what is genuinely new.

## Scope and sequencing

This is a delivery and adoption surface, correctly **after** the safety net is
qualified on unseen repositories (G0 through G5). It is not a detection change;
it is how developers and agents consume the detection early. The proof model
improvement lives in `proof-arm-opencode`; this brief is the dev- and
agent-facing feedback channel.
