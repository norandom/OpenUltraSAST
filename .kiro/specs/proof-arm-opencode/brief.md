# Brief: OpenCode-MCP proof arm (follow-up to search-with-proof)

Status: brief / not yet specced. Proposed 2026-10-07 by the maintainer. Builds on
`search-with-proof` (see `../search-with-proof/verification-architecture.md`).

## Motivation

The search arm (directed, Cairn-inspired) works. The **proof-authoring** last mile is the drag:

1. **Safety-classifier refusals.** Authoring exploit demos repeatedly tripped a safety classifier
   this session when exploit payloads or step-by-step attack prose passed through the model or a
   tool prompt. The mitigation so far (keep payloads on disk, treat demos as opaque) is a workaround,
   not a fix, and it limits how directly the proof model can reason about the exploit.
2. **Nondeterministic wiring.** The agent authors a demo but intermittently mis-wires the app to
   the oracle fixture (served directory for path, database URL for SQL), so a demonstrable pair
   comes back inconclusive until a retry. Each miss has cost a paid run.

Proposal: drive the proof with an **agentic coding tool (OpenCode MCP)** running **inside gVisor**,
using a model chosen for exploit authoring rather than one that refuses it, and **learn** the
proof-authoring policy with DSPy from **traces logged in OpenObserve**.

## Shape

- **Search model:** DeepSeek (current). Good at the directed fact/intent search.
- **Proof model:** GLM 5.3 (Anthropic-recommended) and/or an abliterated model via
  `ABLITERATION_BASE_URL` (`abliterated large v2`). The abliterated model authors exploit **demos**
  without the refusals that block a safety-trained model on this defensive task.
- **Proof driver:** OpenCode MCP (github.com/AlaeddineMessadi/opencode-mcp) as the agentic
  demo-author, running inside the gVisor verification task so the exploit-authoring is sandboxed.
- **Learning:** DSPy compiles/optimizes the proof-authoring program (demo schema, wiring, steps)
  from past traces, instead of the per-family hand-guidance we keep adding (which is now hitting
  the prompt character budget — a signal the hand-rule approach is near its limit). Matches the
  maintainer's "learned decisions, not hand-tuning" direction.
- **Tracing:** proof runs (reason/explore/author/verify, timings, outcomes, error classes) log to
  **OpenObserve AI** at `OPENOBSERVE_URL` (org `OPENOBSERVE_ORG`, stream `OPENOBSERVE_TRACES_STREAM`).
  DSPy consumes these traces as its training signal.
- **Credentials:** stored in `.env` like the existing keys, referenced by name only:
  `ABLITERATION_API_KEY`, `ABLITERATION_BASE_URL`, `ABLITERATION_MODEL`, `OPENOBSERVE_URL`,
  `OPENOBSERVE_ORG`, `OPENOBSERVE_TRACES_STREAM`, `OPENOBSERVE_TOKEN`. No secret value ever enters a
  tracked file, a prompt, a log stream, or a commit.

## The trust-domain decision (must be resolved first)

The current design keeps the **model key on the VM only**; cluster tasks carry no secrets and have
restricted egress (verify tasks reach the files host only). Running the proof **model** inside gVisor
(as OpenCode MCP would) breaks both: the task would hold a model key and need egress to the model
API host. Two options:

- **A. Scoped key + egress in the cluster (operator-managed).** Inject a spend-limited proof-model
  key into the proof task (like the existing `gemini-api-secret` slot) and add a per-host egress
  allowlist for the proof-model API. Keeps the fully-sandboxed agentic authoring the maintainer
  wants; requires an operator change and widens the cluster's secret/egress surface.
- **B. Brain on the VM, execution in gVisor (current split preserved).** OpenCode MCP and the proof
  model run on the VM; only the DAST execution stays in gVisor. No new cluster secret or egress;
  but the agentic authoring loop is not itself sandboxed.

Recommendation: start with **B** (no trust-domain change, fastest to try the abliterated proof model
and DSPy loop), and move to **A** only if sandboxing the authoring loop itself proves necessary.

## Security scope (why an abliterated model is in-scope here)

This is authorized **defensive** work: authoring proof-of-concept demos for **known CVE fix-pairs**
in a **gVisor-isolated** corpus, to demonstrate a regression before push. Guardrails to keep:

- Demos are **data**, not agent code; they stay in the gitignored private area, never echoed.
- No real-world or third-party live targets; only the frozen fix-pair corpus and owned oracles.
- gVisor is the execution boundary; the abliterated model never runs code itself, it only writes a
  declarative demo the trusted verifier executes.
- The abliterated model is confined to proof-authoring; the search and all reporting stay on the
  normal models.

## Open questions for the spec

1. A or B for the trust domain (above).
2. Does the abliterated proof model actually raise the demonstrated rate and remove the wiring
   misses, measured on the pairs already shown demonstrable (xiaomusic, glance)? Qualify before scaling.
3. DSPy program shape: what is the proof-authoring signature (inputs: candidate + oracle contract;
   output: a valid, wired demo), and what metric does it optimize (demonstrated rate at zero false
   proofs) from OpenObserve traces?
4. Does OpenCode MCP fit the existing executor/verifier task contract (no-secret, presigned I/O,
   scratch/egress limits), or does it need a new task kind?
5. Cost envelope per proof vs the current DeepSeek authoring.

## OpenCode MCP as the endpoint for both PoC and fix

Maintainer note (2026-10-07): OpenCode MCP is a good server endpoint for the PoC **and** the fix,
not only proof authoring. The same agentic endpoint can:

1. Author the PoC (the demonstrated proof) for a caught finding.
2. Write a candidate fix against the finding's repair direction and the failing PoC.
3. Hand the fix back to the differential verifier, which re-runs the PoC and confirms absence
   (the proof flips from failing to passing).

This turns the "no auto-patch" gap in `../../../docs/use-case-fix-and-reverify.md` into "the proof
endpoint also proposes the fix, and the fix is accepted only when the proof it generated goes green."
The PoC is the acceptance test for the fix, so a wrong fix is caught, not trusted. The fix stays a
proposal for the developer to review; the verifier's green proof is the objective signal, not the
model's say-so. This fix capability is specced alongside the proof authoring when this arm is built.

## Not in scope

Changing the search arm, the oracle differential, or the abstract-interpretation triage. This brief
is about the **proof-authoring and fix** driver and its learning loop, planned as a full spec after
the safety net is qualified.
