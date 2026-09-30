# Threat model & hardening

OpenUltraSAST analyzes **untrusted code**. This document states what it trusts, what
it does not, and the controls that keep a scan safe to run in CI and safe to share.

## Trust boundaries

- **Scanned code is untrusted input, never executed.** Quick and standard modes read
  source as text (regex rules, evidence ladder, optional LLM review). They never import,
  build, or run the target. Only `deep` mode would execute target-derived code, and only
  inside the sandbox below — and deep mode is not yet implemented (it exits with a clear
  message rather than running anything).
- **The ruleset and CWE policy are trusted, governed data.** They change only through
  reviewed commits or the bounded self-improvement loop (`ousast improve`), which can
  flip rule *status* and tune score constants but can never edit pattern text or the
  authoritative 0–5 severity. See the self-improving cycle in the README.
- **Provider credentials are the operator's.** The zero-dependency core makes no network
  calls. A local scan calls a model only for the optional `[models] hunter` tool hunter
  in standard mode. Agentic work runs on the plane (`ousast plane run`): `ousast` reads
  the variable a task's Model names (`secretKey.key`) from the operator's environment or
  `.env` and sends the key only in that task's start request, through Agent Substrate's
  router to that task's actor. It is not baked into an image or task template, and it is
  never logged or written to artifacts.

## Controls

### Secret redaction
Scan artifacts can quote source that contains live credentials. `redaction.py` masks
recognizable secret shapes (provider API keys, AWS/GitHub/Slack/Google tokens, bearer
tokens, URL-embedded credentials, PEM private keys, and `key = value` assignments for
sensitive names) before traces (`trace/events.jsonl`) and the markdown report are
written. On by default; disable with `[hardening] redact_secrets = false`.

### Plane egress
Each plane task runs in its own actor behind Agent Substrate's egress gateway, which
denies by default. The task's EgressPolicy (`src/openultrasast/plane/egress.py`) allows exactly three
things: plain HTTP to the artifact receiver, and TLS passthrough to the Git hosts of the
task's bound Workspaces and to the hosts its bound Model declares
(`openultrasast.io/egress-hosts`). There are no wildcards, no IP addresses and no TLS
interception. The policy is deleted with the actor.

### Cost & CI budgets
- **Agentic spend** is bounded per plane task by the Run's `budget: {usd, calls}`. The
  metered client refuses the next call once either ceiling is reached (the task is
  `unfinished` and resumes on a rerun with a larger budget). A usd budget on a Model
  without prices is refused rather than metered as zero, and an account or
  authentication error fails the task and starts nothing further. The standard-mode tool
  hunter is bounded by the per-tier hunter budgets.
- **Output size** is bounded by `[hardening] max_findings` (0 = unlimited). Truncation is
  severity-ordered and disclosed as a `budget` degradation in the manifest.

### Provider reliability
LLM/embedding calls retry transient failures (HTTP 429/5xx, connection errors, timeouts)
with exponential backoff; non-transient errors (e.g. 4xx, malformed JSON) fail fast.

### Visible degradation & determinism
When an optional capability is missing (the extra, a model, a provider key), the scan
falls back to its deterministic equivalent and records a `degradations` entry in the
manifest — it is never silently downgraded. Runs are reproducible: fixed config,
artifact manifests, prompt hashes, and model identifiers are recorded.

### MCP surface
`ousast mcp` exposes only the ten narrow project tools. No tool runs arbitrary shell,
Docker, or internal hunter tools, and no tool accepts a free-form command argument.

## Sandbox limits (deep mode, when implemented)

Dynamic analysis runs under the bounds in `[sandbox]` (`config.SandboxConfig`):

| Control | Default |
|---|---|
| network | disabled (`network = false`) |
| workspace | read-only (`workspace_readonly = true`) |
| memory | 2048 MB (`memory_mb`) |
| pids | 512 (`pids_limit`) |
| timeout | 300 s (`timeout_seconds`) |

Dynamic probes additionally declare their network scope, log commands, and capture
artifacts; a hardened runtime (e.g. gVisor) is used when available. Until deep mode
ships, no target code is executed at all.
