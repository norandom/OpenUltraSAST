# Threat model & hardening

OpenUltraSAST analyzes **untrusted code**. This page states what it trusts and what it does not.
It also lists the controls that keep a scan safe to run in CI and safe to share.

## Trust boundaries

- **Scanned code is untrusted input.** Quick and standard modes never import, build or run the
  target.
  - Quick mode reads source as text.
  - Standard mode also parses it into a code property graph (a graph of the program's syntax,
    control flow and data flow) with Joern. It uses `joern-parse`, a parser, not a build.
    Standard mode may send code excerpts to the configured model.
  - Only `deep` mode executes target-derived code. Its REGRESS stage loads promoted candidates
    inside the Docker sandbox described below. It runs only when `docker
    info` succeeds (otherwise the stage is skipped and recorded as `sandbox_unavailable`).
- **The ruleset and CWE policy are trusted, governed data.** They change in only two ways:
  through reviewed commits, or through the bounded self-improvement loop (`ousast improve`). The
  loop can flip rule *status* and tune score constants. It can never edit pattern text or the
  authoritative 0–5 severity. See [architecture.md](architecture.md#self-improvement).
- **Provider credentials are the operator's.** The core install (PyYAML only) makes no network
  calls on its own.
  - A local scan calls a model only in standard or deep mode, and only when a key is available.
    The model layer asks the residual question the graph cannot settle. `[models] hunter`
    enables the tool hunter.
  - LLM calls go to DeepSeek (`DEEPSEEK_API_KEY`). OpenRouter (`OPENROUTER_API_KEY`) serves
    embeddings.
  - Keys come from the environment or a gitignored `.env`. `.env` never overrides an exported
    variable.
  - The pre-push check calls a model only with an explicit `--model-config`.
  - Agentic work runs on the plane (`ousast plane run`). `ousast` reads the variable a task's
    Model names (`secretKey.key`) from the operator's environment or `.env`. It sends the key
    only in that task's start request. The request goes through Agent Substrate's router to that
    task's actor. The key is not baked into an image or task template. It is never logged or
    written to artifacts.

## Controls

### Secret redaction
Scan artifacts can quote source that contains live credentials. `redaction.py` masks
recognizable secret shapes before traces (`trace/events.jsonl`) and the markdown report are
written. It masks:

- provider API keys;
- AWS/GitHub/Slack/Google tokens;
- bearer tokens;
- URL-embedded credentials;
- PEM private keys;
- `key = value` assignments for sensitive names.

Redaction is on by default. Turn it off with `[hardening] redact_secrets = false`.

### Plane egress
Each plane task runs in its own actor behind Agent Substrate's egress gateway. The gateway denies
by default. The task's EgressPolicy (`src/openultrasast/plane/egress.py`) allows exactly three
things:

1. plain HTTP to the artifact receiver;
2. TLS passthrough to the Git hosts of the task's bound Workspaces;
3. TLS passthrough to the hosts its bound Model declares (`openultrasast.io/egress-hosts`).

There are no wildcards, no IP addresses and no TLS interception. The policy is deleted with the
actor.

### Cost & CI budgets
- **Agentic spend** is bounded per plane task by the Run's `budget: {usd, calls}`.
  - The metered client refuses the next call once either ceiling is reached. The task is then
    `unfinished`. It resumes on a rerun with a larger budget.
  - A usd budget on a Model without prices is refused. It is not metered as zero.
  - An account or authentication error fails the task and starts nothing further.
  - The standard-mode tool hunter is bounded by the per-tier hunter budgets.
- **Output size** is bounded by `[hardening] max_findings` (0 = unlimited). Truncation is
  severity-ordered. It is disclosed as a `budget` degradation in the manifest.

### Provider reliability
LLM/embedding calls retry transient failures with exponential backoff. Transient failures are
HTTP 429/5xx, connection errors and timeouts. Non-transient errors fail fast, for example 4xx or
malformed JSON.

### Visible degradation & determinism
A scan is never silently downgraded. When an optional engine is missing, the scan falls back to
its deterministic equivalent. It records a `degradations` entry in the manifest (Joern:
`cpg_unavailable`; Docker: `sandbox_unavailable`).

Without a provider key, the model layer asks no question. It reports only what the graph
entailed.

Runs are reproducible. The fixed config, artifact manifests, prompt hashes and model identifiers
are recorded.

### MCP surface
`ousast mcp` exposes only the ten narrow project tools. No tool runs arbitrary shell, Docker or
internal hunter tools. No tool accepts a free-form command argument.

## Sandbox (deep mode)

The REGRESS stage (`regress/`, `sandbox/runner.py`) runs each snippet with `docker run`. It never
mounts the host Docker socket.

| Control | Setting |
|---|---|
| network | `--network none`, always; a host-network argument is refused |
| source | the target bind-mounted read-only at `/workspace`; root filesystem `--read-only` |
| scratch | a tmpfs at `/scratch` for the snippet |
| user | non-root `65534:65534`, `--cap-drop ALL`, `no-new-privileges` |
| memory | `[sandbox] memory_mb`, default 2048 MB |
| pids | `[sandbox] pids_limit`, default 512 |
| timeout | `[sandbox] timeout_seconds`, default 300 s |

A structural deny-list (`regress/safety.py`) checks each snippet before anything runs. It rejects
a snippet that mentions sockets, curl, host networking or writes under `/workspace`.
