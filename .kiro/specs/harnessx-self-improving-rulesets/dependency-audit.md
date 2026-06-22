# HarnessX Dependency Dry-Run Audit (Task 5.1)

Recorded realized transitive dependency graph and the accept-vs-vendor decision for
adopting HarnessX (`git+https://github.com/Darwin-Agent/HarnessX.git`) in Phase 3.

## Method

```bash
uv venv /tmp/hx-audit --python 3.11
uv pip install --dry-run --python /tmp/hx-audit/bin/python <HarnessX checkout>
```

- **118 transitive packages** resolved from HarnessX's **30 direct** `[project.dependencies]`
  (all mandatory upstream; the only extra is `dev`).
- Pinned versions observed: `harnessx 0.1.0`, and engine image `registry.dagger.io`/SDK
  unrelated; LLM SDKs `anthropic 0.111.0`, `openai 2.43.0`, `litellm 1.89.3`.

### Realized transitive graph (118)

```
aiofiles aiohappyeyeballs aiohttp aiosignal annotated-doc annotated-types anthropic
antlr4-python3-runtime anyio attrs bracex certifi cffi charset-normalizer click cryptography
distro docker dockerfile-parse docstring-parser e2b et-xmlfile fastapi fastuuid filelock
frozenlist fsspec googleapis-common-protos greenlet grpcio h11 h2 harnessx hf-xet hpack
html2text httpcore httptools httpx httpx-sse huggingface-hub hydra-core hyperframe idna
importlib-metadata jinja2 jiter jsonschema jsonschema-specifications litellm loguru lxml
markdown-it-py markupsafe mcp mdurl multidict omegaconf openai openpyxl opentelemetry-api
opentelemetry-exporter-otlp opentelemetry-exporter-otlp-proto-common
opentelemetry-exporter-otlp-proto-grpc opentelemetry-exporter-otlp-proto-http opentelemetry-proto
opentelemetry-sdk opentelemetry-semantic-conventions packaging pdfminer-six pdfplumber pillow
playwright prompt-toolkit propcache protobuf pycparser pydantic pydantic-core pydantic-settings
pyee pygments pyjwt pypdfium2 python-dateutil python-docx python-dotenv python-multipart
python-pptx pyyaml referencing regex reportlab requests rich rpds-py shellingham six sniffio
sse-starlette starlette structlog tiktoken tokenizers tqdm typer typing-extensions
typing-inspection urllib3 uvicorn uvloop watchfiles wcmatch wcwidth websockets xlsxwriter yarl zipp
```

## Key finding: heavy backends are lazy; ~half the tree is dead weight

Every heavy backend is **lazily imported** — `docker`/`e2b` are `TYPE_CHECKING`-guarded and
imported inside provider factories; `playwright` is imported inside `_get_local_page()`;
office/PDF libs inside `tools/builtin/read.py` parse functions; `sandbox/__init__.py` registers
docker/e2b via `try/except`. The `gateway/` is a **separate distribution**. So the 118-package
tree is an **install-time** cost; at **runtime only what a given agent path touches is loaded**.

This is the answer to "I don't need most of these": neither OpenUltraSAST (SAST) nor the
author's DocuHarnessX (docs) loads the bulk of it — HarnessX simply declares every capability as
a *mandatory* dependency.

| Category | Packages | SAST verdict |
|---|---|---|
| LLM SDKs | anthropic, openai, litellm, tiktoken, tokenizers, huggingface-hub, hf-xet, jiter, regex, tqdm, fsspec | **needed** |
| HTTP / async / pydantic core | httpx(+core/h11/h2/hpack/hyperframe), anyio, aiohttp(+glue), pydantic(+core/settings), certifi, urllib3, requests, sniffio | **needed** |
| Config / CLI / logging | hydra-core, omegaconf, antlr4-runtime, typer, click, rich, prompt-toolkit, structlog, loguru, jsonschema(+glue) | **needed** |
| Browser automation | **playwright, pyee, greenlet, html2text** | **dead weight** (+ out-of-band Chromium binary download via `playwright install`) |
| Sandbox backends | docker, dockerfile-parse, **e2b** | docker = useful (isolate hunter); **e2b = dead weight** |
| Web gateway / Lab UI | **fastapi, uvicorn, starlette, sse-starlette, httptools, websockets, uvloop, watchfiles, python-multipart, aiofiles** | **dead weight** (server surface; never started by a headless embed) |
| gRPC + OpenTelemetry | grpcio, protobuf, googleapis-common-protos, opentelemetry-* (8) | **optional** (tracing only) |
| Office / PDF | **python-pptx, python-docx, openpyxl, reportlab, pdfplumber, pdfminer-six, pypdfium2, pillow, xlsxwriter, lxml, et-xmlfile** | **dead weight** (SAST reads source, not documents) |
| MCP | mcp, httpx-sse | optional (only if the agent calls MCP tools) |

Roughly **55–60 packages are opt-in capability weight** pulled in mandatorily, including a
browser binary and a Docker SDK — an awkward footprint for a supply-chain auditing tool.

## Decision

**ACCEPT HarnessX as the optional, SHA-pinned extra `openultrasast[harnessx]`, lazy-imported
behind `_has_harnessx()`. Keep a pre-specified vendored lean subset as a documented, triggered
fallback. Pursue upstream dependency-extras as the preferred long-term slimming path.**

Rationale:
1. **Footprint is fully opt-in.** Core `dependencies = []` stays zero-dep; the governance /
   scoring / benchmark / detection planes never pull HarnessX. Only `openultrasast[harnessx]`
   installs the tree, and lazy imports keep heavy backends cold unless the path runs.
2. **Author precedent.** DocuHarnessX already ships `harnessx` as a direct git dependency — the
   `ModelConfig.agentic` integration is proven and maintained. OpenUltraSAST reuses the
   mechanism but tightens the posture (opt-in, not direct).
3. **Lower maintenance than vendoring.** Accept + SHA-pin gives reproducibility without a fork;
   vendoring is paid only if the *installed* graph is itself judged unacceptable.

### Preferred long-term: upstream dependency-extras (helps both projects)

The clean fix for "I don't need most of these" is to modularize HarnessX's own dependencies into
extras — e.g. `harnessx[browser]`, `harnessx[sandbox-e2b]`, `harnessx[gateway]`, `harnessx[office]`,
`harnessx[otel]` — leaving a lean agent-runtime core (`anthropic`/`openai`/`litellm`/`pydantic`/
`httpx`/`hydra`/`structlog`/`mcp`). Since the author owns the `Darwin-Agent/HarnessX` line, this is
actionable and benefits DocuHarnessX equally. OpenUltraSAST would then depend on
`harnessx` (lean core) under its `[harnessx]` extra and add only the subsets it needs.

### Vendored lean subset (fallback, fully specified)

If triggered, vendor `harnessx/` only:

- **KEEP**: `core/`, `processors/{control,evaluation,observability,tools,context,memory,multi_model}`,
  `meta_harness/`, `rl/`, `providers/`, `tools/builtin/` (minus `browser.py`/`web_*`),
  `sandbox/{base,local,docker}.py`, plus `config`/`tracing`/`plugins`/`bundles`/`workspace` as needed.
- **REMOVE**: `frontend/`, `gateway/`, `harnessx/api/` (drops the web-server stack), `examples/`,
  `docs/`, `benchmarks/`, `container/`, `scripts/`, `recipe/` (incl. the `recipe/verl_harnessX/verl`
  submodule — clone non-recursive regardless), `extensions/skills/{docx,pdf,pptx,xlsx}` (drops
  office/PDF), `harnessx/sandbox/e2b.py` (drops e2b), `harnessx/tools/builtin/browser.py`
  (drops playwright + browser binary). Net ≈ 40–60% fewer packages, no browser binary.

## Residual risks (security-tool-specific) and mitigations

| Risk | Mitigation |
|---|---|
| `playwright install` fetches a Chromium binary out-of-band (unaudited, breaks hermetic builds) | Browser path is lazy and never invoked; document that `[harnessx]` does not trigger a browser download; lean subset deletes `browser.py` |
| `docker` SDK can reach the Docker daemon socket (privilege boundary) | Docker sandbox **default-off**, `LocalSandbox` default; run untrusted target code only inside the sandbox; SHA-pin docker/cryptography/cffi |
| FastAPI/uvicorn listening-socket surface in a security tool | `api/` server only starts on the explicit `serve` path; add a guard test asserting no server starts on import; lean subset removes `api/` |
| 118-package CVE surface in a supply-chain tool | SHA-pin the entire extra; keep core **zero-dep**; add a **zero-dep CI guard test** (importing `openultrasast` without the extra pulls nothing outside stdlib) |
| `recipe/verl` git submodule recursion | Init non-recursively; never in the accept-as-extra install path |

> Decision date 2026-06-22. The `pip install --dry-run` audit is itself the Phase-3 gate: it is
> re-run before the packaging task (5.2), and if the realized graph pulls a browser binary /
> Docker SDK / FastAPI stack as *mandatory* (non-lazy) deps judged unacceptable, the spec switches
> to the vendored lean subset under the same extra name.
