# Recognition-coverage target table (valid-detection-benchmark task 7.1, detection-core 8.2)

Manifest-only read of the 12 pilot-pool repositories (package.json / pyproject.toml /
setup.py at repo root); no pool labels read.

| repository | manifest | detected framework deps | in entry vocabulary |
|---|---|---|---|
| bytebase/dbhub | package.json | express | no |
| contentful/contentful-mcp-server | package.json | (workspace-local) | no |
| fastapi-users/fastapi-users | pyproject.toml | fastapi | no |
| i18next/i18next-http-middleware | package.json | express, koa | no |
| imzbf/md-editor-v3 | package.json | - | no |
| jupyter-lsp/jupyterlab-lsp | package.json | - | no |
| matrix-org/matrix-appservice-bridge | package.json | express | no |
| nvbn/thefuck | setup.py | - | no |
| ondata/ckan-mcp-server | package.json | express, @modelcontextprotocol/sdk | no |
| webpack/webpack-bundle-analyzer | package.json | - | no |
| zenitram/malla | pyproject.toml | flask | no |
| zereight/gitlab-mcp | package.json | express, @modelcontextprotocol/sdk | no |

Entry vocabulary today (`mapping/legacy.py` entry_framework): stapler, jetty, servlet,
jaxrs, symfony, livewire, laravel, remix, tornado. **0/12 pilot repos covered.**

First fact-pack target: **express** (5 repos; covers 2 of the 3 in-family access_control
pilot cases: dbhub, matrix). Script: /tmp/opencode/recognition_table_71.py; raw:
table.json.

## Probe 2026-10-30 (engine wiring): handler extraction is the deeper gap

The probe ran with built-in tokens only (pack wiring is package-rooted since this commit); route statements are found (matrix: 10, dbhub: several),
but every one has `defines_handler=False` and a misidentified handler name (`res`,
`None`) on `this.app.get('/health', this.getHealth.bind(this))`-style registrations.
The prover consumes only entries with `defines_handler` + named handler + line, so all
are ignored -- this is why the admission records showed zero frameworks for these repos.
Raw probe: `probe-handler-extraction.txt`. Next increment: `_js_registration` /
`_js_handler_name` must resolve `.bind(this)` and arrow handlers. The express pack is
necessary (patterns) but not sufficient (handler identity).
