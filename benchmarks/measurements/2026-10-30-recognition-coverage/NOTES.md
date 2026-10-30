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
