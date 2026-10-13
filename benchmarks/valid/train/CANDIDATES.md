# Training-set candidates for the maintainer's spot-check

Generated 2026-10-13 by `benchmarks/valid/train/sourcing.py candidates`. Every location below passed all three
model checks (vulnerable before the fix, fix addresses it, reachable from an in-repo entry point) and waits for a
human accept or reject. Nothing here is a positive until accepted. Accept or reject a location with

    .venv/bin/python -m benchmarks.valid.verify spot-check benchmarks/valid/train/verification.json <id> accept|reject --reviewer <you> --date YYYY-MM-DD

Sites passing: 99 in 28 repositories, 28 positive changes (fix commits); languages: java 21, javascript 5, php 31, python 21, typescript 21

The verifier's entry point is the model's claim, not a checked fact; it is the reason the site passed the reachability check.

## andrea9293/mcp-documentation-server

- advisory: GHSA-6f5r-5672-72j7 (access_control, CWE-306), origin `osv`, ecosystem npm, licence MIT
- fix `37159d4e06b8ee50c3645b2496e3d3f6d32c47f9`, parent (fix^1) `06d28086dd3fe120978bfa4a49a0a93c7bba8449`
- advisory title: @andrea9293/mcp-documentation-server: Web UI API binds to all interfaces without authentication by default

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `andrea9293-mcp-documentation-server-0913a4303cf82c9a` | `src/web-server.ts::startWebServer` (24-41) | typescript | startWebServer -> app.listen(PORT) binding all interfaces; HTTP routes GET /api/documents, POST /api/documents, DELETE /api/documents/:id, POST /api/search-all, GET /api/config | 0.9 |

## apache/atlas

- advisory: GHSA-v73p-f52r-fmmr (output_encoding, CWE-80), origin `osv`, ecosystem maven, licence Apache-2.0
- fix `800f979307d6ea0f0b6563ec890f6b728022e497`, parent (fix^1) `e67cc199e61afc92f242cccd05e97a61e0791bd2`
- advisory title: Apache Atlas UI: Authenticated User XSS

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `apache-atlas-3f751971e2a63d2e` | `dashboardv2/public/js/views/search/SearchResultLayoutView.js::function` (34-1474) | javascript | SearchResultLayoutView.getFixedDslColumn / getDaynamicColumns formatters rendering entity attributes via Backgrid Html cells; source is search API response entity attributes (e.g. name, typeName, cust | 0.55 |
| `apache-atlas-42a370a3cdec7d12` | `dashboardv2/public/js/views/site/Header.js::function` (27-347) | javascript | Header view onRender: that.$('.userName').html(Globals.userLogedIn.response.userName) renders the authenticated user's userName via .html() (DOM XSS sink); source is the logged-in user's userName from | 0.75 |
| `apache-atlas-4c582bc549c555a1` | `dashboard/src/components/FilterQuery.tsx::clearQueryAttr` (97-503) | typescript | React route /search/searchResult (FilterQuery component); source: URL query string via location.search / URLSearchParams, attacker-controlled filter params (type, tag, relationshipName, entityFilters, | 0.55 |
| `apache-atlas-940ab56a7aadcda1` | `dashboardv2/public/js/views/search/RelationSearchResultLayoutView.js::function` (33-820) | javascript | Backbone Marionette view RelationSearchResultLayoutView rendering relationship search results; data from relationship search API (getBasicRearchResult/fetch) flows into Backgrid Html cell formatters ( | 0.55 |

## apache/pdfbox

- advisory: GHSA-jjwr-xmw6-gf78 (path, CWE-22), origin `osv-extend`, ecosystem maven, licence Apache-2.0
- fix `b028eafdf101b58e4ee95430c3be25e3e3aa29d7`, parent (fix^1) `daaead9069d562e166918d461191c89773e51f90`
- advisory title: Apache PDFBox has Path Traversal through PDComplexFileSpecification.getFilename() function

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `apache-pdfbox-3dc4e739d0307166` | `examples/src/main/java/org/apache/pdfbox/examples/pdmodel/ExtractEmbeddedFiles.java::try` (66-81) | java | ExtractEmbeddedFiles.main(String[] args) CLI argument args[0] (PDF file path); embedded filename from PDComplexFileSpecification.getFilename() flows into extractFile(filePath, filename, embeddedFile) | 0.9 |
| `apache-pdfbox-56ad35de6b5478ab` | `examples/src/main/java/org/apache/pdfbox/examples/pdmodel/ExtractEmbeddedFiles.java::extractFilesFromPage` (84-104) | java | main(String[] args) CLI: args[0] PDF file path; embedded file names from PDComplexFileSpecification.getFilename() flow into extractFile | 0.9 |
| `apache-pdfbox-7d8d6513c163f5fe` | `examples/src/main/java/org/apache/pdfbox/examples/pdmodel/ExtractEmbeddedFiles.java::main` (56-83) | java | ExtractEmbeddedFiles.main(String[] args) CLI argument args[0] (PDF file path); embedded filename from PDComplexFileSpecification.getFilename() in PDF content reaches extractFile | 0.9 |

## codecov/codecov-python

- advisory: GHSA-h3qr-fjhm-jphw (injection, CWE-88), origin `osv-extend`, ecosystem pip, licence Apache-2.0
- fix `2a80aa434f74feb31242b6f213b75ce63ae97902`, parent (fix^1) `73b1b138ec40912eee6fed02636be6011105706e`
- advisory title: Codecov does not sanitize gcov arguments

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `codecov-codecov-python-261567376b9ecd8e` | `codecov/__init__.py::main` (209-805) | python | codecov/__init__.py:main() CLI entry point; attacker-controlled source: --gcov-args / --gcov-exec / --gcov-root CLI arguments (argparse) flowing into cmd string passed to try_to_run (popen) | 0.9 |

## cyanheads/git-mcp-server

- advisory: GHSA-3q26-f695-pp76 (injection, CWE-77), origin `osv-extend`, ecosystem npm, licence Apache-2.0
- fix `0dbd6995ccdf76ab770b58013034365b2d06c4d9`, parent (fix^1) `f30169ec3a2520990e5467c19ef42ea7d6d9270e`
- advisory title: @cyanheads/git-mcp-server vulnerable to command injection in several tools

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `cyanheads-git-mcp-server-07d42f8af21c4e1d` | `src/mcp-server/tools/gitClone/logic.ts::gitCloneLogic` (69-278) | typescript | MCP tool git_clone (gitCloneLogic) invoked via MCP tools/call with attacker-controlled input.targetPath/repositoryUrl/branch reaching child_process.exec | 0.85 |
| `cyanheads-git-mcp-server-3c306de22fb76061` | `src/mcp-server/tools/gitInit/logic.ts::gitInitLogic` (63-227) | typescript | MCP tool git_init (gitInitLogic) invoked via tools/call with input.initialBranch | 0.9 |

## cyface/django-termsandconditions

- advisory: GHSA-6rmf-cv6p-4h27 (untrusted_destination, CWE-601), origin `osv-extend`, ecosystem pip, licence BSD-3-Clause
- fix `03396a1c2e0af95e12a45c5faef7e47a4b513e1a`, parent (fix^1) `c131a1b1daab533ece466f12d79a9ff903c9cacc`
- advisory title: Terms and Conditions Module vulnerable to Open Redirect

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `cyface-django-termsandconditions-1b3a86185cb651c3` | `termsandconditions/views.py::form_valid` (154-185) | python | EmailTermsView at url /terms/email; GET parameter returnTo flows via get_initial into form initial, then form_valid sets self.success_url from form.cleaned_data['returnTo'] without validation, causing | 0.85 |
| `cyface-django-termsandconditions-387ba4069e5df737` | `termsandconditions/views.py::post` (76-124) | python | AcceptTermsView.post at URL /terms/accept, reading request.POST['returnTo'] | 0.85 |
| `cyface-django-termsandconditions-8ee6351ba4d07811` | `termsandconditions/tests.py::test_accept_redirect_safe` (245-259) | python | POST /terms/accept/ with returnTo parameter handled by termsandconditions/views.py returnTo function | 0.85 |
| `cyface-django-termsandconditions-95885d31451074da` | `termsandconditions/tests.py::test_accept_redirect_unsafe` (260-270) | python | POST /terms/accept/ with returnTo parameter (termsandconditions/views.py returnTo function) | 0.85 |
| `cyface-django-termsandconditions-d51b737f5af17360` | `termsandconditions/views.py::get_initial` (67-75) | python | AcceptTermsView at url /terms/accept; GET parameter returnTo read via self.request.GET.get("returnTo", "/") in get_initial | 0.85 |

## datamodel-code-generator/datamodel-code-generator

- advisory: GHSA-77xj-x4rm-935c (path, CWE-22), origin `osv`, ecosystem pip, licence MIT
- fix `5e94b8f4203198798ec66b8e48217f70af69a0dc`, parent (fix^1) `834731d56c0a90c182a0919f316069cf5ff0659a`
- advisory title: datamodel-code-generator: Protobuf weak-import path traversal allows files to be written outside the temporary directory

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `datamodel-code-generator-datamodel-code-generator-bd146f812470891a` | `src/datamodel_code_generator/parser/protobuf.py::_write_missing_weak_imports` (383-395) | python | CLI: datamodel-code-generator --input-file-type protobuf --input <attacker-controlled .proto> (or --url); source: WEAK_IMPORT_PATTERN capture group from the proto text reaching _write_missing_weak_imp | 0.9 |

## docling-project/docling

- advisory: GHSA-p3fw-7699-7926 (config_secrets, CWE-522), origin `osv`, ecosystem pip, licence MIT
- fix `5e469137f275ffc443306a30d12a3a45bceb80fb`, parent (fix^1) `efaf9edd61363ef7239a49ba8e6b349ee219268f`
- advisory title: Docling: Configured HTTP headers sent to every remote image host named by a document

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `docling-project-docling-442cf60d08eedb5a` | `docling/cli/main.py::convert` (769-1181) | python | CLI command `convert` (docling/cli/main.py) with `--html-image-headers` and `--html-image-fetch remote\|all`; attacker-controlled source is the untrusted HTML document's `<img src>` URL | 0.85 |
| `docling-project-docling-6fdb354a87a33a5b` | `docling/backend/html_backend.py::_render_with_browser` (1004-1208) | python | HTMLBackend._render_with_browser via HTMLBackendOptions(enable_remote_fetch=True, fetch_images=True, headers=...) / CLI --html-image-headers with --html-image-fetch remote\|all; attacker-controlled so | 0.75 |
| `docling-project-docling-e161c7347b530396` | `docling/backend/html_backend.py::_route_request` (1044-1054) | python | HTMLBackend._route_request via HTMLBackendOptions(enable_remote_fetch=True, fetch_images=True, headers=...) / CLI --html-image-headers with --html-image-fetch remote\|all; attacker-controlled source i | 0.75 |

## dtwang/line-desktop-mcp

- advisory: GHSA-4hf8-5mjm-rfgq (access_control, CWE-306), origin `osv`, ecosystem npm, licence MIT
- fix `680617894981ea93f8f6ceb51ecde7519754d501`, parent (fix^1) `4023b0c85004507e28ae08999aac689293db63a5`
- advisory title: Streamable HTTP mode exposes LINE Desktop read/send tools without MCP authentication

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `dtwang-line-desktop-mcp-11072dcfdfa41a45` | `src/server.js::parseArgs` (575-607) | javascript | CLI --http-mode --port 3000 binds Express app to 0.0.0.0 and exposes POST /mcp Streamable HTTP endpoint without authentication | 0.9 |
| `dtwang-line-desktop-mcp-b9429141072345c4` | `src/server.js::run` (438-574) | javascript | Express app.all('/mcp') handler in LineDesktopMCPServer.run() invoked via CLI --http-mode --port; attacker-controlled source is the unauthenticated HTTP POST to /mcp (req.body initialize / mcp-session | 0.9 |

## flytohub/flyto-core

- advisory: GHSA-c9hr-64h3-gxpc (untrusted_destination, CWE-918), origin `osv`, ecosystem pip, licence Apache-2.0
- fix `0a0a528520ec18f5a21f1ddf858a71cc1edfb6e9`, parent (fix^1) `2471c6e774102fcca21c61eb66cae057c0f0cecf`
- advisory title: Flyto2 Core: Guarded HTTP modules follow redirects into internal space without per-hop SSRF revalidation

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `flytohub-flyto-core-9648472ee6b1bd21` | `src/core/modules/atomic/http/request.py::http_request` (280-398) | python | execute_module http.request {url: attacker-controlled} -> http_request() -> session.request(method, url, allow_redirects=True) follows 302 into internal space | 0.85 |
| `flytohub-flyto-core-c57a8e72e5f62c6f` | `src/core/modules/atomic/http/get.py::http_get` (85-125) | python | execute_module http.get with attacker-controlled url parameter (http_get in src/core/modules/atomic/http/get.py) | 0.85 |

## graphql/graphql-playground

- advisory: GHSA-59r9-6jp6-jcm7 (output_encoding, CWE-79), origin `osv-extend`, ecosystem npm, licence MIT
- fix `b8a956006835992f12c46b90384a79ab82bcadad`, parent (fix^1) `5073062f3834bb8652c0c0e3297ad83ddc8ad867`
- advisory title: XSS vulnerability in GraphQL Playground from untrusted schemas

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `graphql-graphql-playground-8a960cf0662c724e` | `packages/graphql-playground-react/src/components/Playground/onHasCompletion.tsx::renderType` (136-138) | typescript | GraphQL Playground endpoint query parameter (?endpoint=...) loading a malicious schema; introspection type names reach renderType via onHasCompletion autocomplete, then injected through information.in | 0.85 |
| `graphql-graphql-playground-8ab7cfafbc027403` | `packages/graphql-playground-react/src/components/Playground/SchemaFetcher.ts::getSchema` (95-166) | typescript | SchemaFetcher.fetchSchema via endpoint query parameter (session.endpoint) loading a malicious schema | 0.75 |
| `graphql-graphql-playground-94e027d23fc54155` | `packages/graphql-playground-react/src/components/Playground.tsx::UNSAFE_componentWillReceiveProps` (215-253) | typescript | GraphQL Playground React app loaded via graphql-playground-html/middleware; endpoint query parameter (?endpoint=...) sets the schema endpoint, and the fetched introspection schema flows through props. | 0.75 |
| `graphql-graphql-playground-afc7c3fd32fb660f` | `packages/graphql-playground-react/src/components/Playground/onHasCompletion.tsx::onHasCompletion` (15-135) | typescript | GraphQL Playground endpoint query parameter (?endpoint=...) loading a malicious schema; onHasCompletion renders untrusted schema type names via innerHTML | 0.85 |

## hkuds/vibe-trading

- advisory: GHSA-5rmq-chc7-m22f (path, CWE-22), origin `osv`, ecosystem pip, licence MIT
- fix `9454d4a27a763b80e1d6eb5763b86c88e9e4e714`, parent (fix^1) `fd767f5c29c72cffe8e3f89c7ff006cb3041397f`
- advisory title: Vibe-Trading file-read tools expose arbitrary server-readable files

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `hkuds-vibe-trading-16a24d8276343ff1` | `agent/src/tools/path_utils.py::safe_user_path` (52-81) | python | POST /sessions/{sid}/messages -> LLM tool registry -> ExtractShadowStrategyTool (journal_path) -> safe_user_path | 0.85 |
| `hkuds-vibe-trading-866d7a8070276364` | `agent/src/tools/doc_reader_tool.py::read_document` (259-291) | python | POST /sessions/{sid}/messages -> LLM tool registry -> DocReaderTool.execute -> read_document(file_path) with attacker-controlled file_path from chat message | 0.85 |
| `hkuds-vibe-trading-c16e9e336b3428d7` | `agent/src/tools/backtest_tool.py::run_backtest` (12-64) | python | BacktestTool.execute -> run_backtest(run_dir) via POST /sessions/{sid}/messages LLM tool invocation; run_dir is attacker-controlled via prompt injection | 0.55 |
| `hkuds-vibe-trading-c504e5fd82839ef8` | `agent/src/tools/pattern_tool.py::run_pattern` (305-342) | python | POST /sessions/{sid}/messages -> LLM tool registry -> PatternTool.execute -> run_pattern(run_dir) | 0.55 |

## home-assistant/frontend

- advisory: GHSA-wx4m-69m9-gx3m (output_encoding, CWE-80), origin `osv`, ecosystem pip, licence Apache-2.0
- fix `b8c201b6d34414d30c622797366570185c219614`, parent (fix^1) `4a6c23c93e0cf24c26721090ba168a853b91843f`
- advisory title: Home Assistant: XSS in Statistics Graph Card

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `home-assistant-frontend-588ec87d01bd562c` | `src/panels/lovelace/cards/energy/common/energy-chart-options.ts::formatTooltip` (226-299) | typescript | Lovelace Statistics Graph card (statistics-chart.ts) rendering ECharts tooltip via formatTooltip; source is entity name from getStatisticLabel/computeStateName (attacker-controlled via helper or integ | 0.85 |
| `home-assistant-frontend-589375de71f6b2f2` | `src/panels/config/integrations/integration-panels/zwave_js/zwave_js-network-visualization.ts::customElement` (33-388) | typescript | ZWave JS network visualization panel (zwave_js-network-visualization custom element) tooltip formatter rendering device names via ECharts tooltip | 0.6 |
| `home-assistant-frontend-72bcad0f4ba8aa00` | `src/components/chart/state-history-chart-timeline.ts::render` (66-171) | typescript | Statistics Graph card / state-history-chart-timeline.ts _renderTooltip (seriesName from entity name via getStatisticLabel/computeStateName) | 0.75 |
| `home-assistant-frontend-d7404ee83aa6f810` | `src/components/chart/ha-chart-base.ts::_getSeries` (955-996) | typescript | Statistics Graph card (statistics-chart.ts) rendering entity name via getStatisticLabel -> computeStateName into ECharts tooltip; attacker-controlled source is the entity name set via helper/integrati | 0.85 |
| `home-assistant-frontend-f515548346e64ad5` | `src/panels/lovelace/cards/energy/hui-energy-devices-graph-card.ts::_renderTooltip` (201-282) | typescript | Lovelace Statistics Graph card tooltip formatter (_renderTooltip) rendering entity name from getStatisticLabel/computeStateName; attacker-controlled source is the entity/statistic name set via helper  | 0.85 |

## htmlunit/htmlunit

- advisory: GHSA-3xrr-7m6p-p7xh (injection, CWE-94), origin `osv`, ecosystem maven, licence Apache-2.0
- fix `641325bbc84702dc9800ec7037aec061ce21956b`, parent (fix^1) `d75f21270a20b94c4a49aa0a7dff3f9b7309ca78`
- advisory title: HtmlUnit Code Injection vulnerability

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `htmlunit-htmlunit-2d8f01031e36f7f1` | `src/main/java/com/gargoylesoftware/htmlunit/javascript/host/xml/XSLTProcessor.java::transform` (121-209) | java | XSLTProcessor.transform (JS-exposed @JsxFunction transformToDocument/transformToFragment) invoked from attacker-controlled webpage JavaScript in HtmlUnit browser | 0.75 |

## inventree/inventree

- advisory: GHSA-vx3h-qwqw-r2wq (untrusted_destination, CWE-918), origin `osv-extend`, ecosystem pip, licence MIT
- fix `5759b60a48e7e178fb417a900ed543f29dc5dc86`, parent (fix^1) `7bffa49f3cdd44dffdcf14e11e57db6295273b36`
- advisory title: Inventree Server-Side Request Forgery vulnerability exposes server port/internal IP

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `inventree-inventree-3c189cf58ad5161c` | `src/backend/InvenTree/InvenTree/serializers.py::validate_remote_image` (890-914) | python | RemoteImageMixin.validate_remote_image via DRF serializer field 'remote_image' (URLField) on API endpoints using RemoteImageMixin; attacker-controlled source is the remote_image URL submitted in the r | 0.75 |

## jenkinsci/ansible-plugin

- advisory: GHSA-38hw-368m-7jmg (config_secrets, CWE-311), origin `osv`, ecosystem maven, licence Apache-2.0
- fix `4cbc48657c21a65a917b3b3049918480198c0cfb`, parent (fix^1) `8191fd551ebf606556c730a08eb1d74426dc6257`
- advisory title: Jenkins Ansible Plugin stores and displays secrets in plain text

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-ansible-plugin-4904f1516a63debe` | `src/main/java/org/jenkinsci/plugins/ansible/workflow/AnsiblePlaybookStep.java::convertExtraVars` (376-397) | java | AnsiblePlaybookStep.AnsiblePlaybookExecution.run() invoked via the ansiblePlaybook pipeline step; extraVars parameter (step.extraVars) is attacker/user-controlled and passed to convertExtraVars | 0.75 |

## jenkinsci/dependency-track-plugin

- advisory: GHSA-xfrw-pcmc-r2p3 (access_control, CWE-862), origin `osv-extend`, ecosystem maven, licence Apache-2.0
- fix `70e7b82ad9a10499e628998a0bcb57c1481c66bc`, parent (fix^1) `69317029c8a3eaadc7fe3f5a57de2c364279f612`
- advisory title: Missing permission checks in Jenkins OWASP Dependency-Track Plugin allow capturing credentials

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-dependency-track-plugin-673cc48b4f75ebf5` | `src/main/java/org/jenkinsci/plugins/DependencyTrack/DescriptorImpl.java::doCheckDependencyTrackFrontendUrl` (205-219) | java | Jenkins Stapler HTTP endpoint doCheckDependencyTrackFrontendUrl (and doTestConnection) invoked via form validation request; attacker-controlled source is the @QueryParameter value / dependencyTrackApi | 0.85 |
| `jenkinsci-dependency-track-plugin-90b566be2c3aebff` | `src/main/java/org/jenkinsci/plugins/DependencyTrack/DescriptorImpl.java::doCheckDependencyTrackUrl` (195-204) | java | Jenkins HTTP endpoint doCheckDependencyTrackUrl (and doTestConnection) reachable via Stapler form validation; attacker-controlled source: @QueryParameter value / dependencyTrackUrl and dependencyTrack | 0.85 |
| `jenkinsci-dependency-track-plugin-9e8488d96f7c0424` | `src/main/java/org/jenkinsci/plugins/DependencyTrack/DescriptorImpl.java::doTestConnection` (220-245) | java | Jenkins Stapler HTTP endpoint doTestConnection (descriptor form validation endpoint, e.g. /descriptorByName/.../testConnection) with attacker-controlled dependencyTrackUrl and dependencyTrackApiKey qu | 0.85 |

## jenkinsci/gitlab-logo-plugin

- advisory: GHSA-22rj-q66g-2jg3 (config_secrets, CWE-522), origin `osv-extend`, ecosystem maven, licence MIT
- fix `1a64595353df91b5fcf2d9336fa627e06ef1f8a9`, parent (fix^1) `f4c28e3db4974bfb03ba41838e68a1d99debd75b`
- advisory title: Jenkins GitLab Logo Plugin stores credentials unencrypted

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-gitlab-logo-plugin-f771ba20ac33c126` | `src/main/java/org/jenkinsci/plugins/gitlablogo/GitlabLogoProperty.java::configure` (100-110) | java | Jenkins global configuration form submission handled by DescriptorImpl.configure(StaplerRequest, JSONObject) via Stapler; attacker-controlled source is the privateToken form field in the submitted JSO | 0.85 |

## jenkinsci/job-import-plugin

- advisory: GHSA-4g29-r7vj-2rpv (access_control, CWE-862), origin `osv-extend`, ecosystem maven, licence MIT
- fix `1b4119849571d4879977c529f9972d271ad6a630`, parent (fix^1) `647b3d5a034708c7f8dd61194c476b4e2b8d9593`
- advisory title: Jenkins Job Import Plugin allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-job-import-plugin-07e0e7023a46cf4d` | `src/main/java/org/jenkins/ci/plugins/jobimport/JobImportAction.java::doFillJenkinsSitesItems` (336-342) | java | Jenkins Stapler HTTP endpoint doFillJenkinsSitesItems on JobImportActionDescriptor (fill field for Jenkins sites), reachable by any authenticated user with Overall/Read permission | 0.85 |
| `jenkinsci-job-import-plugin-5509a356384e862e` | `src/main/java/org/jenkins/ci/plugins/jobimport/JobImportAction.java::doFillCredentialIdItems` (318-335) | java | Jenkins Stapler HTTP endpoint /jobImport/fillCredentialIdItems (doFillCredentialIdItems on JobImportActionDescriptor), reachable by any authenticated user with Overall/Read permission | 0.85 |

## jenkinsci/p4-plugin

- advisory: GHSA-f9v6-p7hp-c3qx (access_control, CWE-862), origin `osv`, ecosystem maven, licence BSD-2-Clause
- fix `2f2a31d8d36de7abab45820fab3a82f4c682b760`, parent (fix^1) `a168eb417f4b725612123be12ac014b01ab09999`
- advisory title: Missing permission checks in Jenkins P4 Plugin

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-p4-plugin-5022afedadfe8449` | `src/main/java/org/jenkinsci/plugins/p4/trigger/P4Hook.java::doChangeSubmit` (105-125) | java | Stapler HTTP endpoint doChangeSubmit (P4Hook) reachable via Jenkins Stapler routing; attacker-controlled source: StaplerRequest parameters (_.p4port) and submitted form | 0.9 |
| `jenkinsci-p4-plugin-65a59903d43924ee` | `src/main/java/org/jenkinsci/plugins/p4/trigger/P4Hook.java::doChange` (69-91) | java | P4Hook.doChange (HTTP endpoint /p4/change via StaplerRequest) | 0.9 |
| `jenkinsci-p4-plugin-85c3775c29eb0c5c` | `src/main/java/org/jenkinsci/plugins/p4/review/ReviewAction.java::doBuild` (78-125) | java | HTTP endpoint doBuild/doBuildSubmit on ReviewAction (urlName 'review') via StaplerRequest parameters | 0.85 |
| `jenkinsci-p4-plugin-a1c0ab5c3582fc3b` | `src/main/java/org/jenkinsci/plugins/p4/review/ReviewAction.java::doBuildSubmit` (70-77) | java | HTTP endpoint /review/buildSubmit (Stapler doBuildSubmit) reachable via Overall/Read authenticated user submitting form data | 0.85 |
| `jenkinsci-p4-plugin-fdef12ac487474fb` | `src/main/java/org/jenkinsci/plugins/p4/trigger/P4Hook.java::doEvent` (49-68) | java | UnprotectedRootAction P4Hook at URL /p4, HTTP endpoint doEvent (and doChange) reachable without authentication; attacker-controlled source is the HTTP request body/JSON payload (req.getInputStream) | 0.9 |

## jenkinsci/tap-plugin

- advisory: GHSA-24jc-w55j-5p83 (path, CWE-22), origin `osv-extend`, ecosystem maven, licence MIT
- fix `8e2a3aa86ce57a98c69e6038e15ae8fe47d08124`, parent (fix^1) `a98a85c961ef983fb2935aa2987587acc2e11e8e`
- advisory title: Jenkins TAP Plugin allows Path Traversal

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-tap-plugin-b1954cc1fc64febe` | `src/main/java/org/tap4j/plugin/TapResult.java::doDownloadAttachment` (306-345) | java | doDownloadAttachment Stapler request handler (Jenkins Stapler route /downloadAttachment) reading request parameter "f" | 0.85 |

## jenkinsci/zap-pipeline-plugin

- advisory: GHSA-4c87-9xq5-5c35 (output_encoding, CWE-79), origin `osv-extend`, ecosystem maven, licence MIT
- fix `bca4b087c66ead39398f54cdadc27c515e8ede31`, parent (fix^1) `5fc703a3c383eb515909cf0b9dc452ccc38f07d9`
- advisory title: Content-Security-Policy protection for user content disabled by Jenkins ZAP Pipeline Plugin

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `jenkinsci-zap-pipeline-plugin-953ab12f1f2d06d9` | `src/main/java/com/vrondakis/zap/ZapAction.java::doDynamic` (61-69) | java | ZapAction.doDynamic (Stapler route /job/<job>/<run>/zap/... via getUrlName() returning ZapArchive.DIRECTORY_NAME), serving DirectoryBrowserSupport content; attacker-controlled source is files in the w | 0.85 |

## line/armeria

- advisory: GHSA-8fp4-rp6c-5gcv (path, CWE-22), origin `osv-extend`, ecosystem maven, licence Apache-2.0
- fix `e2697a575e9df6692b423e02d731f293c1313284`, parent (fix^1) `a1105519e920b00ee3bc848a5074d943925931ef`
- advisory title: Path Traversal in com.linecorp.armeria:armeria

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `line-armeria-143c39cfd2874e4c` | `core/src/main/java/com/linecorp/armeria/internal/common/PathAndQuery.java::appendOneByte` (359-389) | java | HTTP request path parsing in Armeria server (PathAndQuery.appendOneByte) reached via FileService under a path prefix, e.g. GET /files/..%2Fsecrets.txt | 0.75 |
| `line-armeria-3196308da59204ff` | `core/src/main/java/com/linecorp/armeria/internal/common/PathAndQuery.java::splitPathAndQuery` (189-230) | java | HTTP request path handling in Armeria server (PathAndQuery.splitPathAndQuery invoked from request path parsing); attacker-controlled source is the request path containing %2F, e.g. /files/..%2Fsecrets | 0.75 |
| `line-armeria-fff692dc76424e72` | `core/src/main/java/com/linecorp/armeria/internal/common/PathAndQuery.java::decodePercentsAndEncodeToUtf8` (231-358) | java | HTTP request path parsing in Armeria server (PathAndQuery.parse) invoked via FileService under a route such as /files, attacker-controlled source: request path containing %2F | 0.85 |

## modoboa/modoboa-dmarc

- advisory: GHSA-vc42-mgr2-w34r (injection, CWE-91), origin `osv-extend`, ecosystem pip, licence MIT
- fix `14c29e0ad9487bdbe4cc0bd1f8bc711285bf9933`, parent (fix^1) `1b1472fc7ef168e19f981f8bb8827e9ed7888e46`
- advisory title: Modoboa is vulnerable to an XML External Entity Injection (XXE)

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `modoboa-modoboa-dmarc-7b9ba42b6d644e40` | `modoboa_dmarc/lib.py::import_report` (76-119) | python | import_report_from_email(content) -> import_archive -> import_report; content originates from DMARC report emails sent to the rua address of a domain | 0.85 |

## posit-dev/py-shiny

- advisory: GHSA-47c3-hpmg-7j6p (path, CWE-22), origin `osv`, ecosystem pip, licence MIT
- fix `1d8ecb46cbc9621b7dc8812111d26692e086b376`, parent (fix^1) `48b4faa0d651476afa84d6423d57503b60716902`
- advisory title: Shiny for Python has path traversal in bookmark restore

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `posit-dev-py-shiny-3537c0dd41a40d38` | `shiny/_app.py::_on_root_request_cb` (397-418) | python | HTTP GET / handler _on_root_request_cb reading request.url.query (_state_id_) | 0.9 |
| `posit-dev-py-shiny-78e995f1fddd0cb5` | `shiny/bookmark/_restore_state.py::_load_state_qs` (183-221) | python | HTTP request query string `_state_id_` parameter reaching `_load_state_qs` (bookmark restore path) | 0.85 |
| `posit-dev-py-shiny-8fd07b2eca54563e` | `shiny/bookmark/_restore_state.py::from_query_string` (110-163) | python | HTTP request query string parsed by RestoreContext.from_query_string via the Shiny bookmark-restore path; attacker-controlled source is the `_state_id_` query-string parameter | 0.85 |

## shopperlabs/shopper

- advisory: GHSA-f946-9qp6-vgch (access_control, CWE-285), origin `osv-extend`, ecosystem composer, licence MIT
- fix `fcd0c5920588702df5b874f432b1042abd77a50b`, parent (fix^1) `ceaea6a078025d4a7634d2646d27dde3f13b6f58`
- advisory title: shopper/framework: Authorization bypass in multiple Livewire admin components

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `shopperlabs-shopper-02254beed509364c` | `packages/admin/src/Livewire/Components/Products/Form/Inventory.php::store` (195-207) | php | Livewire component packages/admin/src/Livewire/Components/Products/Form/Inventory.php store() method, invoked via Livewire request from the admin product inventory form; attacker-controlled source is  | 0.85 |
| `shopperlabs-shopper-047e62abed0b91fa` | `packages/admin/src/Livewire/Components/Customers/Orders.php::table` (36-123) | php | Livewire component Shopper\Admin\Livewire\Components\Customers\Orders (public $customer property, table()/render()); attacker-controlled source: Livewire client-side property tampering of the unlocked | 0.6 |
| `shopperlabs-shopper-052f88a347caf2eb` | `packages/admin/src/Livewire/Components/Orders/OrderNotes.php::leaveNotes` (24-37) | php | Livewire component Shopper\Livewire\Components\Orders\OrderNotes::leaveNotes(), invoked via Livewire update request from the order detail admin panel; attacker-controlled source is the public $notes p | 0.85 |
| `shopperlabs-shopper-064f0b5f8937aae5` | `packages/admin/src/Livewire/Pages/Settings/Team/Index.php::table` (77-118) | php | Livewire admin component Settings/Team/Index (table recordActions DeleteAction) reachable by any authenticated panel user | 0.75 |
| `shopperlabs-shopper-0fd6e8d87dd0ed82` | `packages/admin/src/Livewire/Pages/Order/Detail.php::markCompleteAction` (114-133) | php | Livewire admin Order Detail component action markCompleteAction (Filament action callable by authenticated low-privilege panel user with read_orders) | 0.85 |
| `shopperlabs-shopper-1112cc61420816ff` | `packages/admin/src/Livewire/Pages/Settings/Team/RolePermission.php::save` (199-210) | php | Livewire component Settings/Team/RolePermission::save() invoked via Livewire update request from the admin panel route (shopper settings team role page); attacker-controlled source is the authenticate | 0.85 |
| `shopperlabs-shopper-13fdb238d0d8e573` | `packages/admin/src/Livewire/Components/Products/Form/Edit.php::store` (213-231) | php | Livewire component Products\Form\Edit::store() invoked via Livewire update request from the admin product edit form; attacker-controlled source is the Livewire form state (data) submitted by an authen | 0.85 |
| `shopperlabs-shopper-22487ec06a8cf50a` | `packages/admin/src/Livewire/Pages/Order/Detail.php::capturePaymentAction` (134-178) | php | Livewire admin component packages/admin/src/Livewire/Pages/Order/Detail.php::capturePaymentAction (Filament action 'capturePayment' invoked by an authenticated low-privilege panel user with read_order | 0.85 |
| `shopperlabs-shopper-2405022067cc6870` | `packages/admin/src/Livewire/Pages/Order/Shipments.php::table` (98-213) | php | Livewire admin component packages/admin/src/Livewire/Pages/Order/Shipments.php::table() record actions (markDelivered, edit) invoked via Livewire request by an authenticated low-privilege panel user w | 0.85 |
| `shopperlabs-shopper-29811dac402a0d13` | `packages/admin/src/Livewire/Pages/Order/Detail.php::markPaidAction` (88-113) | php | Livewire admin component Order/Detail markPaidAction (Filament action 'markPaid') invoked by an authenticated low-privilege panel user with read_orders permission | 0.85 |
| `shopperlabs-shopper-2aeaefee52274ee8` | `packages/admin/src/Livewire/Pages/Order/Detail.php::archiveAction` (179-207) | php | Livewire admin component Order/Detail archiveAction (Filament action 'archive') invoked via Livewire request to the admin order detail page; attacker-controlled source is the authenticated low-privile | 0.85 |
| `shopperlabs-shopper-5481a94c34f42fbf` | `packages/admin/src/Livewire/Components/Products/Form/Files.php::store` (54-65) | php | Livewire component packages/admin/src/Livewire/Components/Products/Form/Files.php store() action, invoked via Livewire request to the product edit page; attacker-controlled source is the Livewire acti | 0.85 |
| `shopperlabs-shopper-5a3dcf2a6b6b16c8` | `packages/admin/src/Livewire/Components/Products/Form/Shipping.php::store` (56-67) | php | Livewire component Products\Form\Shipping::store() invoked via Livewire update request from the admin product shipping form; attacker-controlled source is the Livewire action call and form state ($thi | 0.85 |
| `shopperlabs-shopper-5e6161ace0cb4b97` | `packages/admin/src/Livewire/Pages/Settings/Team/RolePermission.php::createPermissionAction` (151-198) | php | Livewire component Settings/Team/RolePermission::createPermissionAction (admin panel route for role permissions), invoked by an authenticated low-privilege panel user with view_users permission | 0.85 |
| `shopperlabs-shopper-61e951b6bcd03186` | `packages/admin/src/Livewire/Pages/Settings/Carriers.php::createCarrierAction` (49-66) | php | Livewire component Shopper\Admin\Livewire\Pages\Settings\Carriers::createCarrierAction (admin panel route rendering the Carriers Livewire component); attacker-controlled source: authenticated low-priv | 0.75 |
| `shopperlabs-shopper-7cc69fb293ec0e10` | `packages/admin/src/Livewire/Pages/Collection/Edit.php::store` (134-143) | php | Livewire component packages/admin/src/Livewire/Pages/Collection/Edit.php store() action, invoked via Livewire update request from the admin collection edit page by an authenticated low-privilege panel | 0.75 |
| `shopperlabs-shopper-8769d9915b8295a9` | `packages/admin/src/Livewire/Pages/Settings/Team/RolePermission.php::generatePermissionsAction` (90-150) | php | Livewire admin component Settings/Team/RolePermission::generatePermissionsAction (Filament action 'generatePermissions'), invoked by an authenticated panel user with only view_users permission; source | 0.85 |
| `shopperlabs-shopper-88497bd11908cf4a` | `packages/admin/src/Livewire/Pages/Settings/Currencies.php::table` (43-130) | php | Livewire component Shopper\Admin\Livewire\Pages\Settings\Currencies (route /settings/currencies) - table() ToggleColumn is_enabled, EditAction edit, and grouped bulk actions enable/disable; attacker-c | 0.75 |
| `shopperlabs-shopper-8b7021ee40c51b56` | `packages/admin/src/Livewire/SlideOvers/AddVariant.php::form` (71-203) | php | Livewire component AddVariant (packages/admin/src/Livewire/SlideOvers/AddVariant.php) form() barcode TextInput; attacker-controlled source is the barcode form field submitted via the Livewire save() a | 0.6 |
| `shopperlabs-shopper-91023b586e4ab747` | `packages/admin/src/Livewire/Components/Settings/Legal/PolicyForm.php::store` (60-72) | php | Livewire component Settings\Legal\PolicyForm::store() invoked via Livewire update request from the admin panel; attacker-controlled source is the authenticated low-privilege panel user's Livewire requ | 0.75 |
| `shopperlabs-shopper-a413505de3d037f8` | `packages/admin/src/Livewire/Pages/Settings/PaymentMethods.php::createPaymentAction` (49-66) | php | Livewire component Shopper\Admin\Livewire\Pages\Settings\PaymentMethods::createPaymentAction (admin panel route for payment methods settings); attacker-controlled source: authenticated low-privilege p | 0.75 |
| `shopperlabs-shopper-a82b452965e2ffe5` | `packages/admin/src/Livewire/Components/Products/Form/Seo.php::store` (52-63) | php | Livewire component packages/admin/src/Livewire/Components/Products/Form/Seo.php store() action, invoked via Livewire request to the product SEO form; attacker-controlled source is the Livewire compone | 0.85 |
| `shopperlabs-shopper-ab37699016e7189c` | `packages/admin/src/Livewire/SlideOvers/AddProduct.php::form` (84-283) | php | Livewire component packages/admin/src/Livewire/SlideOvers/AddProduct.php::store() invoked via Livewire request to the AddProduct slide-over (form submit wire:target="store"); attacker-controlled sourc | 0.6 |
| `shopperlabs-shopper-b37cd0c75b594760` | `packages/admin/src/Livewire/Pages/Product/Variant.php::updateStockAction` (46-81) | php | Livewire component Shopper\Admin\Livewire\Pages\Product\Variant::updateStockAction (admin panel product variant page); attacker-controlled source: Livewire action call with form data (sku, barcode) fr | 0.85 |
| `shopperlabs-shopper-cd45e0d6604bb846` | `packages/admin/src/Livewire/Pages/Order/Detail.php::cancelOrderAction` (47-69) | php | Livewire admin component Shopper\Livewire\Pages\Order\Detail::cancelOrderAction invoked via Livewire action call on the order detail page (route shopper.orders.detail); attacker-controlled source is t | 0.85 |
| `shopperlabs-shopper-d05ad8c2776691be` | `packages/admin/src/Livewire/Components/Settings/Locations/InventoryForm.php::store` (103-118) | php | Livewire component Settings/Locations/InventoryForm::store() invoked via Livewire update request from the admin panel route shopper.settings.locations; attacker-controlled source is the Livewire form  | 0.85 |
| `shopperlabs-shopper-d26bdca35566e799` | `packages/admin/src/Livewire/Pages/Settings/PaymentMethods.php::table` (67-112) | php | Livewire component PaymentMethods (Settings/PaymentMethods) table actions: ToggleColumn is_enabled, EditAction edit, DeleteAction delete; invoked via Livewire update endpoint by any authenticated pane | 0.85 |
| `shopperlabs-shopper-deb90b541bcac1aa` | `packages/admin/src/Livewire/Pages/Order/Detail.php::startProcessingAction` (70-87) | php | Livewire admin component Order/Detail::startProcessingAction (Filament action 'startProcessing') invoked by an authenticated low-privilege panel user with read_orders permission | 0.85 |
| `shopperlabs-shopper-df2391064e3c3332` | `packages/admin/src/Livewire/Pages/Settings/Team/Index.php::createRoleAction` (41-76) | php | Livewire component Shopper\Admin\Livewire\Pages\Settings\Team\Index (route: shopper.settings.team.index) - createRoleAction invoked by any authenticated panel user; source: Livewire action call from c | 0.85 |
| `shopperlabs-shopper-f3cb66743db8d5f1` | `packages/admin/src/Livewire/Pages/Customers/Create.php::store` (142-178) | php | Livewire component Customers\Create::store() invoked via admin panel route shopper.customers.create (Livewire POST to /admin/customers/create); attacker-controlled source is the Livewire form state ($ | 0.85 |
| `shopperlabs-shopper-fddd0d6c3c4501aa` | `packages/admin/src/Livewire/Pages/Settings/Carriers.php::table` (67-112) | php | Livewire component packages/admin/src/Livewire/Pages/Settings/Carriers.php (table actions: ToggleColumn is_enabled, EditAction, DeleteAction) invoked via Livewire update requests by any authenticated  | 0.75 |

## triggerdotdev/trigger.dev

- advisory: GHSA-4672-hwv6-gq62 (access_control, CWE-639), origin `osv`, ecosystem npm, licence Apache-2.0
- fix `6997aeb05e27d2db47f9eda01fdc8a17c81a1ae0`, parent (fix^1) `cc748422d8188833948035281cc50ef4f7ab77e2`
- advisory title: Trigger.dev: Cross-environment deployment cancel

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `triggerdotdev-trigger.dev-0eb72665259b13c2` | `apps/webapp/app/routes/api.v1.schedules.$scheduleId.deactivate.ts::action` (14-75) | typescript | POST /api/v1/schedules/:scheduleId/deactivate (action in apps/webapp/app/routes/api.v1.schedules.$scheduleId.deactivate.ts), authenticated via authenticateApiRequest using an environment-scoped secret | 0.55 |
| `triggerdotdev-trigger.dev-124d417d0ae18fbe` | `apps/webapp/app/routes/api.v1.schedules.$scheduleId.activate.ts::action` (14-75) | typescript | POST /api/v1/schedules/:scheduleId/activate (action in apps/webapp/app/routes/api.v1.schedules.$scheduleId.activate.ts), authenticated via authenticateApiRequest using an environment-scoped secret API | 0.55 |
| `triggerdotdev-trigger.dev-2240070f2c86924b` | `apps/webapp/app/v3/services/initializeDeployment.server.ts::call` (24-315) | typescript | POST /api/v1/deployments/:deploymentId/cancel (api.v1.deployments.$deploymentId.cancel.ts) -> DeploymentService.cancelDeployment -> getDeployment(projectId, friendlyId); attacker-controlled source: de | 0.75 |
| `triggerdotdev-trigger.dev-30dec4b7031de737` | `apps/webapp/app/routes/api.v1.deployments.$deploymentId.cancel.ts::action` (12-78) | typescript | POST /api/v1/deployments/:deploymentId/cancel (action in apps/webapp/app/routes/api.v1.deployments.$deploymentId.cancel.ts); attacker-controlled source: API key in request headers via authenticateRequ | 0.9 |
| `triggerdotdev-trigger.dev-5b0c0ef74fdf5bc3` | `apps/webapp/app/v3/services/deployment.server.ts::generateRegistryCredentials` (280-333) | typescript | POST /api/v1/deployments/:deploymentId/cancel (apps/webapp/app/routes/api.v1.deployments.$deploymentId.cancel.ts) with attacker-controlled secret API key (dev/preview env) and deploymentId param | 0.85 |
| `triggerdotdev-trigger.dev-5f1cf28e3ac84980` | `apps/webapp/app/v3/services/deployment.server.ts::getDeployment` (475-515) | typescript | POST /api/v1/deployments/:deploymentId/cancel (apps/webapp/app/routes/api.v1.deployments.$deploymentId.cancel.ts) -> DeploymentService.cancelDeployment -> getDeployment; attacker-controlled source: au | 0.9 |
| `triggerdotdev-trigger.dev-eebfca9646e01b1c` | `apps/webapp/app/v3/services/deployment.server.ts::cancelDeployment` (193-270) | typescript | POST /api/v1/deployments/$deploymentId/cancel (apps/webapp/app/routes/api.v1.deployments.$deploymentId.cancel.ts) -> DeploymentService.cancelDeployment; attacker-controlled source: authenticated envir | 0.9 |

## whiskeysockets/baileys

- advisory: GHSA-qvv5-jq5g-4cgg (config_secrets, CWE-346), origin `osv`, ecosystem npm, licence MIT
- fix `3beb08eecfcb4e65722e674034bd84fb11a9de35`, parent (fix^1) `28ca087cf1cbe3c05a5b704d67b3e2270d647b74`
- advisory title: Baileys has message upsert / hist sync spoofing and app state corruption when using maliciously crafted protocolMessage payload

| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |
|---|---|---|---|---|
| `whiskeysockets-baileys-89cd6d4edf46d286` | `src/Utils/process-message.ts::processMessage` (293-751) | typescript | processMessage(message, ctx) invoked from the Baileys socket message pipeline (e.g. sendMessage/ev 'messages.upsert' handling); attacker-controlled source is the incoming WAMessage.message.protocolMes | 0.75 |

