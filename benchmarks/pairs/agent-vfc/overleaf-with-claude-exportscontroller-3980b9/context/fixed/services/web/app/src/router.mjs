// Provenance: ZUENS2020/overleaf-with-claude exportProject (fixed).
// repo: ZUENS2020/overleaf-with-claude
// commit: 3980b9e5806defb63e45ae2696e6c1899f3a8431
// parent: 5a886aa9fb9fe4e2203f3cb1d62c91f4be0525ed
// commit_url: https://github.com/ZUENS2020/overleaf-with-claude/commit/3980b9e5806defb63e45ae2696e6c1899f3a8431
// cve: 
// license: AGPL-3.0
// function: exportProject
// relpath: services/web/app/src/router.mjs
// provenance: agent
// mechanism: identity_from_request_body

  webRouter.post(
    '/project/:project_id/export/:brand_variation_id',
    AuthorizationMiddleware.ensureUserCanWriteProjectContent,
    ExportsController.exportProject
  )
