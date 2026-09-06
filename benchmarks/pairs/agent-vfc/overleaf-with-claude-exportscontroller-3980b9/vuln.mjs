// Provenance: ZUENS2020/overleaf-with-claude exportProject (vuln).
// repo: ZUENS2020/overleaf-with-claude
// commit: 5a886aa9fb9fe4e2203f3cb1d62c91f4be0525ed
// parent: 5a886aa9fb9fe4e2203f3cb1d62c91f4be0525ed
// commit_url: https://github.com/ZUENS2020/overleaf-with-claude/commit/3980b9e5806defb63e45ae2696e6c1899f3a8431
// cve: 
// license: AGPL-3.0
// function: exportProject
// relpath: services/web/app/src/Features/Exports/ExportsController.mjs
// provenance: agent
// mechanism: identity_from_request_body
// upstream_start: 1

from '@overleaf/promise-utils'
import SessionManager from '../Authentication/SessionManager.mjs'
import logger from '@overleaf/logger'
import OError from '@overleaf/o-error'

async function exportProject(req, res, next) {
  const { project_id: projectId, brand_variation_id: brandVariationId } =
    req.params
  const userId = SessionManager.getLoggedInUserId(req.session)
  const exportParams = {
    project_id: projectId,
    brand_variation_id: brandVariationId,
    user_id: userId,
  }

  if (req.body) {
    if (req.body.firstName) {
      exportParams.first_name = req.body.firstName.trim()
    }
    if (req.body.lastName) {
      exportParams.last_name = req.body.lastName.trim()
    }
    // additional parameters for gallery exports
    if (req.body.title) {
      exportParams.title = req.body.title.trim()
    }
    if (req.body.description) {
      exportParams.description = req.body.description.trim()
    }
    if (req.body.author) {
      exportParams.author = req.body.author.trim()
    }
    if (req.body.license) {
      exportParams.license = req.body.license.trim()
    }
    if (req.body.showSource != null) {
      exportParams.show_source = req.body.showSource
    }
  }

  try {
    const exportData = await ExportsHandler.exportProject(exportParams)
    logger.debug(
      {
        userId,
        projectId,
        brandVariationId,
        exportV1Id: exportData.v1_id,
      },
      'exported project'
    )
    return res.json({
      export_v1_id: exportData.v1_id,
      message: exportData.message,
    })
  } catch (err) {
    const info = OError.getFullInfo(err)
    if (info?.forwardResponse) {
      logger.debug(
        { responseError: info.forwardResponse },
        'forwarding response'
      )
      const statusCode = info.forwardResponse.status || 500
      return res.status(statusCode).json(info.forwardResponse)
    }
    throw err
  }
}

exportProject: expressify(exportProject),
