// Provenance: Cap-go/capgo.app  (vuln).
// repo: Cap-go/capgo.app
// commit: 8c0ac7e233946abd8dc26581b871e9fcd0928899
// parent: 8c0ac7e233946abd8dc26581b871e9fcd0928899
// commit_url: https://github.com/Cap-go/capgo.app/commit/4dadd2580d02213d227a331eee0232aa59859b59
// cve: 
// license: AGPL-3.0
// function: createHono
// relpath: supabase/functions/_backend/utils/hono.ts
// provenance: agent
// mechanism: permissive_default

export function createHono(functionName: string, _version: string) {
  let appGlobal
  if (getRuntimeKey() === 'deno') {
    appGlobal = new Hono<MiddlewareKeyVariables>().basePath(`/${functionName}`)
  }
  else {
    appGlobal = new Hono<MiddlewareKeyVariables>()
  }

  // Plugin hot paths (/updates|/stats|/channel_self and the CF plugin worker).
  // HAR/CPU inspect showed middleware + logging dominating non-DB request cost.
  const pluginHotPath = functionName === 'plugin'
    || functionName === 'updates'
    || functionName === 'stats'
    || functionName === 'channel_self'

  appGlobal.use('*', (c, next): Promise<any> => {
    // ADD HEADER TO IDENTIFY WORKER SOURCE
    const name = `${getEnv(c, 'ENV_NAME') || functionName}-${CapgoVersion}`
    c.header('X-Worker-Source', name)
    const hostname = new URL(c.req.url).hostname
    if (!isPreviewHost(hostname))
      c.header('Content-Security-Policy', API_CONTENT_SECURITY_POLICY)
    return next()
  })

  // Skip hono's access logger on plugin hot paths — it serializes every request
  // on millions of device calls/day.
  if (!pluginHotPath)
    appGlobal.use('*', logger())
  // Use platform-specific request IDs, fallback to generated UUID.
  // Do not cloudlog inside the generator: it runs on every request (incl. cf-ray).
  appGlobal.use('*', requestId({
    generator: (c) => {
      // Cloudflare provides the Ray ID in the cf-ray header
      // Check this first as it's our primary deployment target
      const cfRay = c.req.header('cf-ray')
      if (cfRay)
        return cfRay
      // Supabase Edge Functions provide SB_EXECUTION_ID
      const sbExecutionId = getEnv(c, 'SB_EXECUTION_ID')
      if (sbExecutionId)
        return sbExecutionId
      // Fallback to crypto.randomUUID() if not on any known platform
      return crypto.randomUUID()
    },
  }))

  appGlobal.post('/ok', (c) => {
    return c.json(BRES)
  })
  appGlobal.post('/ko', (c) => {
    const defaultResponse: SimpleErrorResponse = {
      error: 'unknown_error',
      message: 'KO',
      moreInfo: {},
    }
    return c.json(defaultResponse, 500)
  })

  return appGlobal
}
