// Provenance: P1R4N351/astroclaw  (vuln).
// repo: P1R4N351/astroclaw
// commit: d3eed2dc01328f21dd404477bb28e2740fa371a4
// parent: d3eed2dc01328f21dd404477bb28e2740fa371a4
// commit_url: https://github.com/P1R4N351/astroclaw/commit/1553a8adf123913cf7f1f1c75be4c4e5cd6c796b
// cve: 
// license: MIT
// function: isTopLevelNavigationRequest
// relpath: extensions/browser/src/browser/pw-session.ts
// provenance: agent
// mechanism: source_reaches_sink

function isTopLevelNavigationRequest(page: Page, request: Request): boolean {
  if (!request.isNavigationRequest()) {
    return false;
  }
  try {
    return request.frame() === page.mainFrame();
  } catch {
    return true;
  }
}
