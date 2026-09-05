// Provenance: P1R4N351/astroclaw  (fixed).
// repo: P1R4N351/astroclaw
// commit: 1553a8adf123913cf7f1f1c75be4c4e5cd6c796b
// parent: d3eed2dc01328f21dd404477bb28e2740fa371a4
// commit_url: https://github.com/P1R4N351/astroclaw/commit/1553a8adf123913cf7f1f1c75be4c4e5cd6c796b
// cve: 
// license: MIT
// function: isTopLevelNavigationRequest
// relpath: extensions/browser/src/browser/pw-session.ts
// provenance: agent
// mechanism: source_reaches_sink

function isTopLevelNavigationRequest(page: Page, request: Request): boolean {
  let sameMainFrame = false;
  try {
    sameMainFrame = request.frame() === page.mainFrame();
  } catch {
    // Frame resolution can fail during redirect/renderer churn; fail closed.
    sameMainFrame = true;
  }
  if (!sameMainFrame) {
    return false;
  }

  try {
    if (request.isNavigationRequest()) {
      return true;
    }
  } catch {
    // Ignore and fall back to resource-type check below.
  }

  try {
    return request.resourceType() === "document";
  } catch {
    return false;
  }
}
