// Provenance: Anas329796/Anastasios  (fixed).
// repo: Anas329796/Anastasios
// commit: 14ec1ac50f9e4e255d875236d30129c6207401d4
// parent: adb7b0d5d6b81c46d56451c709e7eac9d0dc93fb
// commit_url: https://github.com/Anas329796/Anastasios/commit/14ec1ac50f9e4e255d875236d30129c6207401d4
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
