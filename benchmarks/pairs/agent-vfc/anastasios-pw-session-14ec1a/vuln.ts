// Provenance: Anas329796/Anastasios  (vuln).
// repo: Anas329796/Anastasios
// commit: adb7b0d5d6b81c46d56451c709e7eac9d0dc93fb
// parent: adb7b0d5d6b81c46d56451c709e7eac9d0dc93fb
// commit_url: https://github.com/Anas329796/Anastasios/commit/14ec1ac50f9e4e255d875236d30129c6207401d4
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
