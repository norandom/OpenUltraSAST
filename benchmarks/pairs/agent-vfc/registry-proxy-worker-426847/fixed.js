// Provenance: agents-repo/registry-proxy  (fixed).
// repo: agents-repo/registry-proxy
// commit: 426847899eb2ee94ae4e5a3aacc50423e36d2dc8
// parent: 6d5937972510cdb5ebca30607b538fdc2e280094
// commit_url: https://github.com/agents-repo/registry-proxy/commit/426847899eb2ee94ae4e5a3aacc50423e36d2dc8
// cve: 
// license: MIT
// function: buildUpstreamRequest
// relpath: src/worker.js
// provenance: agent
// mechanism: permissive_default

function buildUpstreamRequest(target, env, requestHeaders) {
  const headers = new Headers();
  const requestAccept = requestHeaders.get("Accept") || "*/*";
  headers.set("User-Agent", UPSTREAM_USER_AGENT);

  const ifNoneMatch = requestHeaders.get("If-None-Match");
  if (ifNoneMatch) {
    headers.set("If-None-Match", ifNoneMatch);
  }

  const ifModifiedSince = requestHeaders.get("If-Modified-Since");
  if (ifModifiedSince) {
    headers.set("If-Modified-Since", ifModifiedSince);
  }

  if (env.GITHUB_TOKEN) {
    headers.set("Accept", "application/vnd.github.raw");
    headers.set("Authorization", `Bearer ${env.GITHUB_TOKEN}`);
    return {
      url: buildContentsApiUrl(target.ref, target.targetPath),
      headers,
    };
  }

  headers.set("Accept", requestAccept);

  return {
    url: buildUpstreamUrl(target.ref, target.targetPath),
    headers,
  };
}
