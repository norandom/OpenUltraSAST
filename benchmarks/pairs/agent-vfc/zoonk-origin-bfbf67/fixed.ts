// Provenance: zoonk/zoonk  (fixed).
// repo: zoonk/zoonk
// commit: bfbf670ccb41d63c407d32c51bd26e626a174f31
// parent: 2604269350bff51f58572c133b45010cb0976a5a
// commit_url: https://github.com/zoonk/zoonk/commit/bfbf670ccb41d63c407d32c51bd26e626a174f31
// cve: 
// license: MIT
// function: getAllowedHosts
// relpath: packages/utils/src/origin.ts
// provenance: agent
// mechanism: permissive_default

export function getAllowedHosts(): string[] {
  return [
    ...ZOONK_DOMAINS.flatMap((domain) => [domain, `*.${domain}`]),
    ...(isLocalhostSupported() ? ["localhost:*"] : []),
    ...(canAcceptVercelPreviewOrigins() ? [ZOONK_VERCEL_PREVIEW_HOST] : []),
  ];
}
