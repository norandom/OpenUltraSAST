// Provenance: DavideCarvalho/nestjs-filter  (fixed).
// repo: DavideCarvalho/nestjs-filter
// commit: aa0e600d05997ea3d77538ea1c2db427c439f2e8
// parent: d899b40d3466f2ffbe9f01c4d49267412401f078
// commit_url: https://github.com/DavideCarvalho/nestjs-filter/commit/aa0e600d05997ea3d77538ea1c2db427c439f2e8
// cve: 
// license: MIT
// function: normalizeInput
// relpath: packages/core/src/input/normalizer.ts
// provenance: agent
// mechanism: prototype_pollution

export function normalizeInput(input: unknown, options: NormalizeOptions): Record<string, unknown> {
  if (input == null || typeof input !== 'object') return {};
  const norm = pickNormalizer(options.normalizer);
  const drop = options.dropId === true;
  const out: Record<string, unknown> = {};
  for (const [rawKey, value] of Object.entries(input as Record<string, unknown>)) {
    if (BLOCKED_KEYS.has(rawKey)) continue;
    let key = norm(rawKey);
    if (BLOCKED_KEYS.has(key)) continue;
    if (drop) key = stripId(key);
    if (key.length === 0) continue;
    out[key] = value;
  }
  return out;
}
