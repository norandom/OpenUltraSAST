// Provenance: dayflower/popmark  (vuln).
// repo: dayflower/popmark
// commit: 31d1ac79b4cfa3118597348e79800a6561115149
// parent: 31d1ac79b4cfa3118597348e79800a6561115149
// commit_url: https://github.com/dayflower/popmark/commit/e5ac407cef37c37178d440541ede301c838640fb
// cve: 
// license: MIT
// function: deepMergeInto
// relpath: src/lexical-markdown/config/editorConfig.ts
// provenance: agent
// mechanism: prototype_pollution

function deepMergeInto(
  target: Record<string, unknown>,
  source: Record<string, unknown>,
): Record<string, unknown> {
  for (const key of Object.keys(source)) {
    const sourceValue = source[key];
    if (sourceValue === undefined) continue;
    if (isPlainObject(sourceValue)) {
      const targetValue = target[key];
      const nested = isPlainObject(targetValue) ? targetValue : {};
      target[key] = deepMergeInto(nested, sourceValue);
    } else {
      target[key] = sourceValue;
    }
  }
  return target;
}
