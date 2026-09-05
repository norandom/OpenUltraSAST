// Provenance: dayflower/etude-lexical-markdown  (fixed).
// repo: dayflower/etude-lexical-markdown
// commit: c61a8bf78fe20d6ae0eab2e4b8b02004508525ed
// parent: 0a2184f59e79a04b1365cd49200026e8f2ffdbd5
// commit_url: https://github.com/dayflower/etude-lexical-markdown/commit/c61a8bf78fe20d6ae0eab2e4b8b02004508525ed
// cve: 
// license: MIT
// function: deepMergeInto
// relpath: src/config/editorConfig.ts
// provenance: agent
// mechanism: prototype_pollution

function deepMergeInto(
  target: Record<string, unknown>,
  source: Record<string, unknown>,
): Record<string, unknown> {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(key)) continue;
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
