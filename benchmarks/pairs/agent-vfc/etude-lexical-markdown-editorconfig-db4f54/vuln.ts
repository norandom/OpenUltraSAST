// Provenance: dayflower/etude-lexical-markdown  (vuln).
// repo: dayflower/etude-lexical-markdown
// commit: 1c865815d05b072f4973388c3ac66b6696d9efde
// parent: 1c865815d05b072f4973388c3ac66b6696d9efde
// commit_url: https://github.com/dayflower/etude-lexical-markdown/commit/db4f54b1ab80ad596de6425e84f90aa781c49999
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
