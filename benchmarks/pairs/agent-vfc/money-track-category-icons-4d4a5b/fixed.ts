// Provenance: andrebubniak/money-track  (fixed).
// repo: andrebubniak/money-track
// commit: 4d4a5b063278c8b6697c3faae133d7c39fcd01c0
// parent: add96df6d6a6b61506635c23dbacf6c6cfe24dc2
// commit_url: https://github.com/andrebubniak/money-track/commit/4d4a5b063278c8b6697c3faae133d7c39fcd01c0
// cve: 
// license: MIT
// function: isCategoryIcon
// relpath: src/lib/category-icons.ts
// provenance: agent
// mechanism: prototype_pollution

export function isCategoryIcon(value: string): value is keyof typeof CATEGORY_ICONS {
  return Object.hasOwn(CATEGORY_ICONS, value);
}
