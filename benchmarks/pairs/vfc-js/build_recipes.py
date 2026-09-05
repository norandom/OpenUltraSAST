#!/usr/bin/env python3
"""Build vfc-js recipes from SecBench.js fix commits (maintainer, network via gh).

SecBench.js has no license file, so nothing from it is vendored. Its package.json
metadata names the upstream fix commit; the pair is harvested from that upstream
repository (hunk mode: the function enclosing the first changed hunk) and carries
the upstream package license. Crawl first:

    python benchmarks/pairs/vfc-js/build_recipes.py --crawl /tmp/secbench.jsonl   # lists modules with a GitHub fixCommit
    python benchmarks/pairs/vfc-js/build_recipes.py --from /tmp/secbench.jsonl     # resolves parent, license, changed file
    python benchmarks/pairs/harvest.py --slice vfc-js --all --fetch
    python benchmarks/pairs/catalog_gen.py --slice vfc-js
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CLASSES = {
    "command-injection": ("CWE-78", "command injection", "source_reaches_sink"),
    "path-traversal": ("CWE-22", "path traversal", "path_join_user_input"),
    "code-injection": ("CWE-94", "code injection", "source_reaches_sink"),
    "prototype-pollution": ("CWE-1321", "prototype pollution", "prototype_pollution"),
    "redos": ("CWE-1333", "regular expression denial of service", "redos"),
}
ACCEPTED_LICENSES = {"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "MPL-2.0", "GPL-3.0", "GPL-2.0", "Unlicense", "0BSD"}
_JS = re.compile(r"\.(js|mjs|cjs|ts)$")
_SKIP = re.compile(r"(test|spec|\.d\.ts|dist/|build/|min\.js|package\.json|README)", re.I)


def _gh(path: str) -> object:
    return json.loads(subprocess.check_output(["gh", "api", path], stderr=subprocess.DEVNULL))


def crawl(out: Path, classes: tuple[str, ...]) -> int:
    count = 0
    with out.open("w") as handle:
        for cls in classes:
            dirs = _gh(f"repos/cristianstaicu/SecBench.js/contents/{cls}")
            for entry in dirs if isinstance(dirs, list) else []:
                if entry.get("type") != "dir":
                    continue
                time.sleep(0.4)
                try:
                    raw = subprocess.check_output(
                        ["gh", "api", f"repos/cristianstaicu/SecBench.js/contents/{cls}/{entry['name']}/package.json", "--jq", ".content"],
                        stderr=subprocess.DEVNULL,
                    )
                    meta = json.loads(base64.b64decode(raw))
                except Exception:  # noqa: BLE001 — skip unreadable modules
                    continue
                fix = str(meta.get("fixCommit", "n/a"))
                if "github.com" in fix and "/commit/" in fix:
                    handle.write(
                        json.dumps(
                            {"class": cls, "module": entry["name"], "cve": meta.get("id"), "fixCommit": fix, "sink": meta.get("sink")}
                        )
                        + "\n"
                    )
                    count += 1
    return count


def build(crawl_path: Path, *, limit: int) -> tuple[list[dict[str, object]], dict[str, int]]:
    recipes: list[dict[str, object]] = []
    skipped = {"unlicensed": 0, "no_js_file": 0, "api": 0, "multi_file": 0}
    rows = [json.loads(line) for line in crawl_path.read_text().splitlines() if line.strip()]
    seen_shas: set[str] = set()
    seen_modules: set[str] = set()
    skipped.update({"duplicate_fix": 0, "module_repo_mismatch": 0})
    for row in rows:
        if len(recipes) >= limit:
            break
        match = re.search(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})", row["fixCommit"])
        if not match:
            continue
        repo, sha = match.group(1), match.group(2)
        module_base = re.sub(r"[^a-z0-9]", "", str(row["module"]).rsplit("_", 1)[0].lower())
        repo_base = re.sub(r"[^a-z0-9]", "", repo.split("/")[-1].lower())
        if sha[:10] in seen_shas or str(row["module"]) in seen_modules:
            skipped["duplicate_fix"] += 1  # SecBench.js records one upstream fix under several module names
            continue
        if module_base not in repo_base and repo_base not in module_base:
            skipped["module_repo_mismatch"] += 1  # the fix commit belongs to another package; do not attribute
            continue
        seen_shas.add(sha[:10])
        seen_modules.add(str(row["module"]))
        time.sleep(0.6)
        try:
            commit = _gh(f"repos/{repo}/commits/{sha}")
            info = _gh(f"repos/{repo}")
        except Exception:  # noqa: BLE001 — upstream gone or renamed
            skipped["api"] += 1
            continue
        assert isinstance(commit, dict) and isinstance(info, dict)
        license_id = (info.get("license") or {}).get("spdx_id") or ""
        if license_id not in ACCEPTED_LICENSES:
            skipped["unlicensed"] += 1
            continue
        files = [f for f in commit.get("files", []) if _JS.search(f["filename"]) and not _SKIP.search(f["filename"]) and f.get("patch")]
        if not files:
            skipped["no_js_file"] += 1
            continue
        if len(files) > 3:
            skipped["multi_file"] += 1
            continue
        target = sorted(files, key=lambda f: -(f.get("additions", 0) + f.get("deletions", 0)))[0]
        parents = commit.get("parents") or []
        if not parents:
            skipped["api"] += 1
            continue
        cwe, cls_text, mechanism = CLASSES[row["class"]]
        module = str(row["module"])
        name = f"{re.sub(r'[^a-z0-9]+', '-', module.lower()).strip('-')}"[:60]
        recipes.append(
            {
                "name": name,
                "host": "github",
                "repo": repo,
                "parent": parents[0]["sha"],
                "commit": commit["sha"],
                "path": target["filename"],
                "mode": "hunk",
                "language": "typescript" if target["filename"].endswith(".ts") else "javascript",
                "relpath": target["filename"],
                "license": license_id,
                "cve": str(row.get("cve") or ""),
                "year": int(str(commit["commit"]["author"]["date"])[:4]),
                "cwe": cwe,
                "class": cls_text,
                "mechanism": mechanism,
                "provenance": "human",
                "origin": "secbench.js",
                "project": module.rsplit("_", 1)[0],
                "sink_location": str(row.get("sink") or ""),
                "secbench_class": row["class"],
                "evidence": f"SecBench.js {row['class']} sink {row.get('sink')} fixed upstream in {sha[:12]}",
                "commit_url": f"https://github.com/{repo}/commit/{commit['sha']}",
            }
        )
    for index, recipe in enumerate(sorted(recipes, key=lambda r: str(r["name"]))):
        recipe["split"] = "holdout" if index % 2 else "train"
    return recipes, skipped


def to_toml(recipes: list[dict[str, object]]) -> str:
    lines = [
        "# vfc-js harvest recipes derived from SecBench.js fixCommit metadata by build_recipes.py.",
        "# Excerpts come from the upstream package repository (its license), never from SecBench.js.",
        "",
    ]
    for recipe in sorted(recipes, key=lambda r: str(r["name"])):
        lines.append("[[recipe]]")
        for key, value in recipe.items():
            if isinstance(value, int) and not isinstance(value, bool):
                lines.append(f"{key} = {value}")
            else:
                lines.append(f'{key} = "{str(value).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"')
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crawl", type=Path, help="write the SecBench.js module list with GitHub fix commits to this jsonl")
    parser.add_argument("--classes", default="command-injection,path-traversal,code-injection")
    parser.add_argument("--from", dest="source", type=Path, help="jsonl produced by --crawl")
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--out", type=Path, default=ROOT / "recipes.toml")
    args = parser.parse_args(argv)
    if args.crawl:
        print(f"crawled {crawl(args.crawl, tuple(args.classes.split(',')))} modules -> {args.crawl}")
    if args.source:
        recipes, skipped = build(args.source, limit=args.limit)
        args.out.write_text(to_toml(recipes), encoding="utf-8")
        print(f"wrote {args.out} ({len(recipes)} recipes); skipped {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
