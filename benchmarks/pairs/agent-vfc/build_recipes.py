#!/usr/bin/env python3
"""Build agent-vfc candidate recipes from agent-authored security-fix commits (maintainer, network via gh).

Candidates come from GitHub commit search on agent co-author trailers or generation
markers plus security-fix wording (see --search). Each candidate is kept only when the
repository states a license, the fix touches one to three JavaScript, TypeScript, or
Python files, and the largest changed file has at most --max-lines changed lines.
Every recipe starts with ``reviewer = "pending"``; a human must set the reviewer and
confirm the mechanism before the pair is trusted (Req 5.3).

    python benchmarks/pairs/agent-vfc/build_recipes.py --search /tmp/agent_candidates.jsonl
    python benchmarks/pairs/agent-vfc/build_recipes.py --from /tmp/agent_candidates.jsonl
    python benchmarks/pairs/harvest.py --slice agent-vfc --all --fetch
    python benchmarks/pairs/catalog_gen.py --slice agent-vfc
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TRAILERS = (
    '"Co-Authored-By: Claude"',
    '"Generated with Claude Code"',
    '"Co-authored-by: Cursor"',
    '"Co-authored-by: Codex"',
    '"Co-authored-by: Copilot"',
    '"Co-authored-by: devin"',
)
KEYWORDS = (
    '"fix IDOR"',
    '"SQL injection"',
    '"path traversal"',
    "SSRF",
    '"hardcoded secret"',
    '"CORS"',
    '"row level security"',
    '"authorization check"',
    '"command injection"',
    '"prototype pollution"',
    '"open redirect"',
    '"missing authentication"',
)
MECHANISM_BY_TITLE = (
    (
        re.compile(r"\bidor\b|ownership|owner.?scope|user_id from|tenant", re.I),
        "identity_from_request_body",
        "CWE-639",
        "insecure direct object reference",
    ),
    (
        re.compile(r"missing auth|unauthenticated|auth(?:orization|entication)? (?:check|guard|middleware)|require.?auth", re.I),
        "missing_auth_guard",
        "CWE-862",
        "missing authorization",
    ),
    (re.compile(r"sql injection|sqli", re.I), "source_reaches_sink", "CWE-89", "sql injection"),
    (re.compile(r"path traversal|zip slip|directory traversal", re.I), "path_join_user_input", "CWE-22", "path traversal"),
    (re.compile(r"\bssrf\b", re.I), "source_reaches_sink", "CWE-918", "server-side request forgery"),
    (re.compile(r"command injection|shell injection", re.I), "source_reaches_sink", "CWE-78", "command injection"),
    (re.compile(r"prototype pollution", re.I), "prototype_pollution", "CWE-1321", "prototype pollution"),
    (re.compile(r"open redirect", re.I), "source_reaches_sink", "CWE-601", "open redirect"),
    (
        re.compile(r"hardcoded|hard-coded|leaked (?:key|secret|token)|service.?role", re.I),
        "secret_in_client",
        "CWE-798",
        "hardcoded credentials",
    ),
    (re.compile(r"\bcors\b|row level security|\brls\b|debug", re.I), "permissive_default", "CWE-16", "permissive default"),
)
ACCEPTED_LICENSES = {
    "MIT",
    "Apache-2.0",
    "BSD-3-Clause",
    "BSD-2-Clause",
    "ISC",
    "MPL-2.0",
    "GPL-3.0",
    "GPL-2.0",
    "AGPL-3.0",
    "Unlicense",
    "0BSD",
}
_CODE = re.compile(r"\.(py|js|mjs|cjs|ts|tsx)$")
_SKIP = re.compile(r"(test|spec|\.d\.ts|migration|dist/|build/|min\.js|\.config\.|stories)", re.I)
_NOISE = re.compile(r"\b(css|icon|i18n|layout|docs?|tracker|sess[aã]o|chore|bump|migration|workflow)\b", re.I)


def _gh(args: list[str]) -> object:
    return json.loads(subprocess.check_output(["gh", "api", *args], stderr=subprocess.DEVNULL))


def search(out: Path) -> int:
    seen: set[tuple[str, str]] = set()
    with out.open("w") as handle:
        for trailer in TRAILERS:
            for keyword in KEYWORDS:
                time.sleep(6)  # commit search has a strict secondary rate limit
                try:
                    result = _gh(["-X", "GET", "search/commits", "-f", f"q={trailer} {keyword} fix", "-f", "per_page=30"])
                except Exception:  # noqa: BLE001 — rate limited; keep going
                    continue
                for item in result.get("items", []) if isinstance(result, dict) else []:
                    key = (item["repository"]["full_name"], item["sha"])
                    if key in seen:
                        continue
                    seen.add(key)
                    handle.write(
                        json.dumps(
                            {
                                "repo": key[0],
                                "sha": key[1],
                                "title": item["commit"]["message"].split("\n")[0][:160],
                                "date": item["commit"]["author"]["date"],
                            }
                        )
                        + "\n"
                    )
    return len(seen)


def classify(title: str) -> tuple[str, str, str] | None:
    for pattern, mechanism, cwe, cls in MECHANISM_BY_TITLE:
        if pattern.search(title):
            return mechanism, cwe, cls
    return None


def build(source: Path, *, limit: int, max_lines: int) -> tuple[list[dict[str, object]], dict[str, int]]:
    recipes: list[dict[str, object]] = []
    skipped = {"noise_title": 0, "unclassified": 0, "unlicensed": 0, "no_code_file": 0, "too_big": 0, "api": 0, "duplicate_repo": 0}
    per_repo: dict[str, int] = {}
    seen_commits: set[str] = set()  # the same fix commit shows up in every fork
    rows = [json.loads(line) for line in source.read_text().splitlines() if line.strip()]
    for row in sorted(rows, key=lambda r: (r["repo"], r["date"])):
        if len(recipes) >= limit:
            break
        title = str(row["title"])
        if _NOISE.search(title):
            skipped["noise_title"] += 1
            continue
        classified = classify(title)
        if classified is None:
            skipped["unclassified"] += 1
            continue
        if per_repo.get(row["repo"], 0) >= 2 or row["sha"] in seen_commits:
            skipped["duplicate_repo"] += 1
            continue
        seen_commits.add(row["sha"])
        time.sleep(0.8)
        try:
            info = _gh([f"repos/{row['repo']}"])
            commit = _gh([f"repos/{row['repo']}/commits/{row['sha']}"])
        except Exception:  # noqa: BLE001
            skipped["api"] += 1
            continue
        assert isinstance(info, dict) and isinstance(commit, dict)
        license_id = (info.get("license") or {}).get("spdx_id") or ""
        if license_id not in ACCEPTED_LICENSES:
            skipped["unlicensed"] += 1
            continue
        files = [f for f in commit.get("files", []) if _CODE.search(f["filename"]) and not _SKIP.search(f["filename"]) and f.get("patch")]
        if not files or len(files) > 3:
            skipped["no_code_file"] += 1
            continue
        target = sorted(files, key=lambda f: -(f.get("additions", 0) + f.get("deletions", 0)))[0]
        if target.get("additions", 0) + target.get("deletions", 0) > max_lines:
            skipped["too_big"] += 1
            continue
        parents = commit.get("parents") or []
        if not parents:
            skipped["api"] += 1
            continue
        mechanism, cwe, cls = classified
        message = commit["commit"]["message"]
        trailer = next((line.strip() for line in message.splitlines() if re.match(r"(?i)co-authored-by:|generated with", line.strip())), "")
        suffix = Path(target["filename"]).suffix
        language = {".py": "python", ".ts": "typescript", ".tsx": "typescript"}.get(suffix, "javascript")
        base = re.sub(r"[^a-z0-9]+", "-", f"{row['repo'].split('/')[-1]}-{Path(target['filename']).stem}".lower()).strip("-")[:56]
        name = f"{base}-{row['sha'][:6]}"
        per_repo[row["repo"]] = per_repo.get(row["repo"], 0) + 1
        recipes.append(
            {
                "name": name,
                "host": "github",
                "repo": row["repo"],
                "parent": parents[0]["sha"],
                "commit": commit["sha"],
                "path": target["filename"],
                "mode": "hunk",
                "language": language,
                "relpath": target["filename"],
                "license": license_id,
                "cve": "",
                "year": int(str(commit["commit"]["author"]["date"])[:4]),
                "cwe": cwe,
                "class": cls,
                "mechanism": mechanism,
                "provenance": "agent",
                "origin": "github-agent-trailer",
                "project": row["repo"].split("/")[-1],
                "trailer": trailer[:120],
                "reviewer": "pending",
                "evidence": title[:200],
                "commit_url": f"https://github.com/{row['repo']}/commit/{commit['sha']}",
            }
        )
    for index, recipe in enumerate(sorted(recipes, key=lambda r: str(r["name"]))):
        recipe["split"] = "holdout" if index % 2 else "train"
    return recipes, skipped


def to_toml(recipes: list[dict[str, object]]) -> str:
    lines = [
        "# agent-vfc candidate recipes from agent-trailer security-fix commits (build_recipes.py).",
        '# reviewer = "pending" means a human has not yet confirmed the vulnerability and mechanism.',
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
    parser.add_argument("--search", type=Path, help="run the GitHub commit search and write candidates to this jsonl")
    parser.add_argument("--from", dest="source", type=Path, help="candidate jsonl to resolve into recipes")
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--max-lines", type=int, default=80)
    parser.add_argument("--out", type=Path, default=ROOT / "recipes.toml")
    args = parser.parse_args(argv)
    if args.search:
        print(f"searched {search(args.search)} candidates -> {args.search}")
    if args.source:
        recipes, skipped = build(args.source, limit=args.limit, max_lines=args.max_lines)
        args.out.write_text(to_toml(recipes), encoding="utf-8")
        print(f"wrote {args.out} ({len(recipes)} recipes); skipped {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
