#!/usr/bin/env python3
"""Extract one function from public parent/fix blobs. Maintainer-only; CI stays offline.

Does not clone mozilla-central, gecko-dev, or Chromium. Advisory-only recipes
(no parent and commit) are rejected. FixFox is not a fetch source.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ALLOWED_HOSTS = {
    "raw.githubusercontent.com",
    "github.com",
    "phabricator.services.mozilla.com",
    "hg.mozilla.org",
    "hg-edge.mozilla.org",
}
BLOCKED_TOKENS = ("fixfox", "zenodo.org/record")


class RecipeError(ValueError):
    """Invalid harvest recipe."""


def extract_function(source: str, function_name: str) -> str:
    """Copy the named function through balanced braces."""
    needle = function_name
    idx = 0
    while True:
        found = source.find(needle, idx)
        if found < 0:
            raise RecipeError(f"function not found: {function_name}")
        before = source[found - 1] if found else " "
        after_name = source[found + len(needle) : found + len(needle) + 1]
        if before.isalnum() or before == "_":
            idx = found + len(needle)
            continue
        rest = source[found + len(needle) :].lstrip()
        if rest.startswith("(") or rest.startswith("<") or rest.startswith("{") or after_name in "(<{":
            brace = source.find("{", found)
            semi = source.find(";", found)
            if brace >= 0 and (semi < 0 or brace < semi):
                break
        idx = found + len(needle)
    line_start = source.rfind("\n", 0, found) + 1
    prev_nl = source.rfind("\n", 0, line_start - 1)
    prev_line = source[prev_nl + 1 : line_start]
    start = line_start
    stripped_prev = prev_line.strip()
    if (
        stripped_prev
        and not stripped_prev.startswith(("/", "*", "#", "//"))
        and "{" not in prev_line
        and ";" not in prev_line
        and not stripped_prev.startswith(("sub ", "def ", "class "))
    ):
        start = prev_nl + 1
    brace = source.find("{", found)
    if brace < 0:
        raise RecipeError(f"no body for function: {function_name}")
    depth = 0
    for pos, char in enumerate(source[brace:], brace):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : pos + 1].strip() + "\n"
    raise RecipeError(f"unbalanced braces for function: {function_name}")


def provenance_header(recipe: dict[str, Any], *, side: str, sha: str) -> str:
    lines = [
        f"Provenance: {recipe.get('repo', '')} {recipe.get('function', '')} ({side}).",
        f"repo: {recipe.get('repo', '')}",
        f"commit: {sha}",
        f"parent: {recipe.get('parent', '')}",
        f"commit_url: {recipe.get('commit_url', '')}",
        f"cve: {recipe.get('cve', '')}",
        f"license: {recipe.get('license', '')}",
        f"function: {recipe.get('function', '')}",
        f"relpath: {recipe.get('relpath', recipe.get('path', ''))}",
    ]
    prefix = "//" if str(recipe.get("language", "c")).startswith("c") and str(recipe.get("path", "")).endswith((".cc", ".cpp", ".java", ".js")) else "/*"
    if prefix == "//":
        return "\n".join(f"// {line}" for line in lines) + "\n"
    return "/* " + "\n * ".join(lines) + "\n */\n"


def validate_recipe(recipe: dict[str, Any]) -> None:
    name = str(recipe.get("name", ""))
    if any(token in str(recipe).lower() for token in BLOCKED_TOKENS):
        raise RecipeError(f"{name}: embargoed or blocked dataset")
    if not recipe.get("parent") or not recipe.get("commit"):
        raise RecipeError(f"{name}: advisory-only recipe rejected; parent and commit required")
    if not recipe.get("path") or not recipe.get("function"):
        raise RecipeError(f"{name}: path and function required")
    if not recipe.get("license"):
        raise RecipeError(f"{name}: license required")


def github_raw_url(repo: str, sha: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"


def excerpt_paths(recipe: dict[str, Any], root: Path) -> tuple[Path, Path]:
    name = str(recipe["name"])
    ext = Path(str(recipe.get("path", "a.c"))).suffix or ".c"
    folder = root / name
    return folder / f"vuln{ext}", folder / f"fixed{ext}"


def write_excerpt(path: Path, recipe: dict[str, Any], *, side: str, sha: str, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = provenance_header(recipe, side=side, sha=sha)
    path.write_text(header + "\n" + body, encoding="utf-8")


def harvest_recipe(recipe: dict[str, Any], root: Path) -> tuple[Path, Path]:
    validate_recipe(recipe)
    if str(recipe.get("host", "github")) != "github":
        raise RecipeError(f"{recipe.get('name')}: live fetch currently implemented for host=github only")
    parent_src = fetch_url(github_raw_url(str(recipe["repo"]), str(recipe["parent"]), str(recipe["path"])))
    fix_src = fetch_url(github_raw_url(str(recipe["repo"]), str(recipe["commit"]), str(recipe["path"])))
    function = str(recipe["function"])
    parent_fn = extract_function(parent_src, function)
    fix_fn = extract_function(fix_src, function)
    vuln_path, fixed_path = excerpt_paths(recipe, root)
    write_excerpt(vuln_path, recipe, side="vuln", sha=str(recipe["parent"]), body=parent_fn)
    write_excerpt(fixed_path, recipe, side="fixed", sha=str(recipe["commit"]), body=fix_fn)
    return vuln_path, fixed_path


def fetch_url(url: str, timeout: int = 60) -> str:
    host = urlparse(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise RecipeError(f"host not allowed: {host}")
    request = Request(url, headers={"User-Agent": "OpenUltraSAST-vfc-harvest"})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 — host allowlisted
        return response.read().decode("utf-8", "replace")


def load_recipes(path: Path) -> tuple[dict[str, Any], ...]:
    payload = tomllib.loads(path.read_text())
    return tuple(dict(item) for item in payload.get("recipe", []))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipes", type=Path, default=Path(__file__).with_name("recipes.toml"))
    parser.add_argument("--name", help="recipe name to harvest (omit with --all)")
    parser.add_argument("--all", action="store_true", help="process every recipe")
    parser.add_argument("--fetch", action="store_true", help="HTTP-fetch and write excerpts; default is dry-run validate")
    parser.add_argument("--force", action="store_true", help="overwrite existing excerpts")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent, help="excerpt root")
    args = parser.parse_args(argv)
    loaded = load_recipes(args.recipes)
    recipes = {str(item["name"]): item for item in loaded}
    selected: list[dict[str, Any]]
    if args.all:
        selected = list(loaded)
    elif args.name:
        if args.name not in recipes:
            print(f"unknown recipe: {args.name}", file=sys.stderr)
            return 2
        selected = [recipes[args.name]]
    else:
        print("pass --name RECIPE or --all", file=sys.stderr)
        return 2
    failures = 0
    for recipe in selected:
        name = str(recipe["name"])
        try:
            validate_recipe(recipe)
        except RecipeError as exc:
            print(str(exc), file=sys.stderr)
            failures += 1
            continue
        if not args.fetch:
            print(f"ok {name} parent={recipe['parent']} commit={recipe['commit']}")
            continue
        vuln_path, fixed_path = excerpt_paths(recipe, args.out)
        if vuln_path.is_file() and fixed_path.is_file() and not args.force:
            print(f"skip {name} (exists)")
            continue
        try:
            harvest_recipe(recipe, args.out)
        except RecipeError as exc:
            print(f"{name}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"wrote {name} -> {vuln_path.parent}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
