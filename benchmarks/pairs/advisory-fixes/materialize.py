"""Materialise and verify the advisory-fix pairs (both sides of each advisory-named function at a real fix).

Each pair in ``catalog.toml`` names a public fix commit, its parent, the file and the advisory-named function. This
script reads the two versions of that one file from a shallow BLOBLESS fetch (``--filter=blob:none``, depth 2) kept in
the pair cache (``$OPENULTRASAST_PAIR_CACHE`` or ``~/.cache/openultrasast/pairs``), cuts the function out of each side
with the label builder's own matcher (``openultrasast.learn.excerpt.function_bounds``), and writes the two excerpts
where ``load_pair_catalog`` looks for a pointer pair (``<cache>/advisory-fixes/<name>/{vuln,fixed}<ext>``). Nothing is
vendored into the repository, and no scanner, rule, engine or model ever runs on these repositories.

Verification (the default, offline) re-reads the cached excerpts the way ``ousast learn labels`` does and fails a
pair unless: the fix commit differs from its parent, the function is declared on both sides, and its body (the lines
after the declaration, whitespace-normalised) differs between them. It reports the bytes it read per pair, so a pass
over an unread cache cannot look like a clean result.

    PYTHONPATH=src python benchmarks/pairs/advisory-fixes/materialize.py            # verify the cache (offline)
    PYTHONPATH=src python benchmarks/pairs/advisory-fixes/materialize.py --fetch    # fetch what is missing, verify
    PYTHONPATH=src python benchmarks/pairs/advisory-fixes/materialize.py --candidate --repo o/r --commit F \
        --parent P --path a/b.py --function f --language python --name o-r-f   # check one candidate (research)
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CATALOG = HERE / "catalog.toml"
SLICE = "advisory-fixes"
MIN_FREE_BYTES = 1_200_000_000  # stop before the host disk drops under 1.2 GB
MAX_REPO_KB = 150_000  # repositories over ~150 MB are skipped
_SHA = re.compile(r"[0-9a-f]{40}")


def _harvest() -> Any:
    spec = importlib.util.spec_from_file_location("ousast_pair_harvest", HERE.parent / "harvest.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cache_root() -> Path:
    from openultrasast.pairs import pair_cache_dir

    return pair_cache_dir() / SLICE


def _git(clone: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", str(clone), *args], capture_output=True, check=check, timeout=600)


def _has_commit(clone: Path, sha: str) -> bool:
    return _git(clone, "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode == 0


def repo_metadata(repo: str) -> dict[str, Any]:
    """Size (KB) and SPDX licence from the GitHub API through ``gh`` (metadata only)."""
    out = subprocess.run(
        ["gh", "api", f"repos/{repo}", "--jq", "{size: .size, license: .license.spdx_id, archived: .archived}"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if out.returncode != 0:
        raise RuntimeError(f"gh api repos/{repo}: {out.stderr.strip()[:200]}")
    return dict(json.loads(out.stdout))


def fetch(repo: str, commit: str, parent: str) -> Path:
    """A shallow blobless clone holding ``commit`` and ``parent`` (blobs arrive lazily, one per ``git show``)."""
    free = shutil.disk_usage(Path.home()).free
    if free < MIN_FREE_BYTES:
        raise RuntimeError(f"free disk {free / 1e9:.2f} GB is under the 1.2 GB floor; stopping")
    clone = cache_root() / "_clones" / repo.replace("/", "__")
    if not (clone / ".git").is_dir():
        clone.mkdir(parents=True, exist_ok=True)
        _git(clone, "init", "-q")
        _git(clone, "remote", "add", "origin", f"https://github.com/{repo}.git")
        _git(clone, "config", "remote.origin.promisor", "true")
        _git(clone, "config", "remote.origin.partialclonefilter", "blob:none")
        _git(clone, "config", "extensions.partialClone", "origin")
    for sha, depth in ((commit, "2"), (parent, "1")):
        if not _has_commit(clone, sha):
            _git(clone, "fetch", "-q", "--filter=blob:none", f"--depth={depth}", "origin", sha)
    return clone


def show(clone: Path, sha: str, path: str) -> str:
    return _git(clone, "show", f"{sha}:{path}").stdout.decode("utf-8", "replace")


def _comment(language: str) -> str:
    return "#" if language in {"python", "ruby"} else "//"


def _body(lines: list[str], span: tuple[int, int]) -> str:
    return re.sub(r"\s+", " ", "\n".join(lines[span[0] + 1 : span[1]])).strip()


def extract(source: str, language: str, function: str) -> tuple[list[str], tuple[int, int]] | None:
    from openultrasast.learn.excerpt import LANGUAGE_ALIASES, function_bounds

    lines = source.splitlines()
    span = function_bounds(lines, LANGUAGE_ALIASES.get(language, language), function)
    return (lines, span) if span else None


def write_side(path: Path, pair: dict[str, Any], *, side: str, sha: str, lines: list[str], span: tuple[int, int]) -> None:
    mark = _comment(str(pair["language"]))
    header = [
        f"Provenance: {pair['repo']} {pair['function']} ({side}).",
        f"repo: {pair['repo']}",
        f"commit: {sha}",
        f"parent: {pair['parent']}",
        f"commit_url: {pair.get('commit_url', '')}",
        f"cve: {pair.get('cve', '')}",
        f"license: {pair.get('license', '')}",
        f"function: {pair['function']}",
        f"relpath: {pair['path']}",
        f"upstream_start: {span[0] + 1}",
    ]
    body = "\n".join(lines[span[0] : span[1]])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(f"{mark} {line}" for line in header) + "\n" + _harvest().redact(body) + "\n", encoding="utf-8")


def excerpt_paths(pair: dict[str, Any]) -> tuple[Path, Path]:
    ext = Path(str(pair["path"])).suffix or ".c"
    folder = cache_root() / str(pair["name"])
    return folder / f"vuln{ext}", folder / f"fixed{ext}"


def materialise(pair: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
    """Fetch both sides of one pair and write its excerpts; the source bytes read are reported."""
    vuln_path, fixed_path = excerpt_paths(pair)
    if vuln_path.is_file() and fixed_path.is_file() and not force:
        return {"name": pair["name"], "fetched": False}
    commit, parent = str(pair["commit"]), str(pair["parent"])
    clone = fetch(str(pair["repo"]), commit, parent)
    vuln_src = show(clone, parent, str(pair["path"]))
    fixed_src = show(clone, commit, str(pair.get("fix_path") or pair["path"]))
    function, language = str(pair["function"]), str(pair["language"])
    vuln, fixed = extract(vuln_src, language, function), extract(fixed_src, language, function)
    if vuln is None or fixed is None:
        missing = [side for side, got in (("vulnerable", vuln), ("fixed", fixed)) if got is None]
        raise RuntimeError(f"{function} not declared on the {' and '.join(missing)} side")
    write_side(vuln_path, pair, side="vuln", sha=parent, lines=vuln[0], span=vuln[1])
    write_side(fixed_path, pair, side="fixed", sha=commit, lines=fixed[0], span=fixed[1])
    return {"name": pair["name"], "fetched": True, "source_bytes": len(vuln_src.encode()) + len(fixed_src.encode())}


def verify(pair: dict[str, Any]) -> dict[str, Any]:
    """The label builder's check, from the cached excerpts: declared on both sides, body changed, a real fix."""
    from openultrasast.learn.excerpt import LANGUAGE_ALIASES, function_bounds

    result: dict[str, Any] = {"name": pair["name"], "ok": False, "bytes_read": 0}
    commit, parent = str(pair.get("commit", "")), str(pair.get("parent", ""))
    if not (_SHA.fullmatch(commit) and _SHA.fullmatch(parent)) or commit == parent:
        result["reason"] = "fix commit must be a full SHA distinct from its parent"
        return result
    language = LANGUAGE_ALIASES.get(str(pair["language"]), str(pair["language"]))
    spans = {}
    for side, path in zip(("vuln", "fixed"), excerpt_paths(pair), strict=True):
        if not path.is_file():
            result["reason"] = f"{side} excerpt not materialised ({path})"
            return result
        text = path.read_text(encoding="utf-8")
        result["bytes_read"] += len(text.encode())
        lines = text.splitlines()
        span = function_bounds(lines, language, str(pair["function"]))
        if span is None:
            result["reason"] = f"{pair['function']} is not declared on the {side} side"
            return result
        spans[side] = _body(lines, span)
    if not spans["vuln"] or spans["vuln"] == spans["fixed"]:
        result["reason"] = "function body is unchanged by the fix"
        return result
    result["ok"] = True
    return result


def _flatten(item: dict[str, Any]) -> dict[str, Any]:
    pair = dict(item)
    expected = (item.get("expected") or [{}])[0]
    pair.setdefault("function", expected.get("function", ""))
    return pair


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--fetch", action="store_true", help="fetch missing sides over the network, then verify")
    parser.add_argument("--force", action="store_true", help="re-fetch and rewrite excerpts that exist")
    parser.add_argument("--json", type=Path, help="write the per-pair report here")
    parser.add_argument("--candidate", action="store_true", help="check one candidate given on the command line")
    for key in ("repo", "commit", "parent", "path", "fix-path", "function", "language", "name"):
        parser.add_argument(f"--{key}")
    args = parser.parse_args(argv)
    if args.candidate:
        pair = {k: getattr(args, k.replace("-", "_")) for k in ("repo", "commit", "parent", "path", "function", "language", "name")}
        pair["fix_path"] = args.fix_path
        try:
            meta = repo_metadata(pair["repo"])
            if int(meta.get("size") or 0) > MAX_REPO_KB:
                print(json.dumps({"name": pair["name"], "ok": False, "reason": f"repository is {meta['size']} KB (> 150 MB)", **meta}))
                return 1
            fetched = materialise(pair, force=args.force)
        except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            detail = (
                exc.stderr.decode(errors="replace")[:200] if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
            )
            print(json.dumps({"name": pair["name"], "ok": False, "reason": f"fetch: {detail}"}))
            return 1
        report = {**verify(pair), **{k: v for k, v in fetched.items() if k != "name"}, **meta}
        print(json.dumps(report))
        return 0 if report["ok"] else 1
    pairs = [_flatten(item) for item in tomllib.loads(args.catalog.read_text()).get("pair", [])]
    rows = []
    for pair in pairs:
        fetched: dict[str, Any] = {}
        if args.fetch:
            try:
                fetched = materialise(pair, force=args.force)
            except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                fetched = {"fetch_error": str(exc)[:200]}
        rows.append({**verify(pair), **{k: v for k, v in fetched.items() if k != "name"}})
    failed = [row for row in rows if not row["ok"]]
    for row in rows:
        print(
            f"{'ok  ' if row['ok'] else 'FAIL'} {row['name']}: {row['bytes_read']} bytes read"
            + ("" if row["ok"] else f" -- {row['reason']}")
        )
    total = sum(row["bytes_read"] for row in rows)
    print(f"{len(rows) - len(failed)}/{len(rows)} pairs verified; {total} excerpt bytes read")
    if args.json:
        args.json.write_text(json.dumps({"pairs": rows, "verified": len(rows) - len(failed), "bytes_read": total}, indent=2) + "\n")
    return 1 if failed or not rows else 0


if __name__ == "__main__":
    sys.exit(main())
