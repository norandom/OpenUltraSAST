"""Resumable labelled-function traces with Docker and Kubernetes execution lanes.

Pair blob identities resolve through catalogs to real source commits. The analyzer
is git archive HEAD src plus a hashed snapshot of this uncommitted tool.
"""

from __future__ import annotations

import argparse
import ast
import copy
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

from engine_trace_k8s import IMAGE, Kubernetes
from engine_trace_queue import Dispatcher
from engine_trace_worker import EXCLUDED_DIRS, safe_path, unit_record, write_json

from openultrasast.learn.examples import read_jsonl
from openultrasast.learn.labels import load_sources, repo_name
from openultrasast.model.specs import taint_specs
from openultrasast.model.taint import request_params
from openultrasast.pairs import _materialize_side, load_pair_catalog
from openultrasast.plane.engine_alerts import export_pin
from openultrasast.plane.memory import FileStore
from openultrasast.plane.tasks.alerts import engine_languages
from openultrasast.preprocess import detect_language

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.ax.batch import schedule

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = Path.home() / "ousast-results/plane/engine-trace"
SNAPSHOT_FILES = (
    "benchmarks/learn/engine_trace.py",
    "benchmarks/learn/engine_trace_worker.py",
    "benchmarks/learn/engine_trace_k8s.py",
    "benchmarks/learn/engine_trace_queue.py",
    "benchmarks/learn/engine_trace_ax.py",
    "benchmarks/ax/batch.py",
    "benchmarks/learn/engine_task_entry.py",
    "benchmarks/learn/engine_worker_service.py",
    "benchmarks/learn/engine_trace_parse.py",
    "src/openultrasast/model/taint.py",
    "src/openultrasast/cpg/queries/taint.sc",
)
MATERIALIZATION_VERSION = 3
EXPORT_CAP = 20 * 1024 * 1024

STATUSES = ("path", "asked-nothing", "failed", "timeout", "unsupported")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def pin_name(pin):
    return digest([pin["repo"], pin["pin"]]) + ".json"


def join_units(units, examples, include_typescript=False):
    index = {row["id"]: row for row in examples}
    missing = [u["unit"] for u in units if u["unit"] not in index]
    if missing:
        raise ValueError(f"example snapshot missing {len(missing)}/{len(units)} unit IDs; supply --examples JSONL; first: {missing[0]}")
    covered = engine_languages() - {"typescript"}
    if include_typescript:
        covered |= {"typescript"}
    result = []
    for unit in units:
        example = index[unit["unit"]]
        if any(example[key] != unit[key] for key in ("family", "label", "group")):
            raise ValueError(f"unit/example identity mismatch: {unit['unit']}")
        file, sep, function = example["candidate"].partition("::")
        if not sep or not function:
            raise ValueError(f"unit has no labelled function: {unit['unit']}")
        language = detect_language(Path(file)) or example.get("language", "other")
        model_language = "javascript" if language == "typescript" else language
        spec = taint_specs(language=model_language).get(unit["family"]) if language in covered else None
        result.append(
            {
                **unit,
                "repo": example["repo"],
                "pin": example["pin"],
                "file": file,
                "function": function,
                "language": language,
                "source": example["source"],
                "excerpt": example.get("excerpt", example["source"] == "pairs" or example["source"].startswith("advisory-fixes")),
                "pin_role": example.get("pin_role", ""),
                "supported": spec is not None,
                "reason": "" if spec else f"no admitted taint model: {language}/{unit['family']}",
            }
        )
    return result


def make_plan(
    units,
    out,
    only_family=None,
    limit=0,
    *,
    include_typescript=False,
    only_source=(),
    rerun_status=("failed",),
    allow_excerpt_fallback=False,
):
    grouped = defaultdict(list)
    for unit in units:
        if (not only_family or unit["family"] == only_family) and (not only_source or unit["source"] in only_source):
            # Include admission options even when a unit's support happens to stay
            # unchanged. Old results cannot mark a different selection as complete.
            identity = {
                "unit": unit,
                "include_typescript": include_typescript,
                "materialization_version": MATERIALIZATION_VERSION,
                "allow_excerpt_fallback": allow_excerpt_fallback,
            }
            grouped[unit["repo"], unit["pin"]].append({**unit, "input_digest": digest(identity)})
    plan = []
    for (repo, pin), rows in sorted(grouped.items()):
        item = {
            "repo": repo,
            "pin": pin,
            "materialization_version": MATERIALIZATION_VERSION,
            "units": sorted(rows, key=lambda r: r["unit"]),
        }
        item["selection"] = digest(item["units"])
        done = out / pin_name(item)
        if done.exists():
            old = json.loads(done.read_text())
            recorded = {r["unit"]: r.get("input_digest") for r in old.get("units", [])}
            if (
                old.get("done")
                and not old.get("fallback_pending")
                and old.get("materialization_version") == MATERIALIZATION_VERSION
                and not any(r.get("status") in rerun_status for r in old.get("units", []) if r["unit"] in {u["unit"] for u in rows})
                and all(recorded.get(r["unit"]) == r["input_digest"] for r in rows)
            ):
                continue
        sources = {r["source"] for r in rows}
        # Inventory medians: harvest sides 31s, advisory sides 47s; v1 pins 182s, v2 pins 498s.
        item["estimated_seconds"] = (
            (47 if any(s.startswith("advisory") for s in sources) else 31)
            if any(r.get("excerpt") for r in rows) or any(s.startswith("advisory") for s in sources)
            else (182 if sources == {"population-v1"} else 498)
        )
        if not any(r["supported"] for r in rows):
            item["estimated_seconds"] = 0
        plan.append(item)
    # limit counts runnable pins, not unsupported records.
    if limit:
        chosen = []
        count = 0
        for pin in plan:
            runnable = any(r["supported"] for r in pin["units"])
            if runnable and count >= limit:
                continue
            chosen.append(pin)
            count += runnable
        return chosen
    return plan


class Inputs:
    """Resolve spent corpora; fetch pair source commits into the host cache."""

    def __init__(self, root, cache, allow_excerpt_fallback=False, *, keep_sources=False, source_cache_mb=500):
        self.cache = cache
        self.allow_excerpt_fallback = allow_excerpt_fallback
        self.keep_sources = keep_sources
        self.source_cache_bytes = source_cache_mb * 1024 * 1024
        self.catalog_rows = defaultdict(list)
        for catalog in (root / "benchmarks/pairs").rglob("catalog.toml"):
            for item in tomllib.loads(catalog.read_text()).get("pair", []):
                self.catalog_rows[item["name"]].append((catalog.parent.name, item))
        self.pairs = []
        self.repos = defaultdict(list)
        sources = load_sources()
        for source in sources.sources:
            if source.kind == "pairs":
                self.pairs.extend(load_pair_catalog(root / source.files[0]))
            elif source.kind == "population":
                if source.id not in {"population-v1", "population-v2"}:
                    continue
                data = tomllib.loads((root / source.files[0]).read_text())
                for case in data.get("case", []):
                    self.repos[repo_name(case["repo"])].append((cache / "independent" / case["id"], case))
            elif source.kind == "recipes":
                for file in source.files:
                    data = tomllib.loads((root / file).read_text())
                    recipe = data.get("repo", data)
                    # Recipes carry a top-level URL and a pinned checkout cache.
                    if isinstance(recipe, dict):
                        self.repos[repo_name(str(recipe.get("url", "")))].append((cache / "repos" / str(data.get("name", "")), data))
        self.hashes = {}

    def pair_for(self, row):
        if row["pin_role"] not in {"fixed", "vulnerable", "vuln"}:
            raise ValueError(f"ambiguous pair side: {row['pin_role']}")
        side = "fixed" if row["pin_role"] == "fixed" else "vuln"
        candidates = [
            c for c in self.pairs if c.relpath == row["file"] and repo_name(c.repo or f"{c.slice}:{c.name}") == repo_name(row["repo"])
        ]
        matches = []
        for case in candidates:
            path = case.fixed_file if side == "fixed" else case.vuln_file
            if path.is_file():
                if path not in self.hashes:
                    data = path.read_bytes()
                    # Harvest hashes decoded text, so universal newline conversion is part
                    # of its identity (one recorded ThreatByte excerpt uses CRLF).
                    normalized = path.read_text().encode("utf-8")
                    self.hashes[path] = {
                        hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() for body in (data, normalized)
                    }
                if row["pin"] in self.hashes[path]:
                    matches.append(case)
        if len(matches) == 1:
            return matches[0], side
        if len(candidates) == 1:
            # Earlier stores used label_pin rather than the excerpt digest.
            from openultrasast.learn.examples import label_pin

            case = candidates[0]
            if row["pin"] == label_pin({"source": "pairs", "source_ref": case.name, "pin_role": row["pin_role"]}):
                return case, side
        raise ValueError(f"cannot uniquely resolve excerpt {row['repo']}@{row['pin']}:{row['file']}")

    def catalog_for(self, case):
        matches = [
            (source, item)
            for source, item in self.catalog_rows[case.name]
            if item.get("relpath") == case.relpath and repo_name(item.get("repo", "")) == repo_name(case.repo)
        ]
        if len(matches) != 1:
            raise ValueError(f"ambiguous catalog source for {case.name}")
        return matches[0]

    def source_identity(self, case, side):
        _, item = self.catalog_for(case)
        parent, commit = item.get("parent", ""), item.get("commit", "")
        if side not in {"vuln", "fixed"} or not all(re.fullmatch(r"[0-9a-fA-F]{40}", sha) for sha in (parent, commit)) or parent == commit:
            raise ValueError(f"ambiguous catalog commits for {case.name}: need distinct parent and commit SHAs")
        repo = item.get("repo", "")
        if not repo:
            raise ValueError(f"missing catalog repository for {case.name}")
        return repo, parent if side == "vuln" else commit

    def source_path(self, repo, commit, roots):
        return self.cache / "trace-sources" / digest([repo, commit, roots])

    def prepare_source_cache(self):
        cache = self.cache / "trace-sources"
        cache.mkdir(parents=True, exist_ok=True)
        entries = []
        for entry in cache.iterdir():
            if entry.is_dir() and not entry.is_symlink():
                size = sum(p.stat().st_size for p in entry.rglob("*") if not p.is_symlink() and p.is_file())
                entries.append((entry.stat().st_mtime_ns, entry, size))
        total = sum(size for _, _, size in entries)
        for _, entry, size in sorted(entries):
            if total <= self.source_cache_bytes:
                break
            shutil.rmtree(entry)
            total -= size
        free = shutil.disk_usage(cache).free
        if free < 1.5 * 1024**3:
            raise OSError(f"refusing source fetch: {free / 1024**3:.2f} GB free at {cache}; at least 1.5 GB required")

    def fetch_source(self, repo, commit, roots):
        self.prepare_source_cache()
        clone = self.source_path(repo, commit, roots)
        clone.mkdir(parents=True, exist_ok=True)
        url = repo if repo.startswith("https://") else f"https://github.com/{repo.removesuffix('.git')}.git"
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        env.pop("GIT_NO_LAZY_FETCH", None)  # sparse checkout may fetch the selected blobs

        def git(*args):
            return subprocess.run(["git", "-C", str(clone), *args], env=env, capture_output=True, text=True, check=True, timeout=300)

        git("init")
        git("config", "remote.origin.url", url)
        git("config", "remote.origin.promisor", "true")
        git("config", "remote.origin.partialclonefilter", "blob:none")
        git("fetch", "--depth", "1", "--filter=blob:none", url, commit)
        git("sparse-checkout", "init", "--cone")
        git("sparse-checkout", "set", "--", *roots)
        git("checkout", "--detach", "--force", commit)
        actual = git("rev-parse", "HEAD").stdout.strip()
        if actual != commit:
            raise ValueError(f"fetched commit mismatch: {actual} != {commit}")
        return clone

    def export_local(self, clone, pin, target):
        with tempfile.TemporaryDirectory(prefix="trace-export-", dir=target.parent) as scratch:
            export_pin(clone, pin["pin"], Path(scratch))
            roots = sorted({source_root(r["file"], r["language"]) for r in pin["units"]})
            proof = export_sources(Path(scratch), target, pin["units"], roots)
        return {**proof, "mode": "source", "commit": pin["pin"]}

    def materialize(self, pin, target):
        rows = pin["units"]
        for row in rows:
            safe_path(target, row["file"])
            if row.get("mapping_error"):
                raise ValueError(row["mapping_error"])
        if any(r.get("excerpt") or r["source"].startswith("advisory-fixes") for r in rows):
            resolved = [self.pair_for(row) for row in rows]
            identities = set()
            catalog_files = []
            for case, side in resolved:
                _, item = self.catalog_for(case)
                parent, commit = item.get("parent", ""), item.get("commit", "")
                if parent != commit and all(re.fullmatch(r"[0-9a-fA-F]{40}", sha) for sha in (parent, commit)):
                    identities.add(self.source_identity(case, side))
                else:
                    file = case.fixed_file if side == "fixed" else case.vuln_file
                    data = file.read_text()
                    if is_catalog_excerpt(data):
                        data = parseable_excerpt(file, data)
                        mode = "excerpt-parseable"
                    else:
                        # Validate BOTH twins before treating this as a complete-file pair.
                        for twin in (case.vuln_file, case.fixed_file):
                            verify_catalog_file(twin)
                        mode = "catalog-file"
                    catalog_files.append((case, side, mode, data))
            if catalog_files:
                if identities:
                    raise ValueError("mixed source and catalog-file materialization at one pair pin")
                for case, side, mode, data in catalog_files:
                    _materialize_side(target, case, side=side)
                    if mode == "excerpt-parseable":
                        safe_path(target, case.relpath).write_text(data)
                verify_functions(target, rows)
                modes = {case.relpath: mode for case, _, mode, _ in catalog_files}
                for row in rows:
                    if modes[row["file"]] == "excerpt-parseable":
                        row["evidence_scope"] = "in-function-only"
                return {
                    "mode": "excerpt-parseable" if "excerpt-parseable" in modes.values() else "catalog-file",
                    "files": sum(p.is_file() for p in target.rglob("*")),
                    "bytes": sum(p.stat().st_size for p in target.rglob("*") if p.is_file()),
                    "roots": sorted({source_root(r["file"], r["language"]) for r in rows}),
                }
            if len(identities) != 1:
                raise ValueError("ambiguous source commits at one pair pin")
            repo, commit = identities.pop()
            roots = sorted({source_root(row["file"], row["language"]) for row in rows})
            try:
                clone = self.fetch_source(repo, commit, roots)
                proof = export_sources(clone, target, rows, roots)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                if not self.allow_excerpt_fallback:
                    raise
                shutil.rmtree(target, ignore_errors=True)
                for case, side in resolved:
                    _materialize_side(target, case, side=side)
                return {"mode": "excerpt-fallback", "reason": str(exc), "repo": repo, "commit": commit}
            finally:
                # Only the exported copy is used by executors. Drop the clone even
                # on a partial fetch, timeout, failed export or excerpt fallback.
                if not self.keep_sources:
                    clone = self.source_path(repo, commit, roots)
                    if clone.exists():
                        shutil.rmtree(clone)
            verify_functions(target, rows)
            return {**proof, "mode": "source", "repo": repo, "commit": commit}
        if all(r["source"] == "dev-php" for r in rows):
            # Export the exact requested commit from the local recipe checkout.
            for recipe in (ROOT / "benchmarks/repos").glob("*.toml"):
                data = tomllib.loads(recipe.read_text())
                if repo_name(str(data.get("url", ""))) == repo_name(pin["repo"]):
                    checkout = self.cache / "repos" / data["name"] / pin["pin"][:12]
                    return self.export_local(checkout, pin, target)
        for clone, _ in self.repos[repo_name(pin["repo"])]:
            check = subprocess.run(["git", "-C", str(clone), "cat-file", "-e", pin["pin"] + "^{commit}"], capture_output=True)
            if check.returncode == 0:
                return self.export_local(clone, pin, target)
        raise ValueError(f"no local clone contains {pin['repo']}@{pin['pin']}")


def is_catalog_excerpt(data):
    # Older Python exports have this header but no upstream_start field.
    return re.match(r"\s*(?://|#)\s*Provenance:", data) is not None


def parseable_excerpt(path, data):
    """Dedent the code independently of its unindented provenance comments."""
    language = detect_language(path)
    lines = data.splitlines(keepends=True)
    start = 0
    while start < len(lines) and (not lines[start].strip() or lines[start].lstrip().startswith(("#", "//"))):
        start += 1
    header = "".join(lines[:start])
    if language == "python":
        header = re.sub(r"(?m)^(\s*)//", r"\1#", header)
    data = header + textwrap.dedent("".join(lines[start:]))
    if not "".join(lines[start:]).strip():
        raise ValueError(f"excerpt does not parse: empty code ({path.name})")
    if language == "python":
        try:
            ast.parse(data, filename=str(path))
        except SyntaxError as exc:
            raise ValueError(f"excerpt does not parse: {exc}") from exc
    else:
        from openultrasast.semantic.cst import parse_with_cst

        parsed = parse_with_cst(str(path), data, language)
        if parsed is None:
            raise ValueError(f"excerpt does not parse: no cheap parser for {language} ({path.name})")
        if not parsed.parse_ok:
            raise ValueError(f"excerpt does not parse: {language} {parsed.reason} ({path.name})")
    return data


def verify_catalog_file(path):
    """Admit complete source only; syntactically valid provenance excerpts still fail."""
    data = path.read_text()
    if is_catalog_excerpt(data):
        raise ValueError(f"catalog side is an upstream excerpt without distinct commits: {path.name}")
    language = detect_language(path)
    if not data.strip():
        raise ValueError(f"catalog side is empty: {path.name}")
    if language == "python":
        try:
            ast.parse(data, filename=str(path))
        except SyntaxError as exc:
            raise ValueError(f"catalog side is not complete Python source: {path.name}: {exc.msg}") from exc
    else:
        from openultrasast.semantic.extra import grammar_for

        grammar = grammar_for(language)
        if grammar is None:
            raise ValueError(f"cannot verify complete catalog source for {language}: {path.name}")
        from tree_sitter import Parser

        if Parser(grammar).parse(data.encode()).root_node.has_error:
            raise ValueError(f"catalog side is not complete {language} source: {path.name}")


def source_root(file, language):
    parts = Path(file).parts
    if language == "java":
        for i in range(len(parts) - 2):
            if parts[i : i + 3] == ("src", "main", "java"):
                return "/".join(parts[: i + 3])
    # Monorepo and source-layout containers are not themselves a package.
    if len(parts) > 2 and parts[0] in {"packages", "apps", "src", "web"}:
        return "/".join(parts[:2])
    return parts[0] if len(parts) > 1 else "."


def local_imports(source, rows):
    """Cheap one-level Python imports from labelled files, without importing code."""
    found = set()
    for row in rows:
        if row["language"] != "python":
            continue
        file = safe_path(source, row["file"])
        try:
            tree = ast.parse(file.read_bytes())
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules, bases = [alias.name for alias in node.names], [source, source / "src"]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
                modules += [".".join(filter(None, (node.module, alias.name))) for alias in node.names if alias.name != "*"]
                bases = [file.parents[node.level - 1]] if node.level and node.level <= len(file.parents) else [source, source / "src"]
            else:
                continue
            for base in bases:
                for module in modules:
                    path = base.joinpath(*module.split("."))
                    for candidate in (path.with_suffix(".py"), path / "__init__.py"):
                        if candidate.is_relative_to(source) and candidate.is_file() and not candidate.is_symlink():
                            rel = candidate.relative_to(source).as_posix()
                            if not any(part in EXCLUDED_DIRS for part in Path(rel).parts):
                                found.add(rel)
    return found


def export_sources(source, target, rows, roots=(".",), cap=EXPORT_CAP):
    """Copy labels intact, narrowing oversized roots before bounding context bytes."""
    labelled = {r["file"] for r in rows}
    languages = {r["language"] for r in rows}
    files = set()
    protected = {parent.as_posix() for rel in labelled for parent in Path(rel).parents}
    for directory, dirs, names in os.walk(source):
        dirs[:] = sorted(
            d
            for d in dirs
            if d != ".git"
            and not (Path(directory) / d).is_symlink()
            and (d not in EXCLUDED_DIRS or (Path(directory) / d).relative_to(source).as_posix() in protected)
        )
        for name in names:
            file = Path(directory) / name
            rel = file.relative_to(source).as_posix()
            excluded = any(part in EXCLUDED_DIRS for part in Path(rel).parts[:-1])
            if not file.is_symlink() and (
                rel in labelled
                or (
                    not excluded
                    and detect_language(file) in languages
                    and any(root == "." or rel == root or rel.startswith(root + "/") for root in roots)
                )
            ):
                files.add(rel)
    missing = labelled - files
    if missing:
        raise ValueError(f"labelled files missing or excluded from export: {sorted(missing)}")
    imports = local_imports(source, rows)
    files.update(imports)
    sizes = {rel: safe_path(source, rel).stat().st_size for rel in files}
    original_roots = sorted(roots)
    roots = original_roots
    # Avoid lexicographically truncating a whole large package such as vllm.
    if sum(sizes.values()) > cap:
        roots = sorted({str(Path(rel).parent) for rel in labelled})
        files = {
            rel for rel in files if rel in labelled or rel in imports or any(root == "." or rel.startswith(root + "/") for root in roots)
        }
    proof = {
        "bytes": 0,
        "files": 0,
        "cap_bytes": cap,
        "cap_hit": False,
        "excludes": sorted(EXCLUDED_DIRS),
        "roots": roots,
        "requested_roots": original_roots,
        "scope_narrowed": roots != original_roots,
        "import_files": sorted(imports),
    }
    for rel in sorted(files, key=lambda rel: (rel not in labelled, rel)):
        file = safe_path(source, rel)
        size = sizes[rel]
        # The cap bounds context only. No labelled source is ever cut or omitted.
        if proof["bytes"] + size > cap:
            proof["cap_hit"] = True
            if rel not in labelled:
                continue
        dest = safe_path(target, rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(file.read_bytes())
        proof["bytes"] += size
        proof["files"] += 1
    return proof


def verify_functions(root, rows):
    for row in rows:
        data = safe_path(root, row["file"]).read_text(errors="replace")
        if not re.search(r"(?<![\w$])" + re.escape(row["function"]) + r"(?![\w$])", data):
            raise ValueError(f"labelled function not found in fetched source: {row['file']}::{row['function']}")


def freeze_source(target):
    target.mkdir(parents=True)
    archive = target.parent / "source.tar"
    with archive.open("wb") as stream:
        subprocess.run(["git", "-C", str(ROOT), "archive", "HEAD", "src"], stdout=stream, check=True)
    subprocess.run(["tar", "-xf", str(archive), "-C", str(target)], check=True)
    archive.unlink()
    overlay = {}
    for name in SNAPSHOT_FILES:
        data = (ROOT / name).read_bytes()
        dest = target / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        overlay[name] = hashlib.sha256(data).hexdigest()
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    return {"head": head, "overlay_sha256": overlay}


def docker_command(source, checkout, out, name, image, deadline, question_deadline):
    return [
        "docker",
        "run",
        "--rm",
        "--init",
        "--name",
        name,
        "--network",
        "none",
        "--memory",
        "3g",
        "--pull",
        "never",
        "--entrypoint",
        "python",
        "-e",
        "PYTHONPATH=/frozen/src",
        "-v",
        f"{source}:/frozen:ro",
        "-v",
        f"{checkout}:/case:ro",
        "-v",
        f"{out}:/out",
        image,
        "/frozen/benchmarks/learn/engine_trace_worker.py",
        "--worker",
        "/out/pin.json",
        "--deadline",
        str(deadline),
        "--heap-profile",
        "vm",
        "--question-deadline",
        str(question_deadline),
    ]


def prepare_questions(pin, root, question_deadline):
    """Prepare metadata on the host, before entering the dependency-minimal image."""
    active = [u for u in pin["units"] if u["supported"]]
    from openultrasast.learn.features import entry_names
    from openultrasast.mapping import php_hook_callbacks
    from openultrasast.plane.harvest import declares
    from openultrasast.preprocess import preprocess_repository

    _, targets = preprocess_repository(root)
    entries, _ = entry_names(root, {u["file"] for u in active})
    hooks = ";".join(f"{h}:{f}" for h, functions in php_hook_callbacks(root, targets).items() for f in functions)
    requests = {}
    for u in active:
        specs = taint_specs(language="javascript" if u["language"] == "typescript" else u["language"])
        if not declares(safe_path(root, u["file"]).read_text(errors="replace").splitlines(), u["file"], u["function"]):
            raise ValueError(f"labelled function not declared: {u['file']}::{u['function']}")
        excerpt = u.get("evidence_scope") == "in-function-only" or pin.get("materialization", {}).get("mode") == "excerpt-fallback"
        params = request_params(
            specs[u["family"]],
            file=u["file"],
            function=u["function"],
            trace=True,
            parameter_sources=excerpt or u["function"] in entries,
            call_depth=0 if excerpt else 3,
            hook_callbacks=hooks,
        )
        params["questionDeadline"] = str(question_deadline)
        requests[u["unit"]] = params
    return requests


def run_pin(pin, source, provenance, inputs, out, args):
    executor = getattr(args, "executor", "docker")
    node = None
    with tempfile.TemporaryDirectory(prefix="trace-pin-", dir=out) as scratch:
        scratch = Path(scratch)
        checkout, output = scratch / "case", scratch / "output"
        output.mkdir()
        try:
            with getattr(args, "input_lock", threading.Lock()):
                pin = {**pin, "materialization": inputs.materialize(pin, checkout)}
            write_json(output / "pin.json", {**pin, "questions": prepare_questions(pin, checkout, args.question_deadline)})
            name = "ousast-trace-" + pin_name(pin)[:16]
            started = time.monotonic()
            if executor in {"k8s", "k8s-jobs"}:
                done, node = args.kubernetes.execute(source, checkout, output, json.loads((output / "pin.json").read_text()))
                status, reason = "failed", done.stderr
                if done.returncode:
                    (output / "container.log").write_text(reason)
            elif executor == "ax":
                done, node = args.ax_dispatcher.execute(checkout, output, json.loads((output / "pin.json").read_text()), pin_name(pin)[:-5])
                status = "timeout" if done is None else "failed"
                reason = f"AX deadline {args.deadline}s" if done is None else done.stderr
            elif executor == "queue":
                done, node = args.dispatcher.execute(checkout, output, json.loads((output / "pin.json").read_text()), pin_name(pin)[:-5])
                status, reason = "timeout", f"queue wait deadline {args.queue_timeout}s"
            else:
                command = docker_command(source, checkout, output, name, args.image, args.deadline, args.question_deadline)
                started = time.monotonic()
                done = None
                try:
                    done = subprocess.run(command, capture_output=True, text=True, timeout=args.deadline)
                    status, reason = "failed", f"container exit {done.returncode}: {done.stderr[-1000:]}"
                    (output / "container.log").write_text(done.stdout + "\n" + done.stderr)
                except subprocess.TimeoutExpired:
                    done = None
                    status, reason = "timeout", f"container deadline {args.deadline}s"
                finally:
                    # Never start the next pin unless this container is known to be gone.
                    try:
                        removed = subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
                    except subprocess.SubprocessError as exc:
                        raise RuntimeError(f"cannot confirm container {name} stopped; refusing another launch") from exc
                    if done is None and removed.returncode != 0:
                        raise RuntimeError(f"cannot remove timed-out container {name}; refusing another launch")
            result_path = output / "result.json"
            if not result_path.exists() and reason != "AX sandbox failed twice":
                reason = f"container produced no result: {reason}"
            record = json.loads(result_path.read_text()) if result_path.exists() else {**pin, "units": []}
            if not record.get("done"):
                previous = {u["unit"]: u for u in record["units"]}
                record["units"] = []
                for unit in pin["units"]:
                    row = previous.get(unit["unit"], unit_record(unit, status))
                    if row["status"] not in {"path", "asked-nothing"}:
                        row.update(
                            status=status if unit["supported"] else "unsupported", reason=reason if unit["supported"] else unit["reason"]
                        )
                    record["units"].append(row)
            if executor != "queue":
                record["container_exit"] = done.returncode if done else None
            else:
                record.setdefault("container_exit", None)
            if done is not None and done.returncode != 0:
                for row in record["units"]:
                    if row["supported"]:
                        row.update(status="failed", reason=reason)
            record.update(
                done=True,
                seconds=time.monotonic() - started,
                analyzer={"image": args.image, "code": "baked-in-image"} if executor == "ax" else provenance,
                image=record.get("image", args.image) if executor == "queue" else args.image,
            )
            if (output / "container.log").exists():
                shutil.copyfile(output / "container.log", out / pin_name(pin).replace(".json", ".log"))
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            record = {
                **pin,
                "done": True,
                "analyzer": provenance,
                "units": [unit_record(u, "failed" if u["supported"] else "unsupported", str(exc)) for u in pin["units"]],
            }
        if executor == "ax":
            record.update(executor="ax", worker=node, worker_ip=node, image=args.image)
            record["analyzer"] = {"image": args.image, "code": "baked-in-image"}
            if (output / "ax_attempts.json").exists():
                record["ax_attempts"] = json.loads((output / "ax_attempts.json").read_text())
        if getattr(args, "fallback", None):
            record.update(executor="docker", fallback=args.fallback, ax_attempt=args.ax_attempt, fallback_pending=False)
            if "ax_attempts" in args.ax_attempt:
                record["ax_attempts"] = args.ax_attempt["ax_attempts"]
        if executor in {"k8s", "k8s-jobs"}:
            record.update(executor="k8s", node=node, image=args.image)
        if executor == "queue":
            record.update(executor="queue", worker=record.get("worker", node), pod=record.get("pod"))
        save_pin(out / pin_name(pin), record)
        print(
            json.dumps({"repo": pin["repo"], "pin": pin["pin"], "statuses": dict(Counter(u["status"] for u in record["units"]))}),
            flush=True,
        )
        return any(u["status"] in {"failed", "timeout"} for u in record["units"])


def save_pin(path, record):
    if path.exists():
        old = json.loads(path.read_text())
        selected = {u["unit"] for u in record["units"]}
        record["units"].extend(u for u in old.get("units", []) if u["unit"] not in selected)
    write_json(path, record)


def summary(out):
    if not out.is_dir():
        raise ValueError(f"results root does not exist: {out}")
    family, source = defaultdict(Counter), defaultdict(Counter)
    pairs = defaultdict(dict)
    units = {}
    result_files = 0
    for path in sorted(out.glob("*.json")):
        record = json.loads(path.read_text())
        if not record.get("done"):
            continue
        result_files += 1
        for unit in record["units"]:
            if unit["unit"] in units:
                raise ValueError(f"duplicate result for {unit['unit']}")
            units[unit["unit"]] = unit
            family[unit["family"]][unit["status"]] += 1
            source[unit["source"]][unit["status"]] += 1
            if unit["pair"]:
                pairs[unit["family"], unit["pair"]][unit["label"]] = unit["status"]
    asymmetry = Counter()
    completed = Counter()
    for sides in pairs.values():
        if set(sides) != {0, 1}:
            asymmetry["incomplete-pair"] += 1
            continue
        key = {(True, False): "vulnerable-only", (False, True): "fixed-only", (True, True): "both", (False, False): "neither"}[
            sides[1] == "path", sides[0] == "path"
        ]
        asymmetry[key] += 1
        if all(s in {"path", "asked-nothing"} for s in sides.values()):
            completed[key] += 1
    return {
        "result_files_read": result_files,
        "units": len(units),
        "by_family": {k: {s: v[s] for s in STATUSES} for k, v in sorted(family.items())},
        "by_source": {k: {s: v[s] for s in STATUSES} for k, v in sorted(source.items())},
        "pair_asymmetry": dict(asymmetry),
        "pair_asymmetry_both_answered": dict(completed),
    }


def run_plan(plan, source, provenance, inputs, args):
    """One task per fixed executor lane; progress is written only by the scheduler."""
    lanes = ["k8s"] * (args.parallel - 1) + ["docker"] if args.executor == "mixed" else [args.executor] * args.parallel
    if args.executor in {"ax", "mixed-ax"}:
        lanes = ["ax"] * args.parallel + ["docker"]
    args.input_lock = threading.Lock()
    progress = {
        "pins_done": 0,
        "pins_total": len(plan),
        "last_pin": None,
        "statuses": {},
        "lanes": dict(Counter(lanes)),
        "pins_in_flight": 0,
        "active_lanes": {},
    }
    counts = Counter()
    pending = list(plan)
    fallbacks = []
    if args.executor in {"ax", "mixed-ax"}:
        pending.clear()
        for pin in plan:
            path = args.out / pin_name(pin)
            old = json.loads(path.read_text()) if path.exists() else {}
            recorded = {u["unit"]: u.get("input_digest") for u in old.get("units", [])}
            if old.get("fallback_pending") and all(recorded.get(u["unit"]) == u.get("input_digest") for u in pin["units"]):
                fallbacks.append((pin, old))
            else:
                pending.append(pin)

    def execute(pin, lane, attempt=None):
        if not any(u["supported"] for u in pin["units"]):
            save_pin(
                args.out / pin_name(pin), {**pin, "done": True, "units": [unit_record(u, "unsupported", u["reason"]) for u in pin["units"]]}
            )
            return False
        options = copy.copy(args)
        options.executor = lane
        if attempt is not None:
            options.fallback = attempt.get("fallback", "vm-oom")
            options.ax_attempt = attempt
        if lane == "docker":
            options.image = getattr(args, "docker_image", args.image)
        return run_pin(pin, source, provenance, inputs, args.out, options)

    def complete(pin, lane, failed, progress):
        result = json.loads((args.out / pin_name(pin)).read_text())
        selected = {u["unit"] for u in pin["units"]}
        reasons = [u.get("reason", "") for u in result["units"] if u["unit"] in selected]
        sandbox_failed = args.executor == "mixed-ax" and result.get("container_exit") == 1 and "AX sandbox failed twice" in reasons
        if lane == "ax" and (sandbox_failed or any("JVM out of memory" in reason for reason in reasons)):
            result.update(fallback="vm-sandbox" if sandbox_failed else "vm-oom", fallback_pending=True)
            write_json(args.out / pin_name(pin), result)
            return False, result
        counts.update(u["status"] for u in result["units"] if u["unit"] in selected)
        progress.update(last_pin={"repo": pin["repo"], "pin": pin["pin"]}, statuses=dict(counts))
        return failed, None

    return schedule(pending, lanes, args.out, execute, complete, fallbacks=fallbacks, overflow=args.executor != "ax", progress=progress)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--units", type=Path, default=ROOT / "plane/experiments/exp-005-graph-slice.units.jsonl")
    parser.add_argument("--examples", type=Path, help="frozen example JSONL instead of the local memory store")
    parser.add_argument("--memory", type=Path, default=Path.home() / "ousast-results/plane/memory")
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/openultrasast")
    parser.add_argument("--keep-sources", action="store_true", help="retain fetched sources after export (still subject to cache eviction)")
    parser.add_argument("--source-cache-mb", type=int, default=500, help="maximum retained source MB before each fetch (default: 500)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--image", help="default: openultrasast:dev for Docker; public 2.0.1 image for k8s/mixed")
    parser.add_argument("--executor", choices=("docker", "k8s", "k8s-jobs", "mixed", "queue", "ax", "mixed-ax"), default="docker")
    parser.add_argument("--queue-status", action="store_true")
    parser.add_argument("--queue-timeout", type=int, default=3600, help="total queue wait including execution, seconds")
    parser.add_argument("--parallel", type=int, help="AX lanes (default 2, maximum 2); otherwise total lanes (default 1)")
    parser.add_argument("--ax-bin", default="ax")
    parser.add_argument("--kubeconfig", type=Path, help="AX kubeconfig; otherwise inherited KUBECONFIG/default CLI config")
    parser.add_argument("--atespace", default="default")
    parser.add_argument("--docker-image", default="openultrasast:dev", help="local VM image for AX OOM fallback/mixed overflow")
    parser.add_argument("--kube-context")
    parser.add_argument("--kube-namespace", default="ousast-engine")
    parser.add_argument("--keep-jobs", action="store_true", help="retain Jobs, Secrets and staging objects for debugging")
    parser.add_argument("--k8s-check", action="store_true")
    parser.add_argument("--deadline", type=int, default=900)
    parser.add_argument("--question-deadline", type=int, default=120)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--only-family")
    parser.add_argument("--only-source", default="", help="comma-separated source catalog IDs")
    parser.add_argument("--rerun-status", default="failed,timeout", help="comma-separated statuses to re-run (including timeout)")
    parser.add_argument(
        "--allow-excerpt-fallback", action="store_true", help="allow fragments only if fetching/exporting resolved source fails"
    )
    parser.add_argument("--include-typescript", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    if args.source_cache_mb < 0:
        parser.error("--source-cache-mb must be nonnegative")
    if args.parallel is None:
        args.parallel = 2 if args.executor in {"ax", "mixed-ax"} else 1
    if args.executor in {"ax", "mixed-ax"}:
        if args.parallel > 2:
            parser.error("AX allows at most 2 engine tasks in flight")
        if not args.image or not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", args.image):
            parser.error("AX requires --image by sha256 digest")
    if args.queue_status:
        print(json.dumps(Dispatcher(args).status(), indent=2))
        return 0
    if args.queue_timeout <= 0:
        parser.error("--queue-timeout must be positive")
    if args.executor == "queue" and (not args.image or "@sha256:" not in args.image):
        parser.error("queue requires --image with the deployed image digest")
    if args.executor == "queue" and args.deadline > 900:
        parser.error("queue deadline must be <= Deployment termination grace (900s)")
    if min(args.deadline, args.question_deadline) <= 0 or args.limit < 0:
        parser.error("deadlines must be positive; limit must be nonnegative")
    if args.parallel < 1 or (args.executor == "mixed" and args.parallel < 2):
        parser.error("--parallel must be positive; mixed needs at least 2 total lanes")
    if (args.executor in {"k8s", "k8s-jobs", "mixed"} or args.k8s_check) and not args.kube_context:
        parser.error("--kube-context is required for Kubernetes")
    args.image = args.image or (IMAGE if args.executor != "docker" or args.k8s_check else "openultrasast:dev")
    if args.k8s_check:
        return Kubernetes(args).check()
    rerun_status = set(filter(None, args.rerun_status.split(",")))
    if rerun_status - set(STATUSES):
        parser.error("unknown --rerun-status value")
    if args.summary:
        print(json.dumps(summary(args.out), indent=2))
        return 0
    # Even inherited opt-ins must not make catalog resolution fetch.
    os.environ["GIT_NO_LAZY_FETCH"] = "1"
    os.environ.pop("OPENULTRASAST_PAIRS_NETWORK", None)
    os.environ.pop("OPENULTRASAST_REPOS_NETWORK", None)
    examples = read_jsonl(args.examples) if args.examples else [r.row for r in FileStore(args.memory).rows(kind="example")]
    try:
        units = join_units(read_jsonl(args.units), examples, args.include_typescript)
    except ValueError as exc:
        parser.error(str(exc))
    inputs = Inputs(ROOT, args.cache, args.allow_excerpt_fallback, keep_sources=args.keep_sources, source_cache_mb=args.source_cache_mb)
    # Resolve pair source names for leak-audit coverage before calculating the resume key.
    for unit in units:
        if unit.get("excerpt") or unit["source"].startswith("advisory-fixes"):
            try:
                case, _ = inputs.pair_for(unit)
                catalog_source, _ = inputs.catalog_for(case)
                unit["source"] = catalog_source if catalog_source.startswith("advisory-fixes") else case.slice
                unit["excerpt"] = True
            except ValueError as exc:
                unit["mapping_error"] = str(exc)
    plan = make_plan(
        units,
        args.out,
        args.only_family,
        args.limit,
        include_typescript=args.include_typescript,
        only_source=set(filter(None, args.only_source.split(","))),
        rerun_status=rerun_status,
        allow_excerpt_fallback=args.allow_excerpt_fallback,
    )
    # Planning is read-only, including unsupported pins. All persistence stays below this return.
    if args.dry_run:
        print(
            json.dumps(
                {
                    "pins": len(plan),
                    "runnable_pins": sum(any(u["supported"] for u in p["units"]) for p in plan),
                    "units": sum(len(p["units"]) for p in plan),
                    "estimated_seconds": sum(p["estimated_seconds"] for p in plan),
                    "estimate_basis": "inventory medians: excerpt 31/47s, repository 182/498s; not a deadline guarantee",
                    "plan": plan,
                },
                indent=2,
            )
        )
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    lock = (args.out / ".lock").open("w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("another trace runner holds this results root")
    failures = False
    if args.executor not in {"ax", "mixed-ax"}:
        args.docker_image = args.image
    if args.executor in {"docker", "mixed"} and any(u["supported"] for pin in plan for u in pin["units"]):
        image = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", args.image], capture_output=True, text=True, check=True
        )
        args.docker_image = image.stdout.strip()
        if not args.docker_image:
            raise ValueError("Docker returned no local image identity")
    if args.executor in {"k8s", "k8s-jobs", "mixed"} and any(u["supported"] for pin in plan for u in pin["units"]):
        args.kubernetes = Kubernetes(args)
        args.kubernetes.namespace()
    if args.executor == "queue":
        args.dispatcher = Dispatcher(args)
    if args.executor in {"ax", "mixed-ax"}:
        from engine_trace_ax import AX

        args.ax_dispatcher = AX(args)
    with tempfile.TemporaryDirectory(prefix="trace-source-", dir=args.out) as scratch:
        source = Path(scratch) / "frozen"
        provenance = {"image": args.image, "executor": "queue"} if args.executor == "queue" else freeze_source(source)
        failures = run_plan(plan, source, provenance, inputs, args)
    return 2 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
