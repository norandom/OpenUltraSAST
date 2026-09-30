"""Equality proof for the HarnessX removal (spec harnessx-removal, design section 3, Requirement 3).

``record`` exports a frozen source tree, runs the deterministic commands with no model reachable and the
``harnessx`` extra absent, and stores their normalized outputs. ``compare`` diffs two such records and exits
non-zero on the first difference outside the exclusion list, naming the file and key.

Usage:
    python benchmarks/harnessx_removal_equality.py record <out-dir> [--tree-ish HEAD] [--workdir DIR]
    python benchmarks/harnessx_removal_equality.py compare <baseline-dir> <candidate-dir> \\
        [--suite-map map.json] [--record comparison.json]

The instrument checks come first and fail loudly: ``harnessx`` must not be importable, ``tree_sitter`` must be,
every child must import ``openultrasast`` from the export, every input manifest must be non-empty, every
command must exit 0, and every command must produce non-zero counts (pairs, TPs, expected findings, suite tests).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]

# Design section 3 "Comparison": timestamps, durations and run identifiers are excluded; nothing else is.
EXCLUDED_KEYS = frozenset({"runtime_seconds", "scan_id", "timestamp", "started", "finished", "created_at", "generated_at"})
EXCLUDED_SUFFIXES = ("_seconds", "_ms")
RUN_ID = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{8}")
EXCLUSIONS = [
    f"JSON keys: {', '.join(sorted(EXCLUDED_KEYS))}",
    f"JSON keys ending in: {', '.join(EXCLUDED_SUFFIXES)}",
    "run directory names / run ids (<timestamp>-<8 hex>, benchmark.py create_benchmark_run, run.py create_scan_run) -> <RUN_ID>",
    "trace/events.jsonl as a whole (timings); never copied",
    "the export's absolute root path -> <ROOT>; the children's TMPDIR -> <TMP>",
    "suite: only the outcome per test id is kept (junit durations dropped)",
    "env.json is a provenance record (commit, freeze hash, instrument checks), not compared",
]

INPUTS = (
    "benchmarks/pairs/catalog.toml",
    "benchmarks/manifests/python-vulnerable.toml",
    "benchmarks/manifests/java-spring-boot-vulnerable.toml",
)
SCAN_KEEP = ("findings.json", "verification.json", "fusion.json", "report.sarif", "harness.json", "manifest.json")
BENCH_KEEP = ("benchmark_result.json", "calibration_records.json", "external_baseline_deltas.json")


class InstrumentError(SystemExit):
    def __init__(self, message: str) -> None:
        super().__init__(f"instrument check failed: {message}")


def normalize(value: Any, root: str, tmp: str) -> Any:
    """Drop excluded keys recursively and scrub the export root, TMPDIR and run ids from strings."""
    if isinstance(value, dict):
        return {k: normalize(v, root, tmp) for k, v in value.items() if not _excluded(k)}
    if isinstance(value, list):
        return [normalize(v, root, tmp) for v in value]
    if isinstance(value, str):
        return scrub(value, root, tmp)
    return value


def _excluded(key: str) -> bool:
    return key in EXCLUDED_KEYS or key.endswith(EXCLUDED_SUFFIXES)


def scrub(text: str, root: str, tmp: str) -> str:
    text = text.replace(tmp, "<TMP>").replace(root, "<ROOT>")
    return RUN_ID.sub("<RUN_ID>", text)


def dump(value: Any) -> str:
    return json.dumps(value, indent=1, sort_keys=True) + "\n"


def _child_env(root: Path, tmp: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.endswith("_API_KEY") and k not in {"PYTHONPATH", "VIRTUAL_ENV"}}
    env.update(OPENULTRASAST_SKIP_DOTENV="1", PYTHONPATH=str(root / "src"), TMPDIR=str(tmp), PYTHONHASHSEED="0")
    return env


def _run(cmd: list[str], root: Path, env: dict[str, str], label: str) -> str:
    proc = subprocess.run(cmd, cwd=root, env=env, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        tail = (proc.stdout + proc.stderr)[-2000:]
        raise InstrumentError(f"{label} exited {proc.returncode}: {' '.join(cmd)}\n{tail}")
    return proc.stdout


def _field(stdout: str, name: str) -> str:
    for line in stdout.splitlines():
        if line.startswith(f"{name}="):
            return line.partition("=")[2]
    raise InstrumentError(f"no {name}= line in output")


def _freeze_hash() -> str:
    uv = shutil.which("uv")
    if uv is None:
        raise InstrumentError("uv not found; cannot hash the environment")
    out = subprocess.run([uv, "pip", "freeze", "--python", sys.executable], capture_output=True, text=True, check=True).stdout
    return hashlib.sha256(out.encode()).hexdigest()


def _suite(xml_path: Path) -> dict[str, str]:
    outcomes: dict[str, str] = {}
    for case in ET.parse(xml_path).getroot().iter("testcase"):
        test_id = f"{case.get('classname')}::{case.get('name')}"
        kinds = {child.tag for child in case}
        outcome = next((k for k in ("error", "failure", "skipped") if k in kinds), "passed")
        outcomes[test_id] = outcome
    return dict(sorted(outcomes.items()))


def record(out: Path, tree_ish: str, workdir: Path) -> None:
    if importlib.util.find_spec("harnessx") is not None:
        raise InstrumentError("harnessx is importable; re-sync the venv without the extra")
    if importlib.util.find_spec("tree_sitter") is None:
        raise InstrumentError("tree_sitter is not importable; the semantic extra is missing")
    workdir.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="export-", dir=workdir)).resolve()
    tmp = Path(tempfile.mkdtemp(prefix="tmp-", dir=workdir)).resolve()
    archive = subprocess.run(["git", "-C", str(REPO), "archive", tree_ish], capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", str(root)], input=archive, check=True)
    env = _child_env(root, tmp)
    rs, ts = str(root), str(tmp)
    py = sys.executable
    out.mkdir(parents=True, exist_ok=True)
    checks: dict[str, Any] = {}

    module = _run([py, "-c", "import openultrasast; print(openultrasast.__file__)"], root, env, "import probe").strip()
    if not module.startswith(rs):
        raise InstrumentError(f"openultrasast imported from {module}, not the export {rs}")
    checks["openultrasast_module"] = scrub(module, rs, ts)
    inputs = {name: (root / name).stat().st_size for name in INPUTS}
    if not all(inputs.values()):
        raise InstrumentError(f"empty input manifest: {inputs}")
    print(f"export={root} module={module} inputs={inputs}", flush=True)

    # 1. Full suite, outcome per test id.
    junit = tmp / "suite.xml"
    _run([py, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={junit}"], root, env, "pytest")
    suite = _suite(junit)
    counts = {k: sum(1 for v in suite.values() if v == k) for k in ("passed", "skipped", "failure", "error")}
    if counts["passed"] == 0:
        raise InstrumentError("suite recorded no passing tests")
    (out / "suite.json").write_text(dump(suite))
    checks["suite"] = counts
    print(f"suite={counts}", flush=True)

    # 2. Pair replay (offline, vendored pairs only).
    pairs = normalize(json.loads(_run([py, "-m", "openultrasast.cli", "pairs", "--json"], root, env, "pairs")), rs, ts)
    checks["pairs"] = _pair_counts(pairs)
    (out / "pairs.json").write_text(dump(pairs))
    print(f"pairs={checks['pairs']}", flush=True)

    # 3. Quick benchmark replay.
    empty = tmp / "empty.toml"
    empty.write_text("")
    cmd = [
        py,
        "-m",
        "openultrasast.cli",
        "benchmark",
        "benchmarks/manifests/python-vulnerable.toml",
        "--mode",
        "quick",
        "--config",
        str(empty),
    ]
    stdout = _run(cmd, root, env, "benchmark")
    expected = int(_field(stdout, "benchmark_expected"))
    if expected <= 0:
        raise InstrumentError("benchmark expected no findings")
    checks["benchmark"] = {k: int(_field(stdout, f"benchmark_{k}")) for k in ("expected", "matched", "missed")}
    checks["benchmark"]["findings"] = int(_field(stdout, "findings"))
    _keep(Path(_field(stdout, "benchmark_run_dir")), BENCH_KEEP, out / "benchmark", rs, ts, checks, "benchmark_files")
    (out / "benchmark" / "stdout.txt").write_text(scrub(stdout, rs, ts))
    print(f"benchmark={checks['benchmark']}", flush=True)

    # 4. One standard-mode scan (verify + fusion, no model configured).
    cmd = [py, "-m", "openultrasast.cli", "scan", "benchmarks/fixtures/python-vulnerable", "--mode", "standard", "--config", str(empty)]
    stdout = _run(cmd, root, env, "scan")
    checks["scan"] = {"findings": int(_field(stdout, "findings")), "file_targets": int(_field(stdout, "file_targets"))}
    if checks["scan"]["file_targets"] <= 0:
        raise InstrumentError("standard scan saw no file targets")
    _keep(Path(_field(stdout, "run_dir")), SCAN_KEEP, out / "scan", rs, ts, checks, "scan_files")
    (out / "scan" / "stdout.txt").write_text(scrub(stdout, rs, ts))
    print(f"scan={checks['scan']}", flush=True)

    # 5. improve --dry-run; the shim keeps the dry-run journal the CLI writes to a throwaway directory.
    shim_out = tmp / "improve"
    cmd = [py, str(Path(__file__).resolve()), "_improve", str(shim_out), "benchmarks/manifests/java-spring-boot-vulnerable.toml"]
    stdout = _run(cmd, root, env, "improve")
    (out / "improve").mkdir(exist_ok=True)
    (out / "improve" / "stdout.txt").write_text(scrub(stdout, rs, ts))
    # A round with no proposals writes no journal (evolve.py returns before append_round); its absence is
    # recorded and compared like any file, so a journal appearing after the removal is a difference.
    rounds = [line for line in stdout.splitlines() if line.startswith("round ")]
    if not rounds or "rounds=" not in stdout:
        raise InstrumentError("improve --dry-run printed no round")
    journal = shim_out / "improve_journal.json"
    checks["improve"] = {"rounds": len(rounds), "journal_bytes": journal.stat().st_size if journal.is_file() else None}
    if journal.is_file():
        journal_data = normalize(json.loads(journal.read_text()), rs, ts)
        (out / "improve" / "improve_journal.json").write_text(dump(journal_data))
    print(f"improve={checks['improve']}", flush=True)

    head = subprocess.run(["git", "-C", str(REPO), "rev-parse", tree_ish], capture_output=True, text=True, check=True).stdout.strip()
    env_record = {
        "tree_ish": head,
        "freeze_sha256": _freeze_hash(),
        "harnessx_importable": False,
        "tree_sitter": True,
        "python": sys.version.split()[0],
        "child_env": {"OPENULTRASAST_SKIP_DOTENV": "1", "PYTHONHASHSEED": "0", "api_keys": "every *_API_KEY unset", "config": "empty"},
        "inputs": inputs,
        "instrument_checks": checks,
        "exclusions": EXCLUSIONS,
    }
    (out / "env.json").write_text(dump(env_record))
    (out / "README").write_text("Excluded from comparison: " + "; ".join(EXCLUSIONS) + "\n")
    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"recorded {out}")


def _pair_counts(pairs: Any) -> dict[str, int]:
    overall = pairs.get("overall", {}) if isinstance(pairs, dict) else {}
    counts = {k: int(overall.get(k, 0)) for k in ("pairs", "detected_vuln", "pair_correct", "labeled_expected", "labeled_matched")}
    counts["outcomes"] = len(pairs.get("outcomes", [])) if isinstance(pairs, dict) else 0
    if counts["pairs"] <= 0 or counts["detected_vuln"] <= 0 or counts["outcomes"] <= 0:
        raise InstrumentError(f"pair replay saw {counts}")
    return counts


def _keep(run_dir: Path, names: tuple[str, ...], dest: Path, rs: str, ts: str, checks: dict[str, Any], key: str) -> None:
    if not run_dir.is_dir():
        raise InstrumentError(f"run directory missing: {run_dir}")
    dest.mkdir(parents=True, exist_ok=True)
    present = {}
    for name in names:
        source = run_dir / name
        if source.is_file():
            present[name] = source.stat().st_size
            (dest / name).write_text(dump(normalize(json.loads(source.read_text()), rs, ts)))
    checks[key] = present


def _improve_shim(out: Path, manifest: str) -> int:
    """Run ``ousast improve --dry-run --no-pair-gate`` and copy the throwaway journal out before cleanup."""
    from openultrasast import cli

    original = tempfile.TemporaryDirectory

    class Keeping(original):  # type: ignore[misc,valid-type]
        def cleanup(self) -> None:
            out.mkdir(parents=True, exist_ok=True)
            for name in ("improve_journal.json",):
                if (Path(self.name) / name).is_file():
                    shutil.copy2(Path(self.name) / name, out / name)
            super().cleanup()

        def __exit__(self, *exc: object) -> None:
            self.cleanup()

    cli.tempfile.TemporaryDirectory = Keeping  # type: ignore[misc]
    try:
        return int(cli.main(["improve", manifest, "--dry-run", "--no-pair-gate"]) or 0)
    finally:
        cli.tempfile.TemporaryDirectory = original  # type: ignore[misc]


def compare(baseline: Path, candidate: Path, suite_map: dict[str, Any]) -> list[str]:
    """Return every difference outside the exclusion list; empty means equal."""
    diffs: list[str] = []
    diffs += _compare_suite(
        json.loads((baseline / "suite.json").read_text()), json.loads((candidate / "suite.json").read_text()), suite_map
    )
    files = sorted(
        {p.relative_to(baseline).as_posix() for p in baseline.rglob("*") if p.is_file()}
        | {p.relative_to(candidate).as_posix() for p in candidate.rglob("*") if p.is_file()}
    )
    for name in files:
        if name in {"suite.json", "env.json", "README", "comparison.json", "determinism.json"}:
            continue
        a, b = baseline / name, candidate / name
        if not a.is_file() or not b.is_file():
            diffs.append(f"{name}: present only in {'candidate' if b.is_file() else 'baseline'}")
            continue
        if a.read_bytes() == b.read_bytes():
            continue
        if name.endswith((".json", ".sarif")):
            diffs.append(f"{name}: {_first_json_diff(json.loads(a.read_text()), json.loads(b.read_text()), '$')}")
        else:
            diffs.append(f"{name}: first differing line {_first_line_diff(a.read_text(), b.read_text())}")
    return diffs


def _compare_suite(a: dict[str, str], b: dict[str, str], suite_map: dict[str, Any]) -> list[str]:
    deleted = set(suite_map.get("deleted", ()))
    renamed: dict[str, str] = dict(suite_map.get("renamed", {}))
    added = set(suite_map.get("added", ())) | set(renamed.values())
    diffs = []
    for test_id, outcome in a.items():
        if test_id in deleted:
            continue
        target = renamed.get(test_id, test_id)
        if target not in b:
            diffs.append(f"suite.json: {test_id} missing from candidate")
        elif b[target] != outcome:
            diffs.append(f"suite.json: {test_id} {outcome} -> {b[target]}")
    diffs += [f"suite.json: {t} new in candidate" for t in b if t not in a and t not in added]
    return diffs


def _first_json_diff(a: Any, b: Any, path: str) -> str:
    if type(a) is not type(b):
        return f"{path}: type {type(a).__name__} -> {type(b).__name__}"
    if isinstance(a, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a or key not in b:
                return f"{path}.{key}: present only in {'candidate' if key in b else 'baseline'}"
            if a[key] != b[key]:
                return _first_json_diff(a[key], b[key], f"{path}.{key}")
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: length {len(a)} -> {len(b)}"
        for i, (x, y) in enumerate(zip(a, b, strict=True)):
            if x != y:
                return _first_json_diff(x, y, f"{path}[{i}]")
    return f"{path}: {json.dumps(a)[:120]} -> {json.dumps(b)[:120]}"


def _first_line_diff(a: str, b: str) -> str:
    la, lb = a.splitlines(), b.splitlines()
    for i, (x, y) in enumerate(zip(la, lb, strict=False), 1):
        if x != y:
            return f"{i}: {x[:120]!r} -> {y[:120]!r}"
    return f"line count {len(la)} -> {len(lb)}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record")
    rec.add_argument("out", type=Path)
    rec.add_argument("--tree-ish", default="HEAD", help="git tree-ish to export (a commit, or `git write-tree` for the index)")
    rec.add_argument("--workdir", type=Path, default=Path(tempfile.gettempdir()) / "hxr-equality")
    cmp_ = sub.add_parser("compare")
    cmp_.add_argument("baseline", type=Path)
    cmp_.add_argument("candidate", type=Path)
    cmp_.add_argument("--suite-map", type=Path, help='JSON {"deleted": [...], "renamed": {old: new}, "added": [...]}')
    cmp_.add_argument("--record", type=Path, help="write the comparison result here as JSON")
    shim = sub.add_parser("_improve")
    shim.add_argument("out", type=Path)
    shim.add_argument("manifest")
    args = parser.parse_args(argv)
    if args.command == "record":
        record(args.out.resolve(), args.tree_ish, args.workdir.resolve())
        return 0
    if args.command == "_improve":
        return _improve_shim(args.out, args.manifest)
    suite_map = json.loads(args.suite_map.read_text()) if args.suite_map else {}
    diffs = compare(args.baseline, args.candidate, suite_map)
    if args.record:
        args.record.write_text(
            dump(
                {
                    "baseline": str(args.baseline),
                    "candidate": str(args.candidate),
                    "equal": not diffs,
                    "differences": diffs,
                    "exclusions": EXCLUSIONS,
                }
            )
        )
    for line in diffs[:20]:
        print(line)
    print(f"equal={not diffs} differences={len(diffs)}")
    return 1 if diffs else 0


if __name__ == "__main__":
    raise SystemExit(main())
