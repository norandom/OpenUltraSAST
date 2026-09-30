"""Engine alerts for the languages quick mode does not cover, and for PHP beside its quick rules
(``ENGINE_ALONGSIDE_QUICK``), produced on the host (harnessx-removal Req 6.3).

The loop's ``alerts`` task runs the quick-mode scan, which has rules only for the languages its ruleset declares; a
case in any other language yields zero alerts that mean nothing (``coverage: none``). PHP has quick rules since
2026-09-30 (``ruleset/php/rules.toml``, line patterns over the engine's vocabulary), but its detection of record is
still the Joern taint engine (``ruleset/semantic/php.toml``), which runs in the ``openultrasast:dev`` image, not in
the runner sandbox. So ``ousast plane alerts-engine <Run.yaml>`` does the ``alerts`` task's work on the host for
every case whose files include a language the engine models and quick mode does not cover, or PHP:

- export the case's vulnerable and fixed pins from the case cache (``git archive``, as
  ``benchmarks/independent/evaluate.py`` does), run the quick scan on each (:func:`.tasks.alerts.scan`) and the
  engine container on each -- ``benchmarks/push/finding_dump.py`` from a FROZEN source export (never a live tree),
  ``--network none --memory 3g``, the case's family, one container at a time, a per-case deadline;
- convert the engine's findings into the ``alerts.jsonl`` row shape of the ``alerts`` task (``rule_id`` is
  ``engine:<family>``, ``source: "engine"``, ``in_fix_range`` from ``case.json``'s ranges), write both kinds of rows
  and a ``summary.json`` (``coverage`` with the engine's languages as ``engine``, the engine's files read, questions,
  completed, seconds and degradations per pin) into ``<run dir>/<case>-alerts/``;
- mark the task done with :func:`.reconciler.mark_done`, the mechanism fact reuse uses, so the Run skips it.

The instrument must have read its input: no result file, no ``read N files`` line, or ``questions == 0`` fails the
case loudly (:class:`EngineAlertsError`) and leaves the run directory untouched.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import reconciler
from .tasks.alerts import ROLES, coverage, covers, engine_languages, function_at, in_range, quick_languages, scan, uncovered
from .tasks.alerts import write_rows as write_alert_rows
from .tasks.alerts import write_summary as write_alert_summary

IMAGE = "openultrasast:dev"
MEMORY = "3g"
DEADLINE = 1800.0
GRACE = 600.0  # the container's own startup and teardown beyond the scan deadline
# Languages whose alerts of record come from the engine even though quick mode has rules for them. PHP's quick rules
# (ruleset/php, 2026-09-30) are a line layer with a low measured precision lower bound on the development corpus, so
# the engine keeps running for PHP beside them, and the coverage reports the engine for it.
ENGINE_ALONGSIDE_QUICK = frozenset({"php"})
CACHE = Path.home() / ".cache" / "openultrasast" / "independent"
DUMP = Path("benchmarks") / "push" / "finding_dump.py"
_READ = re.compile(r"^read (\d+) files, (\d+) bytes", re.MULTILINE)
_SITE = re.compile(r"^(.+?):(\d+):(.*)$")

Runner = Callable[[Sequence[str], float], subprocess.CompletedProcess[str]]


class EngineAlertsError(RuntimeError):
    """The engine did not demonstrably read its input, or a case cannot be prepared."""


def run_command(command: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), capture_output=True, text=True, timeout=timeout, check=False)


@dataclass(frozen=True)
class EngineCase:
    case_id: str
    entry: str  # the Run entry of the case's `alerts` task
    repo: str
    pins: Mapping[str, str]  # role -> commit
    family: str
    ranges: Mapping[str, Any]  # role -> {path: [[lo, hi], ...]} or None


def engine_cases(run_manifest: Path) -> tuple[str, list[EngineCase]]:
    """(Run name, every `alerts` entry of the Run as a case): pins from the task's env, family and fix ranges from the
    `case.json` of its bound inputs Workspace, the repository from its bound git Workspace."""
    run, manifests = reconciler.load_run(Path(run_manifest))
    cases: list[EngineCase] = []
    for entry in run.tasks:
        task = manifests.tasks[entry.task]
        if tuple(task.command[:1]) != ("alerts",):
            continue
        env = {e.name: e.value for e in task.env}
        bound = [manifests.workspaces[b.name] for b in task.workspaces if b.name in manifests.workspaces]
        files = {f.path: f.content for ws in bound for f in ws.files}
        repos = [g.repo for ws in bound for g in ws.git]
        if "case.json" not in files or not repos:
            raise EngineAlertsError(f"{entry.name}: no bound case.json or git Workspace")
        case = json.loads(files["case.json"])
        pins = {"vulnerable": env.get("OUSAST_VULNERABLE_PIN", ""), "fixed": env.get("OUSAST_FIXED_PIN", "")}
        if not all(pins.values()) or not case.get("family"):
            raise EngineAlertsError(f"{entry.name}: pins {pins} or family {case.get('family')!r} missing")
        case_id = str(case.get("id") or entry.name.removesuffix("-alerts"))
        ranges = {"vulnerable": case.get("ranges"), "fixed": case.get("fixed_ranges")}
        cases.append(EngineCase(case_id, entry.name, repos[0], pins, str(case["family"]), ranges))
    return run.metadata.name, cases


def frozen_source(source: Path) -> Path:
    """The analyzer tree the engine container mounts: an export (``git archive HEAD src benchmarks/push/finding_dump.py``),
    never a live checkout, whose files could change under a long run."""
    source = Path(source).resolve()
    if (source / ".git").exists():
        raise EngineAlertsError(f"{source} is a git checkout; export it first (git archive HEAD src {DUMP.as_posix()})")
    if not (source / "src" / "openultrasast").is_dir() or not (source / DUMP).is_file():
        raise EngineAlertsError(f"{source} holds no src/openultrasast and {DUMP.as_posix()}")
    return source


def export_pin(cache_repo: Path, pin: str, target: Path) -> Path:
    """``git archive <pin>`` of the case cache into ``target`` (emptied first)."""
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    archive = target.parent / f"{target.name}.tar"
    with archive.open("wb") as stream:
        subprocess.run(["git", "-C", str(cache_repo), "archive", pin], stdout=stream, check=True)
    subprocess.run(["tar", "-xf", str(archive), "-C", str(target)], check=True)
    archive.unlink()
    if not any(target.rglob("*")):
        raise EngineAlertsError(f"{cache_repo} @ {pin}: the export is empty")
    return target


def docker_command(source: Path, checkout: Path, out_dir: Path, name: str, family: str, deadline: float, image: str) -> list[str]:
    return [
        "docker", "run", "--rm", "--init", "--network", "none", "--memory", MEMORY, "--entrypoint", "python",
        "-e", "OUSAST_LOG_LEVEL=WARNING", "-e", "PYTHONPATH=/new/src",
        "-v", f"{source / 'src'}:/new/src:ro", "-v", f"{source / DUMP}:/dump.py:ro",
        "-v", f"{checkout}:/case:ro", "-v", f"{out_dir}:/out",
        image, "/dump.py", "--root", "/case", "--families", family,
        "--out", f"/out/{name}.json", "--deadline", str(int(deadline)), "--max-regions", "5000",
    ]  # fmt: skip


def read_record(out: Path, log: str, returncode: int) -> dict[str, Any]:
    """The engine's result, with the files and bytes it said it read; fails unless it read input and asked questions."""
    tail = log.strip()[-600:]
    if not out.is_file():
        raise EngineAlertsError(f"the engine wrote no result {out.name} (exit {returncode}): {tail}")
    record = json.loads(out.read_text(encoding="utf-8"))
    read = _READ.search(log)
    if read is None or int(read.group(1)) == 0:
        raise EngineAlertsError(f"{out.name}: the engine did not report reading any file (exit {returncode}): {tail}")
    if not record.get("questions"):
        raise EngineAlertsError(f"{out.name}: no question was asked (exit {returncode}): the engine measured nothing")
    return {**record, "files": int(read.group(1)), "bytes": int(read.group(2)), "exit": returncode}


def parse_site(site: str) -> tuple[str, int | None, str | None]:
    match = _SITE.match(site)
    if match is None:
        return site, None, None
    return match.group(1), int(match.group(2)), match.group(3) or None


def engine_rows(record: Mapping[str, Any], root: Path, role: str, pin: str, ranges: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """The engine's findings as ``alerts.jsonl`` rows (the ``alerts`` task's shape plus ``source: "engine"``), one per
    rule, file, line; ``function`` by the ``repo-facts`` patterns when ``root`` holds the file, else the engine's."""
    cache: dict[str, list[str]] = {}
    rows: dict[tuple[str, str, int | None], dict[str, Any]] = {}
    for finding in record.get("findings") or []:
        path, line, function = parse_site(str(finding["site"]))
        rule_id = f"engine:{finding['family']}"
        row = {
            "rule_id": rule_id, "rule_status": "enabled", "path": path, "line": line,
            "function": function_at(root, path, line, function, cache), "pin_role": role, "pin": pin,
            "in_fix_range": in_range(ranges, path, line), "source": "engine",
        }  # fmt: skip
        rows.setdefault((rule_id, path, line), row)
    return sorted(rows.values(), key=lambda r: (r["path"], r["line"] or 0, r["rule_id"]))


def _image_id(image: str, runner: Runner) -> str:
    done = runner(["docker", "image", "inspect", "--format", "{{.Id}}", image], 60.0)
    return done.stdout.strip() if done.returncode == 0 and done.stdout.strip() else image


def produce(
    case: EngineCase, run_name: str, source: Path, work: Path, *, cache: Path = CACHE, deadline: float = DEADLINE,
    image: str = IMAGE, runner: Runner | None = None, results_root: Path | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Quick and engine alerts of one case on both pins into the run directory, the task marked done; the summary.
    A case whose files are all in quick-covered languages is ``skipped`` and nothing is written."""
    runner = runner or run_command
    started = time.monotonic()
    quick, engine = quick_languages(), engine_languages()
    rows: list[dict[str, Any]] = []
    files: dict[str, dict[str, int]] = {}
    summary: dict[str, Any] = {"read": {}, "alerts": {}, "alerts_engine": {}, "in_fix_range": {}, "engine": {}, "pins": dict(case.pins)}
    needed: set[str] = set()
    for role in ROLES:
        checkout = export_pin(cache / case.case_id, case.pins[role], work / f"{case.case_id}--{role}")
        try:
            quick_rows, read = scan(checkout, role, case.pins[role], case.ranges.get(role))
            files[role] = read.pop("languages")
            if read["files"] == 0:
                raise EngineAlertsError(f"{case.case_id} {role}: the quick scan read no file of {checkout}")
            needed |= {
                lang for lang in files[role]
                if lang != "unknown" and lang in engine and (not covers(quick, lang) or lang in ENGINE_ALONGSIDE_QUICK)
            }  # fmt: skip
            if not needed:
                return {"case": case.case_id, "status": "skipped", "reason": "quick mode covers every language read", "languages": files}
            out_dir = work / "out"
            out_dir.mkdir(parents=True, exist_ok=True)
            name = f"{case.case_id}--{role}"
            (out_dir / f"{name}.json").unlink(missing_ok=True)
            command = docker_command(source, checkout, out_dir, name, case.family, deadline, image)
            try:
                done = runner(command, deadline + GRACE)
            except subprocess.TimeoutExpired as exc:
                raise EngineAlertsError(f"{name}: the engine container outlived {deadline + GRACE:g}s") from exc
            record = read_record(out_dir / f"{name}.json", (done.stdout or "") + "\n" + (done.stderr or ""), done.returncode)
            found = engine_rows(record, checkout, role, case.pins[role], case.ranges.get(role))
        finally:
            shutil.rmtree(checkout, ignore_errors=True)
        rows.extend(quick_rows + found)
        summary["read"][role] = read
        summary["alerts"][role] = len(quick_rows) + len(found)
        summary["alerts_engine"][role] = len(found)
        summary["in_fix_range"][role] = sum(1 for r in found if r["in_fix_range"] is True)
        keys = ("files", "bytes", "questions", "completed", "seconds", "degradations", "exit")
        summary["engine"][role] = {**{k: record.get(k) for k in keys}, "findings": len(record.get("findings") or [])}
    cov = coverage(files, set(quick) - needed, needed)  # a language the engine ran for is reported as the engine's
    summary.update(
        status="done", units_done=len(ROLES), units_total=len(ROLES), usd=0, calls=0, usage={}, model=None, source="engine",
        host=True, family=case.family, image=_image_id(image, runner), deadline=deadline, quick_languages=sorted(quick),
        engine_languages=sorted(needed), coverage=cov, uncovered=uncovered(cov), seconds=round(time.monotonic() - started, 1),
    )  # fmt: skip
    output = reconciler.run_dir(run_name, results_root) / case.entry
    output.mkdir(parents=True, exist_ok=True)
    write_alert_rows(output, rows)
    write_alert_summary(output, summary)
    reused = {"source": "engine", "host": True, "image": summary["image"], "alerts": summary["alerts"], "seconds": summary["seconds"]}
    reconciler.mark_done(run_name, case.entry, reused=reused, results_root=results_root)
    return {"case": case.case_id, **summary}


def alerts_engine(
    run_manifest: Path, *, source: Path, only: Sequence[str] = (), work: Path | None = None, cache: Path = CACHE,
    deadline: float = DEADLINE, image: str = IMAGE, runner: Runner | None = None, results_root: Path | None = None,
) -> list[dict[str, Any]]:  # fmt: skip
    """:func:`produce` for every `alerts` case of the Run (or those named), one engine container at a time."""
    run_name, cases = engine_cases(run_manifest)
    unknown = set(only) - {c.case_id for c in cases}
    if unknown:
        raise EngineAlertsError(f"no alerts task in {run_manifest} for {sorted(unknown)}")
    frozen = frozen_source(source)
    scratch = Path(work) if work is not None else Path(tempfile.mkdtemp(prefix="ousast-engine-alerts-"))
    results: list[dict[str, Any]] = []
    for case in cases:
        if only and case.case_id not in only:
            continue
        results.append(
            produce(case, run_name, frozen, scratch, cache=cache, deadline=deadline, image=image, runner=runner, results_root=results_root)
        )
    if work is None:
        shutil.rmtree(scratch, ignore_errors=True)
    return results


__all__ = ["EngineAlertsError", "EngineCase", "alerts_engine", "engine_cases", "engine_rows", "parse_site", "produce", "read_record"]
