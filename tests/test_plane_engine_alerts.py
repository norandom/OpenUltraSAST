"""`ousast plane alerts-engine` (harnessx-removal Req 6.3): PHP alerts from the engine image, produced on the host.

No container runs here: the docker runner is injected. The engine's output is the recorded probe
(``fixtures/plane-engine/probe.json``: 1 file read, 1 question asked and completed, 2 injection findings)."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from test_plane_loop import LOOP, _templates, _write

from openultrasast import cli
from openultrasast.plane import engine_alerts
from openultrasast.plane.engine_alerts import EngineAlertsError, alerts_engine, engine_rows, parse_site, read_record
from openultrasast.plane.generate import CaseInputs, render

FIXTURE = Path(__file__).parent / "fixtures" / "plane-engine"
CASE = "php-probe"
RECORD = json.loads((FIXTURE / "probe.json").read_text())
LOG = (FIXTURE / "probe.stdout.txt").read_text()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def world(tmp_path: Path) -> dict[str, Any]:
    """A case cache with a vulnerable and a fixed commit, a Run with the case's `alerts` task, a frozen source."""
    repo = tmp_path / "cache" / CASE
    (repo / "app").mkdir(parents=True)
    _git(repo, "init", "-q")
    shutil.copy(FIXTURE / "app" / "index.php", repo / "app" / "index.php")
    _git(repo, "add", ".")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "vulnerable")
    vulnerable = _git(repo, "rev-parse", "HEAD")
    text = (repo / "app" / "index.php").read_text().replace('" . $id', '" . intval($id)')
    (repo / "app" / "index.php").write_text(text)
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qam", "fixed")
    fixed = _git(repo, "rev-parse", "HEAD")
    record = {"id": CASE, "repo": "https://example.com/reserved/probe", "family": "injection", "vulnerable": vulnerable, "fixed": fixed}
    candidate = ("app/index.php", "<global>", 3)
    case = CaseInputs(
        record, (candidate,), (candidate,), {}, 0.0, ranges={"app/index.php": [(3, 3)]}, fixed_ranges={"app/index.php": [(3, 3)]}
    )
    files = render([case], _templates(), "validation-46", "t", population="p", split="s", loop=LOOP)
    source = tmp_path / "frozen"
    (source / "src" / "openultrasast").mkdir(parents=True)
    (source / "benchmarks" / "push").mkdir(parents=True)
    (source / "benchmarks" / "push" / "finding_dump.py").write_text("")
    run = _write(tmp_path / "plane", files)
    return {"run": run, "source": source, "cache": tmp_path / "cache", "pins": (vulnerable, fixed), "results": tmp_path / "results"}


class FakeDocker:
    """Answers `docker image inspect` and writes ``record`` as the engine's result for every `docker run`."""

    def __init__(self, record: dict[str, Any] | None = RECORD, log: str = LOG) -> None:
        self.record, self.log, self.runs = record, log, []  # type: ignore[var-annotated]

    def __call__(self, command: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
        command = list(command)
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, "sha256:feed\n", "")
        mounts = [command[i + 1] for i, part in enumerate(command) if part == "-v"]
        checkout = Path(next(m for m in mounts if m.endswith(":/case:ro")).split(":")[0])
        assert (checkout / "app" / "index.php").is_file(), "the pin was exported before the container ran"
        self.runs.append({"command": command, "timeout": timeout})
        if self.record is not None:
            out = Path(next(m for m in mounts if m.endswith(":/out")).split(":")[0])
            (out / command[command.index("--out") + 1].removeprefix("/out/")).write_text(json.dumps(self.record))
        return subprocess.CompletedProcess(command, 0, self.log, "")


def _produce(world: dict[str, Any], docker: FakeDocker, tmp_path: Path) -> list[dict[str, Any]]:
    return alerts_engine(
        world["run"], source=world["source"], work=tmp_path / "work", cache=world["cache"], deadline=120, runner=docker,
        results_root=world["results"],
    )  # fmt: skip


def test_recorded_engine_findings_become_alert_rows() -> None:
    assert parse_site("app/index.php:3:<global>") == ("app/index.php", 3, "<global>")
    assert parse_site("lib/A.php:76:Foo::bar") == ("lib/A.php", 76, "Foo::bar")
    record = read_record(FIXTURE / "probe.json", LOG, 0)
    assert (record["files"], record["bytes"], record["questions"], record["completed"]) == (1, 145, 1, 1)
    rows = engine_rows(record, FIXTURE, "vulnerable", "a" * 40, {"app/index.php": [[3, 3]]})
    assert rows == [
        {"rule_id": "engine:injection", "rule_status": "enabled", "path": "app/index.php", "line": line, "function": "<global>",
         "pin_role": "vulnerable", "pin": "a" * 40, "in_fix_range": line == 3, "source": "engine"}
        for line in (3, 5)
    ]  # fmt: skip


def test_an_engine_that_read_nothing_or_asked_nothing_fails(tmp_path: Path) -> None:
    out = tmp_path / "x.json"
    with pytest.raises(EngineAlertsError, match="wrote no result"):
        read_record(out, "boom", 125)
    out.write_text(json.dumps({**RECORD, "questions": 0}))
    with pytest.raises(EngineAlertsError, match="no question was asked"):
        read_record(out, LOG, 0)
    out.write_text(json.dumps(RECORD))
    with pytest.raises(EngineAlertsError, match="did not report reading"):
        read_record(out, "", 0)


def test_alerts_engine_writes_the_alerts_task_outputs_and_marks_it_done(world: dict[str, Any], tmp_path: Path) -> None:
    docker = FakeDocker()
    [result] = _produce(world, docker, tmp_path)
    assert result["status"] == "done" and len(docker.runs) == 2, "one container per pin, one after the other"
    for run in docker.runs:
        command = run["command"]
        assert command[command.index("--memory") + 1] == "3g" and command[command.index("--network") + 1] == "none"
        assert command[command.index("--families") + 1] == "injection" and run["timeout"] == 120 + engine_alerts.GRACE
    out = world["results"] / "validation-46" / f"{CASE}-alerts"
    rows = [json.loads(line) for line in (out / "alerts.jsonl").read_text().splitlines()]
    vulnerable, fixed = world["pins"]
    quick = {(r["pin_role"], r["rule_id"], r["line"]) for r in rows if "source" not in r}
    assert ("vulnerable", "php-sql-call-composition", 3) in quick and ("fixed", "php-sql-call-composition", 3) not in quick, (
        "PHP's quick rules run beside the engine and see the intval fix"
    )
    got = [(r["pin_role"], r["pin"], r["line"], r["in_fix_range"], r["source"]) for r in rows if "source" in r]
    assert got == [("vulnerable", vulnerable, 3, True, "engine"), ("vulnerable", vulnerable, 5, False, "engine"),
                   ("fixed", fixed, 3, True, "engine"), ("fixed", fixed, 5, False, "engine")]  # fmt: skip
    summary = json.loads((out / "summary.json").read_text())
    assert (summary["status"], summary["units_done"], summary["units_total"], summary["source"]) == ("done", 2, 2, "engine")
    assert summary["engine"]["vulnerable"] == {
        "files": 1, "bytes": 145, "questions": 1, "completed": 1, "seconds": 58.6, "degradations": [], "exit": 0, "findings": 2
    }  # fmt: skip
    assert summary["coverage"] == {"php": {"coverage": "engine", "files": {"fixed": 1, "vulnerable": 1}}} and summary["uncovered"] == []
    assert summary["in_fix_range"] == {"vulnerable": 1, "fixed": 1} and summary["image"] == "sha256:feed"
    assert isinstance(summary["seconds"], float)
    state = json.loads((world["results"] / "validation-46" / "state.json").read_text())["tasks"][f"{CASE}-alerts"]
    assert state["status"] == "done" and state["reused"]["source"] == "engine", "the reconciler skips it like reused facts"
    assert not list((tmp_path / "work").glob(f"{CASE}--*/"))


def test_a_failed_engine_leaves_the_run_untouched(world: dict[str, Any], tmp_path: Path) -> None:
    with pytest.raises(EngineAlertsError, match="no question was asked"):
        _produce(world, FakeDocker({**RECORD, "questions": 0, "findings": []}), tmp_path)
    with pytest.raises(EngineAlertsError, match="wrote no result"):
        _produce(world, FakeDocker(None), tmp_path)
    assert not (world["results"] / "validation-46").exists(), "no alerts written, nothing marked done"


def test_the_source_must_be_a_frozen_export(world: dict[str, Any], tmp_path: Path) -> None:
    (world["source"] / ".git").mkdir()
    with pytest.raises(EngineAlertsError, match="export it first"):
        _produce(world, FakeDocker(), tmp_path)


def test_the_cli_reports_and_fails_loudly(world: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                          capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    monkeypatch.setattr(engine_alerts, "run_command", FakeDocker({**RECORD, "questions": 0}))
    argv = ["plane", "alerts-engine", str(world["run"]), "--source", str(world["source"]), "--repos", str(world["cache"])]
    monkeypatch.setenv("OUSAST_RESULTS", str(tmp_path / "r"))
    assert cli.main(argv) == 2
    assert "no question was asked" in capsys.readouterr().err
