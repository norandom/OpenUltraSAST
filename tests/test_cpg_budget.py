"""Absolute transaction deadlines on the real process boundary (pre-push 4.1/4.2)."""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from openultrasast.cpg.backend import BEGIN, END, JoernBackend
from openultrasast.model.contracts import ExecutionBudget


def test_expired_budget_launches_nothing(tmp_path: Path) -> None:
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "ok", "")

    backend = JoernBackend(runner=run, execution_budget=ExecutionBudget(time.monotonic() - 1, 0.2))
    assert backend._run(["unused"], timeout=300) is None
    assert not calls
    assert "deadline_exhausted" in backend.last_failure


def test_remaining_time_is_not_reset_between_commands() -> None:
    remaining = []

    def run(command, **kwargs):
        remaining.append(kwargs["timeout"])
        time.sleep(0.04)
        return subprocess.CompletedProcess(command, 0, "", "")

    backend = JoernBackend(runner=run, execution_budget=ExecutionBudget(time.monotonic() + 0.5, 0.2))
    assert backend._run(["first"], timeout=300) is not None
    assert backend._run(["second"], timeout=300) is not None
    assert 0 < remaining[1] < remaining[0] <= 0.5


@pytest.mark.parametrize("leader_exits", [False, True])
def test_hanging_process_group_killed_inside_shared_allowance(tmp_path: Path, leader_exits: bool) -> None:
    source = tmp_path / "source.js"
    source.write_bytes(b"const input = req.query.input;\n")
    assert len(source.read_bytes()) == 31
    pids = tmp_path / "pids"
    script = """import os,signal,time,sys
signal.signal(signal.SIGTERM,signal.SIG_IGN)
child=os.fork()
if child==0:
    while True: time.sleep(1)
open(sys.argv[1], 'w').write(str(os.getpid())+' '+str(child))
if sys.argv[2]=='yes': sys.exit(0)
while True: time.sleep(1)
"""
    started = time.monotonic()
    deadline = started + 0.25
    backend = JoernBackend(execution_budget=ExecutionBudget(deadline, 0.3))
    try:
        assert backend._run([sys.executable, "-c", script, str(pids), "yes" if leader_exits else "no"], timeout=1) is None
        assert time.monotonic() - started < 0.65
        assert pids.is_file()
        for pid in map(int, pids.read_text().split()):
            status = Path(f"/proc/{pid}/stat")
            for _ in range(30):
                if not status.exists() or status.read_text().split()[2] == "Z":
                    break
                time.sleep(0.005)
            else:
                pytest.fail(f"process {pid} survived cancellation")
    finally:
        if pids.exists():
            for pid in map(int, pids.read_text().split()):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, 9)


@pytest.mark.parametrize("hang_stage", ["probe", "frontend", "overlay", "census", "taint"])
def test_real_hanging_engine_stages_share_deadline_and_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hang_stage: str) -> None:
    from openultrasast.cpg import backend as module

    root = tmp_path / "source"
    root.mkdir()
    source = root / "api.php"
    source.write_bytes(b"<?php function f($x) { return $x; }\n")
    assert len(source.read_bytes()) == 36
    launcher = tmp_path / "engine"
    event_log = tmp_path / "events"
    pid_log = tmp_path / "pids"
    launcher.write_text(f"""#!{sys.executable}
import os,sys,json,time,signal
from pathlib import Path
args=sys.argv[1:]
stage='probe' if '-r' in args else 'frontend' if '-o' in args else Path(args[args.index('--script')+1]).stem
with open({str(event_log)!r},'a') as f: f.write(stage+'\\n')
if stage=='probe':
    data=Path(args[-1]).read_bytes()
    print(len(data))
    assert data
if stage=={hang_stage!r}:
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    child=os.fork()
    if child==0:
        while True: time.sleep(1)
    Path({str(pid_log)!r}).write_text(str(os.getpid())+' '+str(child))
    while True: time.sleep(1)
if stage=='frontend': Path(args[args.index('-o')+1]).write_bytes(b'controlled graph fixture')
if stage=='overlay':
    graph=Path(next(a.split('=',1)[1] for a in args if a.startswith('cpgFile=')))
    saved=Path.cwd()/'workspace'/graph.name/'cpg.bin'
    saved.parent.mkdir(parents=True)
    saved.write_bytes(b'controlled graph with overlays')
print({BEGIN!r})
print(json.dumps({{'files':'1','methods':'1','calls':'1','overlays':'dataflowOss'}} if stage!='taint' else {{'r':[]}}))
print({END!r})
""")
    launcher.chmod(0o700)
    monkeypatch.setattr(module.shutil, "which", lambda name: str(launcher))
    monkeypatch.setattr(module, "joern_version", lambda: (4, 0, 625))
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(module.tempfile, "mkdtemp", lambda **kwargs: str(scratch))
    started = time.monotonic()
    budget = ExecutionBudget(started + 0.55, 0.35)
    backend = JoernBackend(execution_budget=budget)
    graph = None
    try:
        graph = backend.build(root, language="php")
        if hang_stage == "taint":
            assert graph is not None
            assert graph.run_batch is not None
            assert graph.run_batch("taint", {"r": {}}) is None
            assert graph.execution_diagnostics is not None
            assert "deadline_exhausted" in graph.execution_diagnostics()
        else:
            assert graph is None
        if graph is not None and graph.cleanup is not None:
            graph.cleanup()
        assert time.monotonic() - started < 1.0
        assert event_log.read_text().splitlines()[-1] == hang_stage
        assert not scratch.exists()
        assert pid_log.exists(), "the controlled subprocess really reached the hanging stage"
        for pid in map(int, pid_log.read_text().split()):
            status = Path(f"/proc/{pid}/stat")
            for _ in range(30):
                if not status.exists() or status.read_text().split()[2] == "Z":
                    break
                time.sleep(0.005)
            else:
                pytest.fail(f"engine child {pid} survived")
    finally:
        if pid_log.exists():
            for pid in map(int, pid_log.read_text().split()):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, 9)


def test_explicit_build_budget_is_retained_without_mutating_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.cpg import backend as module

    calls = []

    def run(command, **kwargs):
        calls.append(kwargs["timeout"])
        if "--output" in command:
            Path(command[command.index("--output") + 1]).write_bytes(b"graph fixture")
        return subprocess.CompletedProcess(command, 0, f'{BEGIN}\n{{"r":[]}}\n{END}', "")

    monkeypatch.setattr(module.shutil, "which", lambda name: name)
    backend = JoernBackend(runner=run)
    budget = ExecutionBudget(time.monotonic() + 1, 0.2)
    graph = backend.build(tmp_path, language="javascript", execution_budget=budget)
    assert graph is not None and graph.run_batch is not None and graph.cleanup is not None
    assert backend.execution_budget is None
    time.sleep(0.02)
    assert graph.run_batch("taint", {"r": {}}) == {"r": []}
    assert 0 < calls[1] < calls[0] <= 1
    graph.cleanup()
    assert not graph.cpg_path.parent.exists()


def test_early_process_timeout_stops_fallback_and_retries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.cpg import backend as module

    calls = []

    def run(command, **kwargs):
        calls.append(command)
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(module.shutil, "which", lambda name: name)
    backend = JoernBackend(runner=run, execution_budget=ExecutionBudget(time.monotonic() + 100, 0.2))
    assert backend.build(tmp_path, language="javascript") is None
    assert len(calls) == 1
    assert "process_timeout" in backend._diagnostics


def test_retry_timeout_consumes_same_absolute_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.cpg import backend as module

    calls = []

    def run(command, **kwargs):
        calls.append(kwargs["timeout"])
        Path(command[command.index("-o") + 1]).write_bytes(b"partial graph")
        time.sleep(0.04)
        return subprocess.CompletedProcess(command, 0, "WARN Failed to process 'x.php'", "")

    monkeypatch.setattr(module.shutil, "which", lambda name: name)
    backend = JoernBackend(runner=run, execution_budget=ExecutionBudget(time.monotonic() + 1, 0.2))
    assert backend._build_with_retries_raw(tmp_path, tmp_path / "cpg.bin", tmp_path, "php") == ("x.php",)
    assert len(calls) == 4
    assert all(a > b > 0 for a, b in zip(calls, calls[1:], strict=False))
    assert calls[0] <= 1


def test_shard_failure_cannot_become_complete_empty_answer(tmp_path: Path) -> None:
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if len(calls) == 2:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, 0, f'{BEGIN}\n{{"r":[]}}\n{END}', "")

    backend = JoernBackend(runner=run, execution_budget=ExecutionBudget(time.monotonic() + 1, 0.2))
    assert backend.query_batch_across([tmp_path / "a.bin", tmp_path / "b.bin", tmp_path / "c.bin"], "taint", {"r": {}}) is None
    assert len(calls) == 2
    assert "shard_query_incomplete" in backend._diagnostics


def test_cleanup_cannot_reset_expired_cancellation_allowance(tmp_path: Path) -> None:
    graph = tmp_path / "owned"
    graph.mkdir()
    (graph / "data").write_bytes(b"data")
    backend = JoernBackend(execution_budget=ExecutionBudget(time.monotonic() - 1, 0.1))
    started = time.monotonic()
    backend._cleanup(graph, final=True)
    assert time.monotonic() - started < 0.05
    assert graph.exists()
    assert "scratch_cleanup_incomplete" in backend._diagnostics


def test_cleanup_does_not_follow_substituted_directory_links(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_bytes(b"keep")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "link").symlink_to(outside, target_is_directory=True)
    backend = JoernBackend(execution_budget=ExecutionBudget(time.monotonic() + 1, 0.2))
    backend._cleanup(scratch, final=True)
    assert not scratch.exists()
    assert (outside / "keep").read_bytes() == b"keep"


def test_driver_propagates_budget_and_rejects_legacy_without_launch(tmp_path: Path) -> None:
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.scan import scan_repository

    budget = ExecutionBudget(time.monotonic() + 1, 0.2)

    class Backend:
        seen = None
        cleaned = False

        def build(self, root, *, language, exclude, execution_budget):
            self.seen = execution_budget
            return CpgResult(tmp_path / "graph", lambda *args: [], cleanup=self.cleanup)

        def cleanup(self):
            self.cleaned = True

    backend = Backend()
    result = scan_repository(tmp_path, [], backend=backend, execution_budget=budget, client=object())
    assert backend.seen is budget and backend.cleaned
    assert any(d["reason"] == "model_withheld_execution_budget" for d in result.degradations)

    class Legacy:
        called = False

        def build(self, root):
            self.called = True
            raise AssertionError("must not launch without a deadline")

    legacy = Legacy()
    result = scan_repository(tmp_path, [], backend=legacy, execution_budget=budget)
    assert not legacy.called
    assert any(d["reason"] == "cpg_build_failed" for d in result.degradations)


def test_budgeted_driver_does_not_retry_internal_typeerror(tmp_path: Path) -> None:
    from openultrasast.model.scan import scan_repository

    class Backend:
        calls = 0

        def build(self, root, **kwargs):
            self.calls += 1
            raise TypeError("internal backend bug")

    backend = Backend()
    with pytest.raises(TypeError, match="internal backend bug"):
        scan_repository(tmp_path, [], backend=backend, execution_budget=ExecutionBudget(time.monotonic() + 1, 0.2))
    assert backend.calls == 1


def test_cancelled_graph_session_does_not_poison_next_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.cpg import backend as module

    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        if "--output" in command:
            Path(command[command.index("--output") + 1]).write_bytes(b"graph")
        return subprocess.CompletedProcess(command, 0, f'{BEGIN}\n{{"r":[]}}\n{END}', "")

    monkeypatch.setattr(module.shutil, "which", lambda name: name)
    backend = JoernBackend(runner=run)
    budget = ExecutionBudget(time.monotonic() + 2, 0.2)
    assert backend.build(tmp_path, execution_budget=budget) is None
    assert backend._cancel_deadline is None
    graph = backend.build(tmp_path, execution_budget=budget)
    assert graph is not None and graph.cleanup is not None
    assert graph.execution_diagnostics is not None
    assert graph.execution_diagnostics() == ()
    graph.cleanup()


def test_driver_cleans_graph_on_unexpected_exception(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model import scan

    cleaned = []

    class Backend:
        def build(self, root, **kwargs):
            return CpgResult(tmp_path / "graph", lambda *args: [], cleanup=lambda: cleaned.append(True))

    def broken(*args, **kwargs):
        raise RuntimeError("broken context")

    monkeypatch.setattr(scan, "_hook_callbacks", broken)
    with pytest.raises(RuntimeError, match="broken context"):
        scan.scan_repository(tmp_path, [], backend=Backend(), execution_budget=ExecutionBudget(time.monotonic() + 1, 0.2))
    assert cleaned == [True]


def test_failed_nonbatch_query_is_unjudged_on_budgeted_path(tmp_path: Path) -> None:
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.regions import ScanRegion
    from openultrasast.model.scan import scan_repository

    source = tmp_path / "api.py"
    source.write_bytes(b"def run(x): return x\n")
    assert len(source.read_bytes()) > 0

    class Backend:
        def build(self, root, **kwargs):
            return CpgResult(tmp_path / "graph", lambda *args: None)

    region = ScanRegion(path="api.py", function="run", language="python", families=("injection",), rank=1.0, source="entry_point")
    result = scan_repository(tmp_path, [region], backend=Backend(), execution_budget=ExecutionBudget(time.monotonic() + 1, 0.2))
    assert result.regions_scanned == 0 and result.regions_unjudged == 1
    assert any(d["reason"] == "query_failed" for d in result.degradations)
