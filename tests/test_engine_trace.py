"""Offline controls for the trace experiment; no Docker, Joern or network."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from openultrasast.cpg.backend import BEGIN, END, CpgResult, JoernBackend
from openultrasast.model.specs import taint_specs
from openultrasast.model.taint import request_params
from openultrasast.model.trace import parse_trace

SCRIPT = Path(__file__).resolve().parents[1] / "benchmarks/learn/engine_trace.py"
_spec = importlib.util.spec_from_file_location("engine_trace", SCRIPT)
assert _spec and _spec.loader
trace = importlib.util.module_from_spec(_spec)
with pytest.MonkeyPatch.context() as patch:
    patch.syspath_prepend(str(SCRIPT.parent))
    _spec.loader.exec_module(trace)
worker = sys.modules["engine_trace_worker"]


def row(**extra):
    return {
        "sink": "os.system(cmd)",
        "source": "request.args['cmd']",
        "sinkFile": "app.py",
        "sinkMethod": "run",
        "sinkLine": 4,
        "sourceKind": "framework",
        "length": 3,
        "paths": 2,
        "sanitized": False,
        "bounded": False,
        "bound": "",
        "trace": ["app.py:run:2 [CALL] request.args['cmd']", "app.py:run:3 [IDENTIFIER] cmd", "app.py:run:4 [CALL] os.system(cmd)"],
        **extra,
    }


def unit(id="a", pin="pin", **extra):
    return {
        "unit": id,
        "repo": "owner/repo",
        "pin": pin,
        "family": "injection",
        "source": "vibe-py",
        "excerpt": True,
        "file": "app.py",
        "function": "run",
        "language": "python",
        "pin_role": "vulnerable",
        "pair": "pair",
        "label": 1,
        "fold": "outer-0",
        "group": "owner/repo",
        "supported": True,
        "reason": "",
        **extra,
    }


def test_trace_roles_and_path_level_sanitizer():
    result = parse_trace(row(sanitized=True, bound="cmd", bounded=True))
    assert [s["roles"] for s in result["steps"]] == [["source"], ["step", "guard"], ["sink"]]
    assert result["steps"][0] == {
        "file": "app.py",
        "method": "run",
        "line": 2,
        "node_label": "CALL",
        "code": "request.args['cmd']",
        "roles": ["source"],
        "raw": "app.py:run:2 [CALL] request.args['cmd']",
    }
    assert result["sanitizer"] == {"on_path": True, "step": None}
    assert result["guard"] == {"text": "cmd", "bounded": True}
    off_path = parse_trace(row(bound="len < 20", bounded=True))
    assert all("guard" not in s["roles"] for s in off_path["steps"])
    assert off_path["guard"]["text"] == "len < 20"


def test_trace_unknown_location_and_method_colons():
    parsed = parse_trace(row(trace=["?:-1 [UNKNOWN] x", "a.php:A::run:4 [CALL] sink(x)"]))
    assert parsed["steps"][0]["line"] == -1
    assert parsed["steps"][0]["method"] == "?"
    assert parsed["steps"][1]["method"] == "A::run"
    assert parse_trace(row(trace=["a.py:run:2 [CALL] x"]))["steps"][0]["roles"] == ["source", "sink"]
    with pytest.raises(ValueError, match="invalid trace"):
        parse_trace(row(trace=["unreadable"]))


def test_rendered_default_scan_params_do_not_request_trace(tmp_path):
    spec = taint_specs(language="python")["injection"]
    rendered = []

    def runner(command, **kwargs):
        request_file = next(arg.split("=", 1)[1] for arg in command if arg.startswith("requestsFile="))
        rendered.append(json.loads(Path(request_file).read_text()))
        return subprocess.CompletedProcess(command, 0, BEGIN + '\n{"r": []}\n' + END, "")

    backend = JoernBackend(runner=runner, session_transport=False)
    cpg = tmp_path / "cpg.bin"
    cpg.write_bytes(b"graph")
    backend._batch_once(cpg, "taint", {"r": request_params(spec)})
    backend._batch_once(cpg, "taint", {"r": request_params(spec, trace=True)})
    assert "trace" not in rendered[0]["r"]
    assert rendered[1]["r"]["trace"] == "true"
    script = backend.queries_dir / "taint.sc"
    assert "traceS = trace" in script.read_text()  # single-query forwarding too


def test_plan_groups_skips_done_and_retains_other_families(tmp_path):
    units = [unit(), unit("b", label=0), unit("c", "other")]
    plan = trace.make_plan(units, tmp_path)
    assert sorted(len(p["units"]) for p in plan) == [1, 2]
    done = next(p for p in plan if p["pin"] == "pin")
    trace.write_json(tmp_path / trace.pin_name(done), {**done, "done": True})
    assert len(trace.make_plan(units, tmp_path)) == 1
    assert trace.make_plan(units, tmp_path, only_family="path") == []
    assert len(trace.make_plan(units, tmp_path, limit=1)) == 1
    # An interrupted pin is rerun, even if a checkpoint file exists.
    trace.write_json(tmp_path / trace.pin_name(done), {**done, "done": False})
    assert len(trace.make_plan(units, tmp_path)) == 2


def test_join_requires_exact_examples_and_ts_opt_in():
    u = unit()
    example = {**u, "id": "a", "candidate": "app.ts::run", "source": "pairs", "language": "typescript"}
    with pytest.raises(ValueError, match="missing 1/1"):
        trace.join_units([u], [])
    assert not trace.join_units([u], [example])[0]["supported"]
    assert trace.join_units([u], [example], include_typescript=True)[0]["supported"]


class FakeBackend:
    seconds = 20
    census_files = 1
    timed_out = False
    fatal = ""
    last_failure = ""
    seen = []

    def __init__(self, deadline, question_deadline, checkpoint):
        self.stages = [{"command": "joern-parse", "seconds": self.seconds, "exit": 0, "cpg_bytes": 2048}]
        self.asked = []
        self.answers = {}

    def build(self, root, language):
        graph = root / "graph.bin"
        graph.write_bytes(b"x" * 2048)

        def batch(query, requests):
            self.seen.append(requests)
            self.asked.extend(requests)
            self.stages.append({"command": "joern", "seconds": self.seconds, "exit": 0})
            return {
                **{rid: [row()] if rid == "a" else [] for rid in requests},
                "__census__": [{"files": str(self.census_files), "file_names": ["app.py"]}],
            }

        return CpgResult(graph, lambda q, p: None, run_batch_once=batch)


def run_fake(tmp_path, monkeypatch, backend=FakeBackend, content="def run():\n    pass\n"):
    monkeypatch.setattr(worker, "MeasuredBackend", backend)
    (tmp_path / "app.py").write_text(content)
    pin = {"repo": "owner/repo", "pin": "pin", "units": [unit(), unit("b")]}
    out = tmp_path / "result.json"
    pin["questions"] = trace.prepare_questions(pin, tmp_path, 120) if content else {}
    worker.worker(pin, tmp_path, out, 900, 120)
    return json.loads(out.read_text())


def test_worker_one_batch_and_preserves_witnesses(tmp_path, monkeypatch):
    FakeBackend.seen = []
    result = run_fake(tmp_path, monkeypatch)
    assert [u["status"] for u in result["units"]] == ["path", "asked-nothing"]
    assert len(FakeBackend.seen) == 1
    assert all(p["trace"] == "true" and p["function"] == "run" and p["file"] == "app.py" for p in FakeBackend.seen[0].values())
    assert result["units"][0]["witness_rows"] == [row()]
    assert result["units"][0]["traces"][0]["steps"][-1]["roles"] == ["sink"]
    assert result["units"][1]["questions_completed"] == ["b"]
    assert result["instrument"]["files"][0]["bytes"] > 0


@pytest.mark.parametrize("failure", ["fast", "zero-input", "zero-census"])
def test_invalid_instrument_is_persisted_failed(tmp_path, monkeypatch, failure):
    class BadBackend(FakeBackend):
        seconds = 0.5 if failure == "fast" else 20
        census_files = 0 if failure == "zero-census" else 1

    result = run_fake(tmp_path, monkeypatch, BadBackend, "" if failure == "zero-input" else "def run():\n    pass\n")
    assert result["done"]
    assert all(u["status"] == "failed" for u in result["units"])
    assert all(u["reason"] for u in result["units"])
    assert "<5s" in result["units"][0]["reason"] if failure == "fast" else "zero" in result["units"][0]["reason"]


def test_missing_labelled_function_is_failure(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="not declared"):
        run_fake(tmp_path, monkeypatch, content="def other():\n    pass\n")


def test_docker_command_is_serial_offline_frozen():
    cmd = trace.docker_command(Path("/export"), Path("/pin"), Path("/output"), "one", "openultrasast:dev", 900, 60)
    assert cmd[cmd.index("--memory") + 1] == "3g"
    assert cmd[cmd.index("--network") + 1] == "none"
    assert cmd[cmd.index("--pull") + 1] == "never"
    assert "/export:/frozen:ro" in cmd and "/pin:/case:ro" in cmd
    assert cmd[-1] == "60"
    assert "/frozen/benchmarks/learn/engine_trace_worker.py" in cmd
    assert "benchmarks/learn/engine_trace_worker.py" in trace.SNAPSHOT_FILES


def test_summary_separates_unanswered_pairs(tmp_path):
    rows = [
        trace.unit_record(unit(), "path"),
        trace.unit_record(unit("b", label=0), "asked-nothing"),
        trace.unit_record(unit("c", pair="other"), "failed"),
        trace.unit_record(unit("d", pair="other", label=0), "timeout"),
    ]
    trace.write_json(tmp_path / "one.json", {"done": True, "units": rows})
    result = trace.summary(tmp_path)
    assert result["pair_asymmetry"] == {"vulnerable-only": 1, "neither": 1}
    assert result["pair_asymmetry_both_answered"] == {"vulnerable-only": 1}
    assert result["by_family"]["injection"]["failed"] == 1


def test_frozen_source_overlays_uncommitted_files_without_live_mount(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    for name in trace.SNAPSHOT_FILES:
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("snapshot " + name)
    monkeypatch.setattr(trace, "ROOT", root)
    commands = []

    def run(cmd, **kwargs):
        commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "head-sha\n", "")

    monkeypatch.setattr(trace.subprocess, "run", run)
    frozen = tmp_path / "frozen"
    proof = trace.freeze_source(frozen)
    assert commands[0][-3:] == ["archive", "HEAD", "src"]
    for name in trace.SNAPSHOT_FILES:
        assert (frozen / name).read_bytes() == (root / name).read_bytes()
        assert len(proof["overlay_sha256"][name]) == 64


def test_question_watchdog_retains_completed_rows_without_joern(tmp_path):
    import sys

    code = (
        "import json,time\n"
        'print(json.dumps({"__question__":"a"}),flush=True)\n'
        'print(json.dumps({"id":"a","rows":[]}),flush=True)\n'
        'print(json.dumps({"__question__":"b"}),flush=True)\n'
        "time.sleep(60)\n"
    )
    backend = worker.MeasuredBackend(10, 0.05, lambda: None)
    done = backend._run([sys.executable, "-c", code], timeout=10, cwd=tmp_path)
    assert backend.timed_out
    assert backend.asked == ["a", "b"]
    assert backend.answers == {"a": []}
    assert done.returncode != 0
    assert backend.stages == []
    assert not backend.fatal


def test_pair_mapping_handles_harvest_normalized_crlf(tmp_path):
    import hashlib
    from types import SimpleNamespace

    file = tmp_path / "excerpt.py"
    file.write_bytes(b"def run():\r\n    pass\r\n")
    normalized = file.read_text().encode()
    pin = hashlib.sha1(b"blob " + str(len(normalized)).encode() + b"\0" + normalized).hexdigest()
    case = SimpleNamespace(name="case", repo="owner/repo", relpath="app.py", vuln_file=file, fixed_file=file)
    inputs = object.__new__(trace.Inputs)
    inputs.pairs = [case]
    inputs.hashes = {}
    assert inputs.pair_for(unit(pin=pin)) == (case, "vuln")


def test_missing_batch_answers_are_timeout_not_empty(tmp_path, monkeypatch):
    class TimeoutBackend(FakeBackend):
        def build(self, root, language):
            graph = root / "graph.bin"
            graph.write_bytes(b"x" * 2048)

            def batch(query, requests):
                self.timed_out = True
                self.asked.append("a")
                return None

            return CpgResult(graph, lambda q, p: None, run_batch_once=batch)

    result = run_fake(tmp_path, monkeypatch, TimeoutBackend)
    assert [r["status"] for r in result["units"]] == ["timeout", "timeout"]
    assert result["units"][0]["questions_asked"] == ["a"]
    assert result["units"][1]["questions_asked"] == []


def test_dry_run_makes_no_subprocess_calls(tmp_path, monkeypatch, capsys):
    import sys

    u = unit()
    examples = [{**u, "id": "a", "candidate": "app.py::run", "source": "population-v1"}]
    units = tmp_path / "units.jsonl"
    units.write_text(json.dumps(u) + "\n")
    example_file = tmp_path / "examples.jsonl"
    example_file.write_text(json.dumps(examples[0]) + "\n")
    monkeypatch.setattr(
        sys, "argv", [str(SCRIPT), "--dry-run", "--units", str(units), "--examples", str(example_file), "--out", str(tmp_path / "results")]
    )
    monkeypatch.setattr(trace.subprocess, "run", lambda *a, **kw: pytest.fail("dry-run spawned a subprocess"))
    assert trace.main() == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["runnable_pins"] == 1 and plan["units"] == 1
    assert plan["estimated_seconds"] == 182
    assert not (tmp_path / "results").exists()


def test_family_filtered_results_merge_without_losing_prior_units(tmp_path):
    first = trace.make_plan([unit(), unit("b", family="path")], tmp_path, only_family="injection")[0]
    trace.save_pin(tmp_path / trace.pin_name(first), {**first, "done": True})
    second = trace.make_plan([unit(), unit("b", family="path")], tmp_path, only_family="path")[0]
    trace.save_pin(tmp_path / trace.pin_name(second), {**second, "done": True})
    assert trace.make_plan([unit(), unit("b", family="path")], tmp_path) == []


def test_failed_launch_persists_failed_pin_and_resume_skips_it(tmp_path, monkeypatch):
    from types import SimpleNamespace

    class Inputs:
        def materialize(self, pin, target):
            target.mkdir()
            (target / "app.py").write_text("def run():\n    pass\n")

    commands = []

    def run(cmd, **kwargs):
        commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(trace.subprocess, "run", run)
    pin = trace.make_plan([unit()], tmp_path)[0]
    args = SimpleNamespace(image="openultrasast:dev", deadline=900, question_deadline=120)
    assert trace.run_pin(pin, tmp_path / "frozen", {}, Inputs(), tmp_path, args)
    result = json.loads((tmp_path / trace.pin_name(pin)).read_text())
    assert result["units"][0]["status"] == "failed"
    assert "produced no result" in result["units"][0]["reason"]
    assert [c[1] for c in commands if c[0] == "docker"] == ["run", "rm"]
    assert trace.make_plan([unit()], tmp_path) == []


def import_container_worker():
    """Import in a fresh interpreter so host imports cannot mask the boundary."""
    script = SCRIPT.with_name("engine_trace_worker.py")
    code = """
import json, pathlib, runpy, sys
sys.modules['yaml'] = None
sys.modules['boto3'] = None
script = pathlib.Path(sys.argv[1])
size = len(script.read_bytes())
runpy.run_path(str(script), run_name='trace_import_check')
print(json.dumps({'bytes': size, 'modules': sorted(
    name for name in sys.modules if name == 'openultrasast' or name.startswith('openultrasast.')
)}))
"""
    result = subprocess.run([sys.executable, "-c", code, str(script)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_trace_container_import_without_yaml_or_boto3():
    assert import_container_worker()["bytes"] > 0


def test_trace_container_transitive_import_boundary():
    # Explicit inventory: additions need review, particularly learn.examples/plane.*.
    assert import_container_worker()["modules"] == [
        "openultrasast",
        "openultrasast.contracts",
        "openultrasast.cpg",
        "openultrasast.cpg.artifact",
        "openultrasast.cpg.backend",
        "openultrasast.cpg.session",
        "openultrasast.model",
        "openultrasast.model.contracts",
        "openultrasast.model.trace",
    ]


@pytest.mark.parametrize("existing", [False, True])
def test_trace_dry_run_unsupported_units_write_nothing(tmp_path, monkeypatch, capsys, existing):
    out = tmp_path / "results"
    if existing:
        out.mkdir()
        (out / ".lock").write_bytes(b"existing lock")
        (out / "checkpoint.json").write_text('{"done": false}')
        (out / "previous.json").write_text('{"done": true, "units": []}')
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in out.glob("*")}
    units = [unit("ts", file="app.ts"), unit("py", pin="python")]
    examples = [{**u, "id": u["unit"], "candidate": u["file"] + "::run", "source": "population-v1"} for u in units]
    units_file, examples_file = tmp_path / "units.jsonl", tmp_path / "examples.jsonl"
    units_file.write_text("\n".join(map(json.dumps, units)))
    examples_file.write_text("\n".join(map(json.dumps, examples)))
    monkeypatch.setattr(
        sys, "argv", [str(SCRIPT), "--dry-run", "--units", str(units_file), "--examples", str(examples_file), "--out", str(out)]
    )
    monkeypatch.setattr(trace.subprocess, "run", lambda *a, **kw: pytest.fail("dry run spawned subprocess"))
    monkeypatch.setattr(trace, "write_json", lambda *a: pytest.fail("dry run wrote JSON"))
    assert trace.main() == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["pins"] == 2 and plan["runnable_pins"] == 1
    assert out.exists() == existing
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in out.glob("*")} == before


def test_trace_real_unsupported_run_then_typescript_opt_in_replans(tmp_path, monkeypatch, capsys):
    u = unit(file="app.ts")
    example = {**u, "id": "a", "candidate": "app.ts::run", "source": "population-v1"}
    units_file, examples_file, out = tmp_path / "units.jsonl", tmp_path / "examples.jsonl", tmp_path / "results"
    units_file.write_text(json.dumps(u) + "\n")
    examples_file.write_text(json.dumps(example) + "\n")
    argv = [str(SCRIPT), "--units", str(units_file), "--examples", str(examples_file), "--out", str(out)]
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(trace, "freeze_source", lambda target: {})
    monkeypatch.setattr(trace.subprocess, "run", lambda *a, **kw: pytest.fail("unsupported run invoked Docker"))
    assert trace.main() == 0
    result_file = out / trace.pin_name(u)
    first = json.loads(result_file.read_text())
    assert first["done"] and first["units"][0]["status"] == "unsupported"
    assert trace.make_plan(trace.join_units([u], [example]), out) == []

    called = []

    def run_pin(pin, source, provenance, inputs, results, args):
        called.append(pin)
        trace.save_pin(
            results / trace.pin_name(pin), {**pin, "done": True, "units": [trace.unit_record(r, "asked-nothing") for r in pin["units"]]}
        )
        return False

    def inspect_image(command, **kwargs):
        assert command[:3] == ["docker", "image", "inspect"]
        return subprocess.CompletedProcess(command, 0, "sha256:fake\n", "")

    monkeypatch.setattr(trace, "run_pin", run_pin)
    monkeypatch.setattr(trace.subprocess, "run", inspect_image)
    monkeypatch.setattr(sys, "argv", [*argv, "--include-typescript"])
    assert trace.main() == 0
    assert len(called) == 1 and called[0]["units"][0]["supported"]
    assert called[0]["selection"] != first["selection"]
    assert json.loads(result_file.read_text())["units"][0]["status"] == "asked-nothing"
    assert trace.make_plan(trace.join_units([u], [example], include_typescript=True), out, include_typescript=True) == []


def test_trace_resume_identity_includes_selection_even_if_support_unchanged(tmp_path):
    first = trace.make_plan([unit()], tmp_path)[0]
    trace.save_pin(tmp_path / trace.pin_name(first), {**first, "done": True})
    assert trace.make_plan([unit()], tmp_path) == []
    assert len(trace.make_plan([unit()], tmp_path, include_typescript=True)) == 1


@pytest.mark.parametrize("binary", sorted(worker.FRONTENDS))
def test_fast_frontend_validates_exact_output(tmp_path, binary):
    frontend = tmp_path / binary
    frontend.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys, time\n"
        "source = pathlib.Path(sys.argv[1])\n"
        "print('read bytes:', len(source.read_bytes()), flush=True)\n"
        "time.sleep(2 if pathlib.Path(sys.argv[0]).name == 'php2cpg' else 0)\n"
        "pathlib.Path(sys.argv[3]).write_bytes(b'x' * 34000)\n"
    )
    frontend.chmod(0o755)
    (tmp_path / "source.php").write_text("<?php echo 'hello';")
    backend = worker.MeasuredBackend(30, 10, lambda: None)
    flag = "--output" if binary == "joern-parse" else "-o"
    done = backend._run([str(frontend), "source.php", flag, "out.graph"], timeout=10, cwd=tmp_path)
    assert done.returncode == 0
    assert "read bytes: 19" in done.stdout
    assert not backend.fatal
    stage = backend.stages[0]
    assert stage["seconds"] < 5
    if binary == "php2cpg":
        assert stage["seconds"] >= 2
    assert stage["cpg_path"] == str(tmp_path / "out.graph")
    assert stage["cpg_bytes"] == 34000
    proof = {"files": ["source.php"], "bytes": 19, **stage, "jvm": backend.stages}
    assert worker.instrument_failure(proof) == ""


@pytest.mark.parametrize("size", [None, 0, 1024])
def test_frontend_without_sufficient_output_fails(tmp_path, size):
    frontend = tmp_path / "php2cpg"
    frontend.write_text(
        f"#!{sys.executable}\nimport pathlib, sys\n"
        + (f"pathlib.Path(sys.argv[2]).write_bytes(b'x' * {size})\n" if size is not None else "")
    )
    frontend.chmod(0o755)
    # A different non-empty CPG must not mask the missing requested output.
    (tmp_path / "unrelated.bin").write_bytes(b"x" * 34000)
    backend = worker.MeasuredBackend(30, 10, lambda: None)
    done = backend._run([str(frontend), "-o", "out.bin"], timeout=10, cwd=tmp_path)
    assert done.returncode == 1
    assert backend.stages[0]["exit"] == 0
    assert backend.stages[0]["cpg_bytes"] == (size or 0)
    assert backend.fatal == "frontend wrote no CPG"


def test_fast_joern_script_is_failed_launch(tmp_path):
    joern = tmp_path / "joern"
    joern.write_text(f"#!{sys.executable}\n")
    joern.chmod(0o755)
    backend = worker.MeasuredBackend(30, 10, lambda: None)
    done = backend._run([str(joern), "--script", "query.sc"], timeout=10, cwd=tmp_path)
    assert done.returncode == 1
    assert backend.stages[0]["exit"] == 0
    assert "implausibly fast JVM step" in backend.fatal


@pytest.mark.parametrize("markers", [[], ["a"], ["a", "b"]])
def test_empty_answers_require_each_question_marker(tmp_path, monkeypatch, markers):
    class EmptyBackend(FakeBackend):
        def build(self, root, language):
            cpg = super().build(root, language)
            batch = cpg.run_batch_once

            def empty_batch(query, requests):
                answers = batch(query, requests)
                self.asked = markers
                return {**answers, **dict.fromkeys(requests, [])}

            return replace(cpg, run_batch_once=empty_batch)

    result = run_fake(tmp_path, monkeypatch, EmptyBackend)
    for row in result["units"]:
        assert row["status"] == ("asked-nothing" if row["unit"] in markers else "failed")
        assert row["reason"] == ("" if row["unit"] in markers else "query produced no markers")


def test_frontend_measurement_survives_failed_build_cleanup(tmp_path, monkeypatch):
    class CleanupBackend(worker.MeasuredBackend):
        def build(self, root, language):
            frontend = root / "php2cpg"
            frontend.write_text(
                f"#!{sys.executable}\nimport pathlib, sys\npathlib.Path(sys.argv[2]).write_bytes(b'x' * 34000)\nsys.exit(1)\n"
            )
            frontend.chmod(0o755)
            self._run([str(frontend), "-o", "actual.graph"], timeout=10, cwd=root)
            (root / "actual.graph").unlink()
            return None

    result = run_fake(tmp_path, monkeypatch, CleanupBackend)
    assert all(row["status"] == "failed" for row in result["units"])
    assert result["instrument"]["cpg_path"] == str(tmp_path / "actual.graph")
    assert result["instrument"]["cpg_bytes"] == 34000
    assert not (tmp_path / "actual.graph").exists()
