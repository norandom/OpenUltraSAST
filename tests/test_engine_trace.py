"""Offline controls for the trace experiment; no Docker, Joern or network."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from openultrasast.cpg.backend import BEGIN, END, CpgResult, JoernBackend
from openultrasast.model.specs import taint_specs
from openultrasast.model.taint import request_params

SCRIPT = Path(__file__).resolve().parents[1] / "benchmarks/learn/engine_trace.py"
_spec = importlib.util.spec_from_file_location("engine_trace", SCRIPT)
assert _spec and _spec.loader
trace = importlib.util.module_from_spec(_spec)
with pytest.MonkeyPatch.context() as patch:
    patch.syspath_prepend(str(SCRIPT.parent))
    from engine_trace_parse import parse_trace

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


@pytest.mark.parametrize("json_roundtrip", [False, True])
def test_worker_writes_string_requests_for_php_and_python(tmp_path, monkeypatch, json_roundtrip):
    written = {}
    submitted = {}

    class RequestBackend(worker.MeasuredBackend):
        def build(self, root, language):
            graph = root / f"{language}.bin"
            graph.write_bytes(b"x" * 2048)
            self.stages.append({"command": "joern-parse", "seconds": 20, "exit": 0, "cpg_bytes": 2048})

            def batch(query, requests):
                submitted.update(requests)
                return self._batch_once(graph, query, requests)

            return CpgResult(graph, lambda q, p: None, run_batch_once=batch)

        def _run(self, command, **kwargs):
            request_file = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("requestsFile=")))
            data = request_file.read_bytes()
            print(f"read {request_file.name}: {len(data)} bytes")
            requests = json.loads(data)
            written.update(requests)
            self.asked.extend(requests)
            self.stages.append({"command": "joern", "seconds": 20, "exit": 0})
            answers = {**dict.fromkeys(requests, []), "__census__": [{"files": "1", "file_names": ["app.php", "app.py"]}]}
            return subprocess.CompletedProcess(command, 0, BEGIN + "\n" + json.dumps(answers) + "\n" + END, "")

    monkeypatch.setattr(worker, "MeasuredBackend", RequestBackend)
    (tmp_path / "app.php").write_text("<?php function run() {}\n")
    (tmp_path / "app.py").write_text("def run(): pass\n")
    pin = {"units": [unit("php", language="php", file="app.php"), unit("python")]}
    pin["questions"] = trace.prepare_questions(pin, tmp_path, 120)
    assert all(isinstance(params["sources"], tuple) and params["sources"] for params in pin["questions"].values())
    expected = {rid: ",".join(sorted(params["sources"])) for rid, params in pin["questions"].items()}
    # Cover both direct tuple callers and arrays decoded from the host's pin.json.
    if json_roundtrip:
        pin = json.loads(json.dumps(pin))
    out = tmp_path / "result.json"
    worker.worker(pin, tmp_path, out, 900, 120)
    result = json.loads(out.read_text())
    assert all(row["status"] == "asked-nothing" for row in result["units"])
    assert set(written) == set(submitted) == {"php", "python"}
    for requests in (written, submitted, {rid: p for row in result["units"] for rid, p in row["questions"].items()}):
        assert all(isinstance(value, str) for params in requests.values() for value in params.values())
        assert {rid: params["sources"] for rid, params in requests.items()} == expected


def test_failed_query_records_non_stack_stderr_tail_in_unit_reason(tmp_path, monkeypatch):
    error = 'ujson.Value$InvalidData: Expected ujson.Str (data: ["$_COOKIE","$_GET"])'
    joern = tmp_path / "joern"
    joern.write_text(
        f"#!{sys.executable}\nimport sys\n"
        "print('read bytes:', len(open(sys.argv[-1], 'rb').read()), flush=True)\n"
        "for i in range(25): print(f'diagnostic {i}', file=sys.stderr)\n"
        f"print({error!r}, file=sys.stderr)\n"
        "for i in range(30): print(f'\\tat example.Frame.method(Frame.java:{i})', file=sys.stderr)\n"
        "print('\\t... 30 more', file=sys.stderr)\n"
        "sys.exit(1)\n"
    )
    joern.chmod(0o755)

    class FailedQueryBackend(worker.MeasuredBackend):
        def build(self, root, language):
            graph = root / "graph.bin"
            graph.write_bytes(b"x" * 2048)
            self.stages.append({"command": "joern-parse", "seconds": 20, "exit": 0, "cpg_bytes": 2048})

            def batch(query, requests):
                done = self._run([str(joern), "--script", str(root / "app.py")], timeout=10, cwd=root)
                assert done.returncode == 1
                assert "read bytes: 20" in done.stdout
                return None

            return CpgResult(graph, lambda q, p: None, run_batch_once=batch)

    result = run_fake(tmp_path, monkeypatch, FailedQueryBackend)
    stage = result["instrument"]["jvm"][-1]
    assert stage["exit"] == 1
    assert stage["output_tail"].splitlines() == [*[f"diagnostic {i}" for i in range(6, 25)], error]
    for row in result["units"]:
        assert row["status"] == "failed"
        assert "joern query exited 1" in row["reason"]
        assert error in row["reason"]
        assert "Frame.java" not in row["reason"]
        assert "implausibly fast" not in row["reason"]


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
    assert "benchmarks/learn/engine_trace_parse.py" in trace.SNAPSHOT_FILES


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
    examples = [{**u, "id": "a", "candidate": "app.py::run", "source": "population-v1", "excerpt": False}]
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


def test_failed_launch_persists_failed_pin_and_resume_replans_it(tmp_path, monkeypatch):
    from types import SimpleNamespace

    class Inputs:
        def materialize(self, pin, target):
            target.mkdir()
            (target / "app.py").write_text("def run():\n    pass\n")
            return {"mode": "source"}

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
    assert len(trace.make_plan([unit()], tmp_path)) == 1
    assert trace.make_plan([unit()], tmp_path, rerun_status=()) == []


def import_container_worker():
    """Import in a fresh interpreter so host imports cannot mask the boundary."""
    script = SCRIPT.with_name("engine_trace_worker.py")
    code = """
import json, pathlib, runpy, sys
sys.modules['yaml'] = None
sys.modules['boto3'] = None
script = pathlib.Path(sys.argv[1])
size = len(script.read_bytes())
# Direct script execution in the image puts the sibling modules on sys.path.
sys.path.insert(0, str(script.parent))
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
    examples = [{**u, "id": u["unit"], "candidate": u["file"] + "::run", "source": "population-v1", "excerpt": False} for u in units]
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
    example = {**u, "id": "a", "candidate": "app.ts::run", "source": "population-v1", "excerpt": False}
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
    progress = json.loads((out / "progress.json").read_text())
    assert progress == {
        "pins_done": 1,
        "pins_total": 1,
        "last_pin": {"repo": u["repo"], "pin": u["pin"]},
        "statuses": {"unsupported": 1},
        "lanes": {"docker": 1},
        "pins_in_flight": 0,
        "active_lanes": {},
    }
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
    assert trace.make_plan([unit()], tmp_path, rerun_status=()) == []
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


def pair_inputs(tmp_path):
    from types import SimpleNamespace

    inputs = trace.Inputs(trace.ROOT, tmp_path / "cache")
    excerpt = tmp_path / "excerpt.py"
    excerpt.write_text("# commit: " + "f" * 40 + "\n# parent: " + "f" * 40 + "\ndef run(): pass\n")
    case = SimpleNamespace(name="fixture", repo="owner/repo", relpath="pkg/app.py", vuln_file=excerpt, fixed_file=excerpt, context_files=())
    inputs.catalog_rows[case.name] = [
        ("advisory-fixes-2", {"repo": case.repo, "relpath": case.relpath, "parent": "a" * 40, "commit": "b" * 40})
    ]
    return inputs, case


@pytest.mark.parametrize("side,sha", [("vuln", "a" * 40), ("fixed", "b" * 40)])
def test_pair_materializes_catalog_side_not_header(tmp_path, monkeypatch, side, sha):
    inputs, case = pair_inputs(tmp_path)
    case.vuln_file.write_text("# Provenance: example\n    def run(self): pass\n")
    fetched = tmp_path / "fetched"
    (fetched / "pkg").mkdir(parents=True)
    (fetched / case.relpath).write_text("class Handler:\n    def run(self): pass\n")
    calls = []

    def fetch(repo, commit, roots):
        calls.append((repo, commit, roots))
        return fetched

    monkeypatch.setattr(inputs, "fetch_source", fetch)
    monkeypatch.setattr(inputs, "pair_for", lambda row: (case, side))
    target = tmp_path / "export"
    proof = inputs.materialize({"units": [unit(file=case.relpath)]}, target)
    assert calls == [("owner/repo", sha, ["pkg"])]
    assert proof["commit"] == sha and proof["mode"] == "source"
    assert (target / case.relpath).read_text().startswith("class Handler:")


@pytest.mark.parametrize("change", [{"parent": ""}, {"parent": "b" * 40}, {"commit": "HEAD"}])
def test_catalog_ambiguous_commits_refused(tmp_path, change):
    inputs, case = pair_inputs(tmp_path)
    inputs.catalog_rows[case.name][0][1].update(change)
    with pytest.raises(ValueError, match="ambiguous catalog commits"):
        inputs.source_identity(case, "vuln")


def test_ambiguous_catalog_and_side_refused(tmp_path):
    inputs, case = pair_inputs(tmp_path)
    inputs.catalog_rows[case.name] *= 2
    with pytest.raises(ValueError, match="ambiguous catalog source"):
        inputs.source_identity(case, "fixed")
    with pytest.raises(ValueError, match="ambiguous pair side"):
        inputs.pair_for(unit(pin_role="unknown"))


def test_sparse_export_filters_languages_dirs_and_caps_context(tmp_path):
    source, target = tmp_path / "source", tmp_path / "export"
    contents = {
        "pkg/app.py": "def run(): pass\n",
        "pkg/context.py": "x" * 200,
        "pkg/other.js": "function run() {}",
        "other/app.py": "other",
    }
    contents.update({f"pkg/{directory}/a.py": "excluded" for directory in worker.EXCLUDED_DIRS})
    for rel, data in contents.items():
        path = source / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
    proof = trace.export_sources(source, target, [unit(file="pkg/app.py")], ["pkg"], cap=50)
    assert [p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()] == ["pkg/app.py"]
    assert proof["cap_hit"] and proof["bytes"] == len(contents["pkg/app.py"])
    assert proof["excludes"] == sorted(worker.EXCLUDED_DIRS)
    assert trace.source_root("module/src/main/java/org/Handler.java", "java") == "module/src/main/java"
    assert trace.source_root("pkg/sub/app.ts", "typescript") == "pkg"
    assert trace.source_root("app.js", "javascript") == "."


def test_wrong_fetched_function_fails_without_fallback(tmp_path, monkeypatch):
    inputs, case = pair_inputs(tmp_path)
    source = tmp_path / "source"
    (source / "pkg").mkdir(parents=True)
    (source / case.relpath).write_text("def runner(): pass\n")
    inputs.allow_excerpt_fallback = True
    monkeypatch.setattr(inputs, "pair_for", lambda row: (case, "vuln"))
    monkeypatch.setattr(inputs, "fetch_source", lambda *args: source)
    with pytest.raises(ValueError, match="labelled function not found in fetched source"):
        inputs.materialize({"units": [unit(file=case.relpath)]}, tmp_path / "export")


def test_excerpt_fallback_requires_explicit_flag(tmp_path, monkeypatch):
    inputs, case = pair_inputs(tmp_path)
    monkeypatch.setattr(inputs, "pair_for", lambda row: (case, "vuln"))

    def unavailable(*args):
        raise ValueError("fetch failed")

    monkeypatch.setattr(inputs, "fetch_source", unavailable)
    pin = {"units": [unit(file=case.relpath)]}
    with pytest.raises(ValueError, match="fetch failed"):
        inputs.materialize(pin, tmp_path / "export")
    inputs.allow_excerpt_fallback = True
    proof = inputs.materialize(pin, tmp_path / "fallback")
    assert proof["mode"] == "excerpt-fallback" and proof["reason"] == "fetch failed"


def test_fetch_renders_sparse_pinned_host_commands(tmp_path, monkeypatch):
    inputs, _ = pair_inputs(tmp_path)
    commands = []

    def git(cmd, **kwargs):
        commands.append(cmd[3:])
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
        assert "GIT_NO_LAZY_FETCH" not in kwargs["env"]
        return subprocess.CompletedProcess(cmd, 0, "a" * 40 + "\n", "")

    monkeypatch.setattr(trace.subprocess, "run", git)
    clone = inputs.fetch_source("owner/repo", "a" * 40, ["module/src/main/java"])
    assert clone.is_relative_to(inputs.cache)
    assert ["fetch", "--depth", "1", "--filter=blob:none", "https://github.com/owner/repo.git", "a" * 40] in commands
    assert ["sparse-checkout", "set", "--", "module/src/main/java"] in commands
    assert ["checkout", "--detach", "--force", "a" * 40] in commands


def test_explicit_heap_in_frontend_and_query_commands(tmp_path, monkeypatch):
    backend = worker.MeasuredBackend(900, 120, lambda: None)
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, BEGIN + '\n{"r": []}\n' + END, "")

    monkeypatch.setattr(backend, "_run", run)
    monkeypatch.setattr("openultrasast.cpg.backend.shutil.which", lambda name: "/opt/joern-cli/" + name)
    graph = tmp_path / "cpg.bin"
    graph.write_bytes(b"x" * 2048)
    backend._build_with_frontend(tmp_path, graph, tmp_path, "python")
    backend._batch_once(graph, "taint", {"r": {}})
    assert {Path(cmd[0]).name for cmd in commands} == {"pysrc2cpg", "joern"}
    assert all("-J-Xmx2560m" in cmd for cmd in commands)
    assert "-Xmx2560m" in backend._jvm_env()["JAVA_TOOL_OPTIONS"]


@pytest.mark.parametrize("binary", ["pysrc2cpg", "joern"])
def test_oom_output_overrides_missing_graph_or_markers(tmp_path, binary):
    launcher = tmp_path / binary
    launcher.write_text(f"#!{sys.executable}\nprint('java.lang.OutOfMemoryError: Java heap space')\n")
    launcher.chmod(0o755)
    backend = worker.MeasuredBackend(30, 10, lambda: None)
    done = backend._run([str(launcher), "--script", "query.sc"], timeout=10)
    assert done.returncode == 1
    assert backend.fatal == "JVM out of memory"
    assert worker.instrument_failure({"jvm": backend.stages}) == "JVM out of memory"


def test_two_language_pin_builds_sequential_frontends_and_routes_questions(tmp_path, monkeypatch):
    events = []

    class LanguagesBackend(FakeBackend):
        def build(self, root, language):
            events.append(("build", language))
            graph = root / (language + ".bin")
            graph.write_bytes(b"x" * 2048)
            self.stages = [
                {"command": {"python": "pysrc2cpg", "javascript": "jssrc2cpg"}[language], "seconds": 20, "exit": 0, "cpg_bytes": 2048}
            ]

            def batch(query, requests):
                events.append(("query", language, sorted(requests)))
                self.asked.extend(requests)
                return {
                    **dict.fromkeys(requests, []),
                    "__census__": [{"files": "1", "file_names": ["app.py" if language == "python" else "app.js"]}],
                }

            return CpgResult(graph, lambda q, p: None, run_batch_once=batch, cleanup=lambda: events.append(("cleanup", language)))

    monkeypatch.setattr(worker, "MeasuredBackend", LanguagesBackend)
    (tmp_path / "app.py").write_text("def run(): pass\n")
    (tmp_path / "app.js").write_text("function run() {}\n")
    pin = {"units": [unit(), unit("js", language="javascript", file="app.js")]}
    pin["questions"] = trace.prepare_questions(pin, tmp_path, 120)
    assert all(params["callDepth"] == "3" for params in pin["questions"].values())
    result = worker.worker(pin, tmp_path, tmp_path / "result.json", 900, 120)
    assert events == [
        ("build", "javascript"),
        ("query", "javascript", ["js"]),
        ("cleanup", "javascript"),
        ("build", "python"),
        ("query", "python", ["a"]),
        ("cleanup", "python"),
    ]
    assert all(u["status"] == "asked-nothing" for u in result["units"])
    assert set(result["instruments"]) == {"python", "javascript"}
    assert all(u["instrument"]["heap_mb"] == 2560 for u in result["units"])


def test_resume_materialization_version_and_status_selection(tmp_path):
    units = [unit(source="advisory-fixes-2"), unit("other", pin="other", source="population-v1")]
    pin = trace.make_plan(units, tmp_path, only_source={"advisory-fixes-2"})[0]
    record = {**pin, "done": True, "units": [trace.unit_record(pin["units"][0], "asked-nothing")]}
    path = tmp_path / trace.pin_name(pin)
    trace.write_json(path, record)
    assert trace.make_plan(units, tmp_path, only_source={"advisory-fixes-2"}) == []
    assert len(trace.make_plan(units, tmp_path, only_source={"advisory-fixes-2"}, rerun_status={"failed", "asked-nothing"})) == 1
    trace.write_json(path, {**record, "materialization_version": trace.MATERIALIZATION_VERSION - 1})
    assert len(trace.make_plan(units, tmp_path, only_source={"advisory-fixes-2"})) == 1


def test_sparse_fetch_from_local_git_without_network(tmp_path, monkeypatch):
    origin = tmp_path / "origin"
    origin.mkdir()
    real_run = subprocess.run

    def git(*args):
        return real_run(["git", "-C", str(origin), *args], capture_output=True, text=True, check=True).stdout.strip()

    git("init")
    git("config", "user.name", "Offline Test")
    git("config", "user.email", "offline@example.invalid")
    for rel in ("module/src/main/java/Handler.java", "module/src/main/java/docs/Other.java", "elsewhere/Other.java"):
        path = origin / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("class Handler { void run() {} }\n")
    git("add", ".")
    git("commit", "-m", "local fixture")
    sha = git("rev-parse", "HEAD")
    inputs, _ = pair_inputs(tmp_path)

    def local_only(cmd, **kwargs):
        # Substitute a local repository for the one URL; no network-capable command runs.
        cmd = [str(origin) if arg == "https://github.com/owner/repo.git" else arg for arg in cmd]
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(trace.subprocess, "run", local_only)
    clone = inputs.fetch_source("owner/repo", sha, ["module/src/main/java"])
    assert not (clone / "elsewhere/Other.java").exists()
    target = tmp_path / "export"
    labelled = unit(file="module/src/main/java/Handler.java", language="java")
    proof = trace.export_sources(clone, target, [labelled], ["module/src/main/java"])
    trace.verify_functions(target, [labelled])
    assert proof["files"] == 1 and proof["bytes"] > 0


@pytest.mark.parametrize("side", ["vuln", "fixed"])
def test_complete_catalog_twins_and_context_need_no_commits(tmp_path, monkeypatch, side):
    inputs, case = pair_inputs(tmp_path)
    inputs.catalog_rows[case.name][0][1].update(parent="", commit="")
    fixed = tmp_path / "fixed.py"
    fixed.write_text("def run(): return 'fixed'\n")
    case.fixed_file = fixed
    context = tmp_path / "context.py"
    context.write_text("registered = True\n")
    case.context_files = (("pkg/context.py", context, context),)
    monkeypatch.setattr(inputs, "pair_for", lambda row: (case, side))
    monkeypatch.setattr(inputs, "fetch_source", lambda *args: pytest.fail("catalog files must not fetch"))
    target = tmp_path / "export"
    proof = inputs.materialize({"units": [unit(file=case.relpath)]}, target)
    assert proof["mode"] == "catalog-file"
    assert (target / case.relpath).read_bytes() == (fixed if side == "fixed" else case.vuln_file).read_bytes()
    assert (target / "pkg/context.py").read_bytes() == context.read_bytes()


@pytest.mark.parametrize(
    "body,reason",
    [
        ("# Provenance: example upstream_start: 25\n    def run():\n        return (\n", "excerpt does not parse:.*never closed"),
        ("def run(:\n", "not complete Python"),
    ],
)
def test_incomplete_catalog_without_commits_fails_specifically(tmp_path, monkeypatch, body, reason):
    inputs, case = pair_inputs(tmp_path)
    inputs.catalog_rows[case.name][0][1].update(parent="", commit="")
    case.vuln_file.write_text(body)
    monkeypatch.setattr(inputs, "pair_for", lambda row: (case, "vuln"))
    with pytest.raises(ValueError, match=reason):
        inputs.materialize({"units": [unit(file=case.relpath)]}, tmp_path / "export")


@pytest.mark.parametrize("comment,newline", [("#", "\n"), ("//", "\n"), ("#", "\r\n")])
@pytest.mark.parametrize("upstream", [True, False])
def test_parseable_python_method_excerpt_is_in_function_only(tmp_path, monkeypatch, comment, newline, upstream):
    inputs, case = pair_inputs(tmp_path)
    inputs.catalog_rows[case.name][0][1].update(parent="", commit="")
    header = f"{comment} Provenance: example\n" + (f"{comment} upstream_start: 25\n" if upstream else "")
    body = header + "\n    def run(self, cmd):\n        os.system(cmd)\n"
    case.vuln_file.write_bytes(body.replace("\n", newline).encode())
    monkeypatch.setattr(inputs, "pair_for", lambda row: (case, "vuln"))
    monkeypatch.setattr(inputs, "fetch_source", lambda *args: pytest.fail("excerpt attempted fetch"))
    pin = {"units": [unit(file=case.relpath)]}
    target = tmp_path / "export"
    pin["materialization"] = inputs.materialize(pin, target)
    assert pin["materialization"]["mode"] == "excerpt-parseable"
    assert (target / case.relpath).read_text() == header.replace("//", "#") + "\ndef run(self, cmd):\n    os.system(cmd)\n"
    assert trace.unit_record(pin["units"][0], "path")["evidence_scope"] == "in-function-only"
    params = trace.prepare_questions(pin, target, 60)["a"]
    assert params["callDepth"] == "0" and params["parameterSources"] == "true"


def test_java_fragment_is_not_parseable_excerpt(tmp_path, monkeypatch):
    inputs, case = pair_inputs(tmp_path)
    inputs.catalog_rows[case.name][0][1].update(parent="", commit="")
    case.relpath = "pkg/App.java"
    case.vuln_file = case.fixed_file = tmp_path / "excerpt.java"
    case.vuln_file.write_text("// Provenance: example\n// upstream_start: 25\n    public void run() {\n        execute(cmd);\n")
    inputs.catalog_rows[case.name][0][1]["relpath"] = case.relpath
    monkeypatch.setattr(inputs, "pair_for", lambda row: (case, "vuln"))
    with pytest.raises(ValueError, match="excerpt does not parse:"):
        inputs.materialize({"units": [unit(file=case.relpath, language="java")]}, tmp_path / "export")


def test_excerpt_without_cheap_parser_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr("openultrasast.semantic.extra.grammar_for", lambda language: None)
    with pytest.raises(ValueError, match="excerpt does not parse: no cheap parser for javascript"):
        trace.parseable_excerpt(tmp_path / "app.js", "// Provenance: example upstream_start: 25\nfunction run() {}\n")


def test_parseable_javascript_excerpt_uses_repository_parser(tmp_path):
    from openultrasast.semantic.extra import grammar_for

    if grammar_for("javascript") is None:
        pytest.skip("optional JavaScript grammar unavailable")
    assert (
        trace.parseable_excerpt(tmp_path / "app.js", "// Provenance: example\n    function run(cmd) { execute(cmd); }\n")
        == "// Provenance: example\nfunction run(cmd) { execute(cmd); }\n"
    )


def test_export_keeps_labels_over_cap_and_excluded_ancestors(tmp_path):
    source, target = tmp_path / "source", tmp_path / "export"
    for rel in ("templates/preferences.php", "templates/other.php", "other.php"):
        path = source / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("<?php function run() {}\n")
    proof = trace.export_sources(source, target, [unit(file="templates/preferences.php", language="php")], cap=1)
    assert (target / "templates/preferences.php").read_bytes() == (source / "templates/preferences.php").read_bytes()
    assert not (target / "templates/other.php").exists()
    assert proof["cap_hit"] and proof["bytes"] > proof["cap_bytes"]


def test_oversized_package_narrows_before_truncation_and_keeps_import(tmp_path):
    source, target = tmp_path / "source", tmp_path / "export"
    for rel, body in {
        "pkg/sub/app.py": "from helper import value\ndef run(): pass\n",
        "pkg/sub/context.py": "x = 1\n",
        "pkg/huge.py": "#" * 500,
        "helper.py": "value = 1\n",
    }.items():
        path = source / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    proof = trace.export_sources(source, target, [unit(file="pkg/sub/app.py")], ["pkg"], cap=100)
    assert proof["roots"] == ["pkg/sub"] and proof["requested_roots"] == ["pkg"]
    assert proof["scope_narrowed"] and not proof["cap_hit"]
    assert (target / "helper.py").exists() and (target / "pkg/sub/context.py").exists()
    assert not (target / "pkg/huge.py").exists()


def test_local_repository_export_scopes_packages(tmp_path, monkeypatch):
    inputs, _ = pair_inputs(tmp_path)

    def export(clone, pin, dest):
        for rel in ("packages/server/run.js", "packages/other/skip.js"):
            path = dest / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("function run() {}\n")

    monkeypatch.setattr(trace, "export_pin", export)
    proof = inputs.export_local(
        tmp_path, {"pin": "sha", "units": [unit(file="packages/server/run.js", language="javascript")]}, tmp_path / "out"
    )
    assert proof["roots"] == ["packages/server"]
    assert not (tmp_path / "out/packages/other/skip.js").exists()


def test_census_membership_is_uncapped_and_warning_is_not_absence(tmp_path, monkeypatch):
    class LargeBackend(FakeBackend):
        def build(self, root, language):
            cpg = super().build(root, language)
            original = cpg.run_batch_once

            def batch(query, requests):
                result = original(query, requests)
                result["__census__"] = [{"files": "3001", "file_names": [f"f{i}.py" for i in range(3000)] + ["/case/app.py"]}]
                return result

            return replace(cpg, run_batch_once=batch, unparsed=("app.py",))

    result = run_fake(tmp_path, monkeypatch, LargeBackend)
    assert [u["status"] for u in result["units"]] == ["path", "asked-nothing"]
    for name in ("census.sc", "taint.sc"):
        assert '"file_names" -> ujson.Arr.from(cpg.file.name.l)' in (trace.ROOT / "src/openultrasast/cpg/queries" / name).read_text()


def test_absent_label_includes_frontend_parse_log(tmp_path, monkeypatch):
    class MissingBackend(FakeBackend):
        def build(self, root, language):
            cpg = super().build(root, language)
            self.stages[0]["labelled_file_logs"] = {"app.py": ["Failed to parse app.py: invalid syntax"]}

            def batch(query, requests):
                self.asked.extend(requests)
                return {**dict.fromkeys(requests, []), "__census__": [{"files": "1", "file_names": ["<unknown>"]}]}

            return replace(cpg, run_batch_once=batch)

    result = run_fake(tmp_path, monkeypatch, MissingBackend)
    assert all(u["status"] == "failed" and "Failed to parse app.py: invalid syntax" in u["reason"] for u in result["units"])


def test_frontend_retains_matching_log_lines(tmp_path):
    launcher = tmp_path / "pysrc2cpg"
    launcher.write_text(f"#!{sys.executable}\nprint('Failed to parse /case/pkg/app.py: syntax')\n")
    launcher.chmod(0o755)
    backend = worker.MeasuredBackend(30, 10, lambda: None)
    backend.labelled_files = ["pkg/app.py"]
    backend._run([str(launcher)], timeout=10)
    assert backend.stages[0]["labelled_file_logs"]["pkg/app.py"] == ["Failed to parse /case/pkg/app.py: syntax"]


@pytest.mark.parametrize("success", [True, False])
def test_engine_bug_retries_taint_only_once(tmp_path, monkeypatch, success):
    backend = worker.MeasuredBackend(900, 120, lambda: None)
    calls = []

    def batch(self, graph, query, requests):
        calls.append((self.queries_dir / "taint.sc").read_text())
        if len(calls) == 1:
            self.fatal = worker.ENGINE_BUG
            self.asked.append("stale")
            self.answers["stale"] = []
            return None
        assert not self.asked and not self.answers
        assert "enhance = false" in calls[-1]
        assert "requires saved dataflowOss overlay" in calls[-1]
        if success:
            return {"a": [], "__census__": [{"files": "1", "file_names": ["app.py"]}]}
        self.fatal = "joern query exited 1"
        return None

    monkeypatch.setattr(JoernBackend, "_batch_once", batch)
    result = backend._batch_once(tmp_path / "cpg.bin", "taint", {"a": {}})
    assert len(calls) == 2 and backend.retries[0]["completed"] == success
    assert (result is not None) == success
    assert backend.fatal == ("" if success else worker.ENGINE_BUG)
    if not success:
        backend._batch_once(tmp_path / "cpg.bin", "taint", {"a": {}})
        assert len(backend.retries) == 1


def test_named_engine_bug_from_process_output(tmp_path):
    launcher = tmp_path / "joern"
    launcher.write_text(
        f"#!{sys.executable}\nprint('Pass io.joern.x2cpg.frontendspecific.jssrc2cpg.ObjectPropertyCallLinker failed')\n"
        "print('java.lang.RuntimeException: Assignment statement with 3 arguments')\nraise SystemExit(1)\n"
    )
    launcher.chmod(0o755)
    backend = worker.MeasuredBackend(30, 10, lambda: None)
    backend._run([str(launcher), "--script", "query.sc"], timeout=10)
    assert backend.fatal == worker.ENGINE_BUG


def test_rerun_failed_and_timeout_only_preserves_completed_v2(tmp_path):
    units = [unit(status, pin=status) for status in trace.STATUSES]
    for pin in trace.make_plan(units, tmp_path):
        trace.save_pin(tmp_path / trace.pin_name(pin), {**pin, "done": True, "units": [trace.unit_record(pin["units"][0], pin["pin"])]})
    assert {p["pin"] for p in trace.make_plan(units, tmp_path, rerun_status={"failed", "timeout"})} == {"failed", "timeout"}


def test_successful_retry_keeps_result_and_records_attempt(tmp_path, monkeypatch):
    class RetriedBackend(FakeBackend):
        def __init__(self, *args):
            super().__init__(*args)
            self.retries = [{"reason": worker.ENGINE_BUG, "mode": "taint-only", "completed": True}]
            self.stages.append({"command": "joern", "seconds": 20, "exit": 1, "output_tail": worker.ENGINE_BUG})

    result = run_fake(tmp_path, monkeypatch, RetriedBackend)
    assert [u["status"] for u in result["units"]] == ["path", "asked-nothing"]
    assert all(u["reason"] == "" for u in result["units"])
    assert result["instrument"]["retries"][0]["completed"]


def test_overlay_engine_bug_allows_one_taint_only_attempt(tmp_path, monkeypatch):
    backend = worker.MeasuredBackend(900, 120, lambda: None)

    def overlay(self, graph, scratch):
        self.fatal = worker.ENGINE_BUG
        return False

    monkeypatch.setattr(JoernBackend, "_apply_overlays", overlay)
    assert not backend._apply_overlays(tmp_path / "cpg.bin", tmp_path)
    assert backend.retry_pending and not backend.fatal

    def batch(self, graph, query, requests):
        assert "enhance = false" in (self.queries_dir / "taint.sc").read_text()
        return {"a": []}

    monkeypatch.setattr(JoernBackend, "_batch_once", batch)
    assert backend._batch_once(tmp_path / "cpg.bin", "taint", {"a": {}}) == {"a": []}
    assert len(backend.retries) == 1


def k8s_args(tmp_path, **overrides):
    from types import SimpleNamespace

    return SimpleNamespace(
        **{
            "executor": "k8s",
            "parallel": 2,
            "kube_context": "test-context",
            "kube_namespace": "ousast-engine",
            "image": "ghcr.io/norandom/openultrasast:2.0.1",
            "deadline": 900,
            "question_deadline": 120,
            "keep_jobs": False,
            "out": tmp_path,
            **overrides,
        }
    )


def test_kubernetes_manifests_keep_urls_in_secret(tmp_path):
    from engine_trace_k8s import BOOTSTRAP, manifests

    args = k8s_args(tmp_path)
    urls = {name: "https://store/" + name + "?signature=secret" for name in ("SOURCE_URL", "ANALYZER_URL", "RESULT_URL")}
    job, secret = manifests("job", "run", args, urls, {})
    spec = job["spec"]
    pod = spec["template"]["spec"]
    container = pod["containers"][0]
    assert spec["activeDeadlineSeconds"] == 900
    assert spec["backoffLimit"] == 0 and spec["ttlSecondsAfterFinished"] > 0
    assert pod["restartPolicy"] == "Never" and not pod["automountServiceAccountToken"]
    assert pod["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
    assert container["image"] == args.image
    assert pod["securityContext"] == {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000}
    assert {m["mountPath"] for m in container["volumeMounts"]} == {"/case", "/frozen", "/out"}
    assert all(v["emptyDir"] == {} for v in pod["volumes"])
    assert container["resources"] == {"requests": {"memory": "3Gi", "cpu": "1"}, "limits": {"memory": "3Gi"}}
    assert secret["stringData"] == urls
    assert all(url not in json.dumps(job) for url in urls.values())
    assert "boto3" not in BOOTSTRAP and "yaml" not in BOOTSTRAP
    compile(BOOTSTRAP, "<bootstrap>", "exec")


@pytest.mark.parametrize("failure", [False, True])
def test_kubernetes_host_pin_success_failure_and_cleanup(tmp_path, monkeypatch, failure):
    import io
    import tarfile

    from engine_trace_k8s import Kubernetes

    from openultrasast.plane.memory import S3Store

    objects, calls, expiries = {}, [], []

    class Client:
        def put(self, key, data, labels):
            objects[key] = data

        def get(self, key):
            return (objects[key], None) if key in objects else None

        def delete(self, key):
            objects.pop(key, None)

        def presign(self, method, key, expires):
            expiries.append(expires.total_seconds())
            return "https://store/" + key + "?secret"

    store = object.__new__(S3Store)
    store.client, store.prefix = Client(), "prefix"
    args = k8s_args(tmp_path)
    transport = Kubernetes(args, store)
    args.kubernetes = transport
    pin = trace.make_plan([unit()], tmp_path)[0]
    source = tmp_path / "frozen"
    source.mkdir()
    (source / "worker.py").write_text("print(42)")

    class Inputs:
        def materialize(self, pin, target):
            target.mkdir()
            (target / "app.py").write_text("def run(): pass")
            return {"bytes": 15, "files": 1}

    def kubectl(command, **kwargs):
        assert command[:5] == ["kubectl", "--context", "test-context", "--namespace", "ousast-engine"]
        calls.append(command[5:])
        action = command[5:]
        stdout = "{}"
        if action[0] == "create":
            manifest = json.loads(kwargs["input"])
            if manifest["kind"] == "Secret":
                assert manifest["metadata"]["ownerReferences"][0]["uid"] == "job-uid"
                for variable, filename in [("SOURCE_URL", "source.dat"), ("ANALYZER_URL", "analyzer.dat"), ("RESULT_URL", "result.dat")]:
                    assert manifest["stringData"][variable].split("?")[0].endswith("/" + filename)
            if manifest["kind"] == "Job":
                stdout = json.dumps({"metadata": {"uid": "job-uid"}})
                env = manifest["spec"]["template"]["spec"]["containers"][0]["env"]
                prepared = json.loads(next(e["value"] for e in env if e["name"] == "PIN"))
                result = {**prepared, "done": True, "units": [worker.unit_record(u, "asked-nothing", "") for u in prepared["units"]]}
                result_bytes = json.dumps(result).encode()
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w") as archive:
                    entry = tarfile.TarInfo("result.json")
                    entry.size = len(result_bytes)
                    archive.addfile(entry, io.BytesIO(result_bytes))
                source_key = next(key for key in objects if key.endswith("source.dat"))
                with tarfile.open(fileobj=io.BytesIO(objects[source_key])) as archive:
                    assert archive.extractfile("app.py").read() == b"def run(): pass"
                objects[source_key.replace("source.dat", "result.dat")] = stream.getvalue()
        if action[:2] == ["get", "job"]:
            stdout = json.dumps(
                {"status": {"conditions": [{"type": "Failed", "status": "True", "reason": "DeadlineExceeded"}]}}
                if failure
                else {"status": {"succeeded": 1}}
            )
        if action[:2] == ["get", "pods"]:
            stdout = json.dumps({"items": [{"spec": {"nodeName": "worker-1"}}]})
        if action[0] == "logs":
            assert "--tail=40" in action
            stdout = "last worker line https://store/private?secret"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(subprocess, "run", kubectl)
    monkeypatch.setattr(trace, "prepare_questions", lambda *a: {"a": {}})
    assert trace.run_pin(pin, source, {"head": "frozen"}, Inputs(), tmp_path, args) is failure
    result = json.loads((tmp_path / trace.pin_name(pin)).read_text())
    assert result["done"] and result["executor"] == "k8s" and result["node"] == "worker-1"
    assert result["analyzer"] == {"head": "frozen"}
    assert result["container_exit"] == int(failure)
    assert result["units"][0]["status"] == ("failed" if failure else "asked-nothing")
    if failure:
        assert "DeadlineExceeded" in result["units"][0]["reason"]
        assert "last worker line" in result["units"][0]["reason"]
        assert "?secret" not in json.dumps(result)
    else:
        assert trace.make_plan([unit()], tmp_path) == []
    assert not objects
    assert any(c[:2] == ["delete", "secret"] for c in calls)
    assert any(c[:2] == ["delete", "job"] for c in calls)
    assert min(expiries) >= args.deadline + 900


@pytest.mark.parametrize("executor,parallel", [("docker", 1), ("k8s", 2), ("mixed", 3)])
def test_scheduler_bounds_lanes_and_progress(tmp_path, monkeypatch, executor, parallel):
    import threading
    import time
    from collections import Counter

    active, peak = Counter(), Counter()
    lock = threading.Lock()
    args = k8s_args(tmp_path, executor=executor, parallel=parallel)
    plan = trace.make_plan([unit(str(i), str(i)) for i in range(9)], tmp_path)

    def run(pin, source, provenance, inputs, out, options):
        with lock:
            active[options.executor] += 1
            active["total"] += 1
            for key, value in active.items():
                peak[key] = max(peak[key], value)
        time.sleep(0.02)
        trace.save_pin(
            out / trace.pin_name(pin), {**pin, "done": True, "units": [worker.unit_record(u, "asked-nothing", "") for u in pin["units"]]}
        )
        with lock:
            active[options.executor] -= 1
            active["total"] -= 1
        return False

    monkeypatch.setattr(trace, "run_pin", run)
    assert not trace.run_plan(plan, None, {}, None, args)
    assert peak["total"] == parallel
    if executor == "mixed":
        assert peak["docker"] == 1 and peak["k8s"] == parallel - 1
    progress = json.loads((tmp_path / "progress.json").read_text())
    assert progress["pins_done"] == 9 and progress["pins_in_flight"] == 0
    assert sum(progress["lanes"].values()) == parallel
    assert trace.make_plan([unit(str(i), str(i)) for i in range(9)], tmp_path) == []


@pytest.mark.parametrize("keep", [False, True])
def test_k8s_check_roundtrip_and_retention(tmp_path, monkeypatch, capsys, keep):
    from engine_trace_k8s import Kubernetes

    from openultrasast.plane.memory import S3Store

    data, manifests_seen, commands = {}, [], []

    class Client:
        def put(self, key, body, labels):
            data[key] = body

        def get(self, key):
            return (b"x" * 1024, None)

        def delete(self, key):
            data.pop(key, None)

        def presign(self, method, key, expires):
            return "https://private/" + key

    store = object.__new__(S3Store)
    store.client, store.prefix = Client(), ""
    runner = Kubernetes(k8s_args(tmp_path, keep_jobs=keep), store)

    def fake(command, **kwargs):
        commands.append(command)
        action = command[5:]
        result = {}
        if kwargs.get("input"):
            manifest = json.loads(kwargs["input"])
            manifests_seen.append(manifest)
            result = {"metadata": {"uid": "check-uid"}}
        if action[:2] == ["get", "nodes"]:
            result = {"items": [{"metadata": {"name": "node"}, "status": {"allocatable": {"memory": "6000000Ki"}}}]}
        if action[:2] == ["get", "pods"]:
            result = {"items": [{"spec": {"nodeName": "node"}}]}
        if action[:2] == ["get", "job"]:
            result = {"status": {"succeeded": 1}}
        return subprocess.CompletedProcess(command, 0, json.dumps(result), "")

    monkeypatch.setattr(subprocess, "run", fake)
    assert runner.check() == 0
    text = capsys.readouterr().out
    assert "6000000Ki" in text and "1024" in text and "passed" in text
    assert "https://" not in text
    assert any(m["kind"] == "Namespace" for m in manifests_seen)
    job = next(m for m in manifests_seen if m["kind"] == "Job")
    assert {"name": "CHECK", "value": "1"} in job["spec"]["template"]["spec"]["containers"][0]["env"]
    assert bool(data) is keep
    assert any("delete" in c for c in commands) is not keep


@pytest.mark.parametrize("outcome", ["success", "timeout", "failure"])
def test_engine_queue_pin_persistence_resume_and_progress(tmp_path, monkeypatch, outcome):
    from engine_trace_queue import Dispatcher
    from engine_worker_service import Queue
    from test_engine_queue import FakeS3

    store = FakeS3()
    args = k8s_args(tmp_path, executor="queue", queue_timeout=2, image="image@sha256:abc")
    plan = trace.make_plan([unit()], tmp_path)

    class Inputs:
        def materialize(self, pin, target):
            target.mkdir()
            (target / "app.py").write_text("def run(): pass")
            return {"files": 1, "bytes": 15}

    def execute(client, task):
        return {
            **task["pin"],
            "done": True,
            "container_exit": 0,
            "units": [worker.unit_record(u, "asked-nothing") for u in task["pin"]["units"]],
        }

    queue = Queue(store, "pod-worker")
    if outcome == "timeout":
        ticks = iter([0, 3])
        args.dispatcher = Dispatcher(args, store, clock=lambda: next(ticks))
    else:
        args.dispatcher = Dispatcher(args, store, pause=lambda _: queue.process_one(execute))
    if outcome == "failure":

        def fail(*_):
            raise RuntimeError("credential-must-not-appear")

        monkeypatch.setattr(store, "put", fail)
    monkeypatch.setattr(trace, "prepare_questions", lambda *_: {"a": {}})
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: pytest.fail("queue must not launch Docker/kubectl"))
    assert trace.run_plan(plan, None, {"image": args.image}, Inputs(), args) is (outcome != "success")
    result = json.loads((tmp_path / trace.pin_name(plan[0])).read_text())
    assert result["executor"] == "queue"
    assert result["units"][0]["status"] == {"success": "asked-nothing", "timeout": "timeout", "failure": "failed"}[outcome]
    assert "credential-must-not-appear" not in json.dumps(result)
    if outcome == "success":
        assert result["worker"] == "pod-worker"
        assert trace.make_plan([unit()], tmp_path) == []
    else:
        assert trace.make_plan([unit()], tmp_path, rerun_status=("failed", "timeout"))
    progress = json.loads((tmp_path / "progress.json").read_text())
    assert progress["pins_done"] == 1 and progress["pins_in_flight"] == 0


@pytest.mark.parametrize("executor", ["ax", "mixed-ax"])
def test_ax_scheduler_requeues_oom_to_single_vm_lane(tmp_path, monkeypatch, executor):
    import threading
    import time
    from types import SimpleNamespace

    plan = trace.make_plan([unit(str(i), str(i)) for i in range(7)], tmp_path)
    args = SimpleNamespace(executor=executor, parallel=2, out=tmp_path, image="cluster", docker_image="vm")
    lock = threading.Lock()
    active = Counter()
    peak = Counter()
    attempts = []

    def run(pin, source, provenance, inputs, out, options):
        with lock:
            active[options.executor] += 1
            peak[options.executor] = max(peak[options.executor], active[options.executor])
            attempts.append((pin["pin"], options.executor, options.image))
        time.sleep(0.01)
        oom = options.executor == "ax"
        record = {
            **pin,
            "done": True,
            "units": [worker.unit_record(u, "failed" if oom else "path", "JVM out of memory" if oom else "") for u in pin["units"]],
        }
        if getattr(options, "fallback", None):
            record["fallback"] = options.fallback
        trace.write_json(out / trace.pin_name(pin), record)
        with lock:
            active[options.executor] -= 1
        return oom

    monkeypatch.setattr(trace, "run_pin", run)
    assert not trace.run_plan(plan, None, {}, None, args)
    assert peak["ax"] <= 2 and peak["docker"] == 1
    for pin in plan:
        record = json.loads((tmp_path / trace.pin_name(pin)).read_text())
        if (pin["pin"], "ax", "cluster") in attempts:
            assert record["fallback"] == "vm-oom"
            assert (pin["pin"], "docker", "vm") in attempts
    progress = json.loads((tmp_path / "progress.json").read_text())
    assert progress["pins_done"] == 7
    assert progress["statuses"] == {"path": 7}
    assert progress["pins_in_flight"] == 0


@pytest.mark.parametrize("timeout", [False, True])
def test_ax_run_pin_persists_worker_ip_timeout_and_resume(tmp_path, monkeypatch, timeout):
    pin = trace.make_plan([unit()], tmp_path)[0]
    calls = []

    class Inputs:
        def materialize(self, prepared, target):
            target.mkdir()
            (target / "app.py").write_text("def run(): pass")
            return {"files": 1, "bytes": 15}

    class Dispatcher:
        def execute(self, checkout, output, prepared, name):
            assert (checkout / "app.py").read_bytes() == b"def run(): pass"
            assert prepared["questions"] == {"a": {}}
            assert prepared["materialization"]["bytes"] == 15
            calls.append(name)
            if timeout:
                return None, "10.0.0.12"
            trace.write_json(
                output / "result.json",
                {**prepared, "done": True, "units": [worker.unit_record(u, "asked-nothing") for u in prepared["units"]]},
            )
            return subprocess.CompletedProcess([], 0, "", ""), "10.0.0.12"

    args = k8s_args(tmp_path, executor="ax", ax_dispatcher=Dispatcher(), image="registry/engine@sha256:" + "a" * 64)
    monkeypatch.setattr(trace, "prepare_questions", lambda *_: {"a": {}})
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: pytest.fail("AX run_pin must use dispatcher only"))
    assert trace.run_pin(pin, None, {"host": "unused"}, Inputs(), tmp_path, args) is timeout
    result = json.loads((tmp_path / trace.pin_name(pin)).read_text())
    assert calls == [trace.pin_name(pin)[:-5]]
    assert result["done"] and result["executor"] == "ax"
    assert result["worker_ip"] == result["worker"] == "10.0.0.12"
    assert result["analyzer"] == {"image": args.image, "code": "baked-in-image"}
    assert result["units"][0]["status"] == ("timeout" if timeout else "asked-nothing")
    assert result["container_exit"] == (None if timeout else 0)
    assert trace.make_plan([unit()], tmp_path, rerun_status=()) == []
    assert bool(trace.make_plan([unit()], tmp_path, rerun_status=("timeout",))) is timeout


@pytest.mark.parametrize("executor", ["ax", "mixed-ax"])
def test_ax_pending_fallback_resumes_in_docker_and_retains_attempt(tmp_path, monkeypatch, executor):
    pin = trace.make_plan([unit()], tmp_path)[0]
    attempt = {
        **pin,
        "done": True,
        "executor": "ax",
        "worker_ip": "10.0.0.12",
        "fallback": "vm-oom",
        "fallback_pending": True,
        "units": [worker.unit_record(u, "failed", "JVM out of memory") for u in pin["units"]],
    }
    trace.write_json(tmp_path / trace.pin_name(pin), attempt)
    resumed = trace.make_plan([unit()], tmp_path, rerun_status=())
    assert len(resumed) == 1
    calls = []

    class Inputs:
        def materialize(self, prepared, target):
            target.mkdir()
            (target / "app.py").write_text("def run(): pass")
            return {"files": 1, "bytes": 15}

    class Dispatcher:
        def execute(self, *_):
            pytest.fail("pending OOM fallback must not dispatch AX again")

    def docker(command, **kwargs):
        calls.append(command)
        assert command[:2] in (["docker", "run"], ["docker", "rm"])
        if command[1] == "run":
            assert command[command.index("--heap-profile") + 1] == "vm"
            assert "vm-image" in command
            output = Path(next(arg.removesuffix(":/out") for arg in command if arg.endswith(":/out")))
            prepared = json.loads((output / "pin.json").read_text())
            trace.write_json(
                output / "result.json",
                {**prepared, "done": True, "units": [worker.unit_record(u, "asked-nothing") for u in prepared["units"]]},
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    args = k8s_args(tmp_path, executor=executor, ax_dispatcher=Dispatcher(), docker_image="vm-image")
    monkeypatch.setattr(trace, "prepare_questions", lambda *_: {"a": {}})
    monkeypatch.setattr(subprocess, "run", docker)
    assert not trace.run_plan(resumed, tmp_path / "frozen", {"code": "frozen"}, Inputs(), args)
    result = json.loads((tmp_path / trace.pin_name(pin)).read_text())
    assert [command[1] for command in calls] == ["run", "rm"]
    assert result["executor"] == "docker" and result["image"] == "vm-image"
    assert result["fallback"] == "vm-oom" and not result["fallback_pending"]
    assert result["ax_attempt"] == attempt
    assert result["units"][0]["status"] == "asked-nothing"
    assert trace.make_plan([unit()], tmp_path, rerun_status=()) == []
    progress = json.loads((tmp_path / "progress.json").read_text())
    assert progress["pins_done"] == 1 and progress["pins_in_flight"] == 0
    assert progress["fallbacks_pending"] == 0 and progress["statuses"] == {"asked-nothing": 1}


@pytest.mark.parametrize("failure", ["", "start", "taint"])
def test_worker_resident_session_and_fallback(tmp_path, monkeypatch, failure):
    from types import SimpleNamespace

    calls = []
    graph = tmp_path / "cpg.bin"
    graph.write_bytes(b"g" * 2048)
    payloads = {
        "overlay": {"files": "1", "methods": "1"},
        "census": {"files": "1", "file_names": ["app.py"]},
        "taint": {"__census__": [{"files": 1, "file_names": ["app.py"]}], "a": []},
    }

    def output(query):
        return BEGIN + "\n" + json.dumps(payloads[query]) + "\n" + END

    class Session:
        loaded_graph = ""
        failure = "fake failure"
        output_observer = None

        def __init__(self, scratch, budget, env, **kwargs):
            self.scratch = scratch
            assert "ActiveProcessorCount=2" in env["JAVA_TOOL_OPTIONS"]

        def start(self):
            calls.append("start")
            return failure != "start"

        def load(self, path, **kwargs):
            calls.append("load")
            assert path.read_bytes() == b"g" * 2048
            self.loaded_graph = str(path)
            return True

        def define(self, source, **kwargs):
            assert "  importCpg(cpgFile)" not in source
            return ""

        def evaluate(self, code, **kwargs):
            query = code.split("(")[0].removeprefix("ousast_")
            calls.append(query)
            if query == "overlay":
                saved = self.scratch / "workspace" / graph.name / "cpg.bin"
                saved.parent.mkdir(parents=True)
                saved.write_bytes(b"s" * 2048)
            if query == "taint":
                if failure == "taint":
                    return None
                self.output_observer('{"__question__":"a"}\n')
                self.output_observer('{"__question__":"a"}\n{"id":"a","rows":[]}\n')
            return SimpleNamespace(stdout=output(query))

        def close(self):
            calls.append("close")

        def log_tail(self):
            return "fake log"

    monkeypatch.setattr(worker, "EngineSession", Session)
    backend = worker.MeasuredBackend(900, 120, lambda: None, heap_profile="cluster")
    disposable = []

    def run(command, **kwargs):
        query = Path(command[command.index("--script") + 1]).stem
        disposable.append(query)
        if query == "overlay":
            saved = tmp_path / "workspace" / graph.name / "cpg.bin"
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(b"s" * 2048)
        return subprocess.CompletedProcess(command, 0, output(query), "")

    monkeypatch.setattr(backend, "_run", run)
    monkeypatch.setattr("openultrasast.cpg.backend.shutil.which", lambda name: name)
    assert backend._apply_overlays(graph, tmp_path)
    assert backend.query(graph, "census", {})["files"] == "1"
    assert backend._batch_once(graph, "taint", {"a": {}})["a"] == []
    backend.close_session()
    assert calls.count("start") == 1
    if failure == "start":
        assert disposable == ["overlay", "census", "taint"]
        assert backend.session_fallback == "fake failure"
    else:
        assert calls.count("load") == 1
        assert [stage["step"] for stage in backend.stages] == ["start", "load", "overlay", "census", "taint"]
        assert all(stage["seconds"] >= 0 for stage in backend.stages)
        assert backend.stages[3]["files"] == 1
        assert disposable == (["taint"] if failure else [])
        if not failure:
            assert backend.asked == ["a"]
            assert backend.answers == {"a": []}
            assert backend.completion_counts["a"] == 1
    assert calls.count("close") == 1


def test_worker_session_question_deadline_keeps_markers_and_does_not_replay(tmp_path):
    from types import SimpleNamespace

    graph = tmp_path / "cpg.bin"
    graph.write_bytes(b"g" * 2048)
    backend = worker.MeasuredBackend(900, 0, lambda: None)
    closed = []

    def evaluate(code, **kwargs):
        assert not fake.output_observer('{"__question__":"a"}\n')
        return None

    fake = SimpleNamespace(
        loaded_graph=str(graph),
        define=lambda *a, **kw: "",
        evaluate=evaluate,
        close=lambda: closed.append(True),
    )
    backend._session = fake
    body = backend._session_payload(graph, "taint", {"cpgFile": str(graph)})
    assert body == '{"__question__":"a"}\n'
    assert backend.timed_out and backend.asked == ["a"]
    assert not backend.answers and not backend.session_fallback
    assert closed == [True]
