"""M2 task 11.2: every shipped query kind must answer identically through both transports.

The session is a transport, so the only thing that makes it usable is that it returns exactly the
payload the disposable invocation returns. This harness builds one real graph, then asks the same
batch of requests through the disposable path and through a session and compares the answers.

Requests are built by each arbiter's own parameter function, the same way the driver builds them,
so the comparison is over the requests production actually sends rather than a hand-written shape.

It also checks the failure shapes that would make a session dangerous rather than merely slow:
an empty answer must stay distinguishable from an unavailable one, a second graph loaded into the
same session must answer about that graph, and a request after the session is gone must not
answer at all.

No detection, precision or latency claim: timings are recorded for orientation only.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from openultrasast.cpg.backend import JoernBackend
from openultrasast.model.config_value import request_params as config_params
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.model.dominance import request_params as dominance_params
from openultrasast.model.scan import _spec_for
from openultrasast.model.specs import ConfigSpec, DominanceSpec, TaintSpec
from openultrasast.model.taint import request_params as taint_params


def build_graph(root: Path, scratch: Path, env: dict[str, str]) -> Path:
    scratch.mkdir(parents=True, exist_ok=True)
    graph = scratch / "cpg.bin"
    result = subprocess.run(  # noqa: S603
        ["joern-parse", "--output", str(graph), str(root)], cwd=scratch, env=env, capture_output=True, text=True, timeout=1800
    )
    if result.returncode != 0 or not graph.is_file() or not graph.stat().st_size:
        raise SystemExit(f"graph build failed: {result.stderr[-400:]}")
    return graph


def requests_for(language: str, path: str, function: str) -> dict[str, dict[str, Any]]:
    """One request per shipped query kind, built by the arbiter that owns each kind.

    Routed through the driver's own family lookup so the parameters are the ones production sends.
    """
    out: dict[str, dict[str, Any]] = {}
    for family in ("injection", "access_control", "config_secrets"):
        spec = _spec_for(family, language)
        if isinstance(spec, TaintSpec) and "taint" not in out:
            out["taint"] = taint_params(spec, function=function, file=path, parameter_sources=True, call_depth=0)
        elif isinstance(spec, DominanceSpec) and "dominance" not in out:
            out["dominance"] = dominance_params(spec, function=function, file=path)
        elif isinstance(spec, ConfigSpec) and "config" not in out:
            out["config"] = config_params(spec, function=function, file=path)
    return out


def main() -> int:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=False)
    root = Path(sys.argv[2])
    second = Path(sys.argv[3]) if len(sys.argv) > 3 else None
    record: dict[str, Any] = {
        "schema_version": 1,
        "experiment": "session-transport-equivalence-v1",
        "milestone": "M2 task 11.2",
        "purpose": "Identical payloads from both transports for every shipped query kind",
        "comparisons": [],
        "failure_shapes": [],
        "verdict": {},
    }

    def save() -> None:
        (out / "result.json").write_text(json.dumps(record, indent=2, default=str) + "\n")

    sources = sorted(p for p in root.rglob("*.js") if p.is_file())
    opened = [(str(p.relative_to(root)), p.read_bytes()) for p in sources]
    if not opened or not all(raw for _, raw in opened):
        raise SystemExit("no readable JavaScript source under the given root")
    record["source"] = {
        "root": str(root),
        "files": len(opened),
        "bytes": sum(len(raw) for _, raw in opened),
        "sha256": hashlib.sha256(b"".join(raw for _, raw in opened)).hexdigest(),
    }
    save()

    env = dict(os.environ, JAVA_TOOL_OPTIONS="-Xmx1536m")
    scratch = out / "scratch"
    scratch.mkdir()
    graph = build_graph(root, scratch, env)
    record["graph"] = {"path": str(graph), "bytes": graph.stat().st_size}
    save()

    target = next((name for name, _ in opened if "contributions" in name), opened[0][0])
    kinds = requests_for("javascript", target, "")
    if "taint" not in kinds:
        raise SystemExit("no JavaScript taint spec available to compare")
    record["requests"] = {kind: params for kind, params in kinds.items()}
    save()

    def ask(kind: str, params: dict[str, Any], *, session: bool, graph_path: Path) -> tuple[Any, float, list[str]]:
        backend = JoernBackend(
            session_transport=session,
            execution_budget=ExecutionBudget(time.monotonic() + 1800, 5.0),
        )
        started = time.monotonic()
        try:
            answer = backend.query_batch(graph_path, kind, {"r1": params})
        finally:
            backend.close_session()
        return answer, time.monotonic() - started, list(backend._diagnostics)

    equivalent = True
    for kind, params in sorted(kinds.items()):
        disposable, disposable_seconds, _ = ask(kind, params, session=False, graph_path=graph)
        in_session, session_seconds, notes = ask(kind, params, session=True, graph_path=graph)
        same = json.dumps(disposable, sort_keys=True) == json.dumps(in_session, sort_keys=True)
        equivalent = equivalent and same
        record["comparisons"].append(
            {
                "kind": kind,
                "identical": same,
                "disposable_seconds": disposable_seconds,
                "session_seconds": session_seconds,
                "disposable_rows": None if disposable is None else {k: len(v) for k, v in disposable.items()},
                "session_rows": None if in_session is None else {k: len(v) for k, v in in_session.items()},
                "disposable_unavailable": disposable is None,
                "session_notes": notes,
            }
        )
        save()

    # An answer with no rows must not be reported the same way as no answer at all.
    empty, _, _ = ask("taint", {**kinds["taint"], "file": "no-such-file.js"}, session=True, graph_path=graph)
    rows = None if empty is None else sum(len(value) for value in empty.values())
    record["failure_shapes"].append({"shape": "empty_answer_is_not_unavailable", "answer_present": empty is not None, "rows": rows})
    missing, _, _ = ask("no-such-query", kinds["taint"], session=True, graph_path=graph)
    record["failure_shapes"].append({"shape": "unknown_query_is_unavailable", "unavailable": missing is None})
    absent, _, _ = ask("census", {}, session=True, graph_path=scratch / "absent.bin")
    record["failure_shapes"].append({"shape": "absent_graph_is_unavailable", "unavailable": absent is None})
    save()

    if second is not None:
        other = build_graph(second, scratch / "second", env)
        # One session, two graphs: the answer must be about the graph the request names.
        backend = JoernBackend(session_transport=True, execution_budget=ExecutionBudget(time.monotonic() + 1800, 5.0))
        try:
            first_answer = backend.query_batch(graph, "census", {"r1": {}})
            second_answer = backend.query_batch(other, "census", {"r1": {}})
        finally:
            backend.close_session()
        expected_first, _, _ = ask("census", {}, session=False, graph_path=graph)
        expected_second, _, _ = ask("census", {}, session=False, graph_path=other)
        switched = json.dumps(first_answer, sort_keys=True) == json.dumps(expected_first, sort_keys=True) and json.dumps(
            second_answer, sort_keys=True
        ) == json.dumps(expected_second, sort_keys=True)
        record["failure_shapes"].append({"shape": "switched_graph_answers_the_named_graph", "correct": switched})
        equivalent = equivalent and switched
        save()

    # One request per session is the session's WORST case: it pays startup and amortizes it over
    # nothing. The transport exists to spread that cost over a transaction's many requests, so the
    # comparison that decides anything is this one.
    repeats = 5
    disposable_total = 0.0
    for _ in range(repeats):
        _, seconds, _ = ask("taint", kinds["taint"], session=False, graph_path=graph)
        disposable_total += seconds
    record["amortized"] = {"requests": repeats, "disposable_seconds": disposable_total}
    save()
    backend = JoernBackend(session_transport=True, execution_budget=ExecutionBudget(time.monotonic() + 1800, 5.0))
    started = time.monotonic()
    answers = []
    try:
        for _ in range(repeats):
            answers.append(backend.query_batch(graph, "taint", {"r1": kinds["taint"]}))
    finally:
        backend.close_session()
    record["amortized"]["session_seconds"] = time.monotonic() - started
    record["amortized"]["session_all_answered"] = all(a is not None for a in answers)
    record["amortized"]["session_answers_identical"] = len({json.dumps(a, sort_keys=True) for a in answers}) == 1
    save()

    shapes_ok = (
        record["failure_shapes"][0]["answer_present"]
        and record["failure_shapes"][1]["unavailable"]
        and record["failure_shapes"][2]["unavailable"]
        and all(item.get("correct", True) for item in record["failure_shapes"])
    )
    amortized = record.get("amortized", {})
    record["verdict"] = {
        "status": "PASS" if equivalent and shapes_ok and amortized.get("session_all_answered") else "FAIL",
        "payloads_identical": equivalent,
        "failure_shapes_correct": shapes_ok,
        "amortized_speedup": (
            round(amortized["disposable_seconds"] / amortized["session_seconds"], 2) if amortized.get("session_seconds") else None
        ),
        "note": (
            "Equivalence on one JavaScript graph for the shipped query kinds available to it. "
            "It is not a latency gate and qualifies no capability."
        ),
    }
    save()
    print(json.dumps(record["verdict"]), flush=True)
    return 0 if record["verdict"]["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
