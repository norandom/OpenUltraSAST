"""Probe: can a shipped query script run inside a Joern session and answer identically?

This settles the one design unknown for release milestone M2 task 11.1. The shipped scripts are
`@main def exec(...)` files invoked as `joern --script X.sc --param k=v`, and a session has no
`--param`. Before routing production work through a session we need a mechanism that runs the
same script with the same parameters and returns the same payload.

It drives the production `EngineSession` transport, so the receipt protocol under test is the real
one. Each candidate defines the script in the session and then calls it, capturing the script's
own console output through the session's private receipt file. A candidate counts as working only
when its payload matches the disposable invocation's payload for the same graph.

The first version of this probe sent two candidates as Scala string literals rather than as code
and reported no working mechanism. That was an instrument defect, recorded here because a probe
that lies about the engine is worse than no probe. It did establish that `runScript` is absent
from the server REPL, and it failed loudly, returning the script's own source as its payload
rather than quietly reporting a zero.

Isolated experiment: no production path is changed, and no detection or latency claim is made.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from openultrasast.cpg.backend import extract_payload
from openultrasast.cpg.session import EngineSession
from openultrasast.model.contracts import ExecutionBudget

QUERIES = Path("/app/src/openultrasast/cpg/queries")


def strip_main(source: str, name: str) -> str:
    """Turn `@main def exec(...)` into an ordinary definition the REPL can hold."""
    return source.replace("@main def exec(", f"def {name}(", 1)


def main() -> int:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=False)
    root = Path(sys.argv[2])
    record: dict[str, Any] = {
        "schema_version": 1,
        "experiment": "session-script-execution-v2",
        "purpose": "Which in-session mechanism runs a shipped @main script with parameters",
        "scope": "One JavaScript graph, census script; no security-query equivalence and no latency claim",
        "instrument_note": (
            "v1 of this probe sent two candidates as Scala string literals instead of code and reported "
            "NO_MECHANISM_FOUND. It did establish that runScript is absent from the server REPL."
        ),
        "attempts": [],
        "verdict": {},
    }

    def save() -> None:
        (out / "result.json").write_text(json.dumps(record, indent=2, default=str) + "\n")

    files = sorted(p for p in root.rglob("*.js") if p.is_file())
    opened = [(str(p.relative_to(root)), p.read_bytes()) for p in files]
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
    with tempfile.TemporaryDirectory(prefix="session-script-probe-") as scratch_name:
        scratch = Path(scratch_name)
        graph = scratch / "cpg.bin"
        build = subprocess.run(  # noqa: S603
            ["joern-parse", "--output", str(graph), str(root)],
            cwd=scratch,
            env=env,
            capture_output=True,
            text=True,
            timeout=900,
        )
        graph_bytes = graph.stat().st_size if graph.is_file() else 0
        record["build"] = {"exit_code": build.returncode, "graph_bytes": graph_bytes, "stderr": build.stderr[-400:]}
        save()
        if build.returncode != 0 or not graph_bytes:
            record["verdict"] = {"status": "INSTRUMENT_FAILURE", "reason": "graph build failed"}
            save()
            return 2

        started = time.monotonic()
        disposable = subprocess.run(  # noqa: S603
            ["joern", "--script", str(QUERIES / "census.sc"), "--param", f"cpgFile={graph}"],
            cwd=scratch,
            env=env,
            capture_output=True,
            text=True,
            timeout=900,
        )
        expected = extract_payload(disposable.stdout or "")
        record["disposable"] = {"seconds": time.monotonic() - started, "exit_code": disposable.returncode, "payload": expected}
        save()
        if not isinstance(expected, dict):
            record["verdict"] = {"status": "INSTRUMENT_FAILURE", "reason": "disposable census produced no payload"}
            save()
            return 2

        source = (QUERIES / "census.sc").read_text()
        candidates: list[tuple[str, str, str]] = [
            ("main_annotation_kept", source, f"exec({json.dumps(str(graph))})"),
            ("main_annotation_stripped", strip_main(source, "ousastCensus"), f"ousastCensus({json.dumps(str(graph))})"),
        ]

        def fresh(tag: str) -> EngineSession:
            live = EngineSession(scratch / f"session-{tag}", ExecutionBudget(time.monotonic() + 1500, 5.0), env)
            live.start()
            return live

        session = fresh("initial")
        if not session.alive:
            record["verdict"] = {"status": "INSTRUMENT_FAILURE", "reason": session.failure}
            save()
            session.close()
            return 2
        record["session_startup_seconds"] = session.startup_seconds
        save()
        try:
            for index, (name, definition, call) in enumerate(candidates):
                attempt: dict[str, Any] = {"mechanism": name}
                started = time.monotonic()
                # Definitions go to the top level unwrapped: `@main` and top-level declarations
                # are not block expressions, so the receipt wrapper cannot hold them. The call
                # that follows is the only proof the definition took.
                defined = session.define(definition, timeout=300)
                attempt["definition_sent"] = defined is not None
                attempt["definition_output"] = (defined or session.failure)[-800:]
                if defined is not None:
                    answer = session.evaluate(call, timeout=600)
                    if answer is None:
                        attempt["error"] = session.failure
                        # The engine's own diagnostic, without which a missing receipt says nothing.
                        attempt["engine_body"] = session.last_body[-1500:]
                    else:
                        parsed = extract_payload(answer.stdout)
                        attempt["call_seconds"] = answer.seconds
                        attempt["payload"] = parsed
                        attempt["stdout_tail"] = answer.stdout[-300:]
                        attempt["payload_matches_disposable"] = bool(
                            isinstance(parsed, dict)
                            and all(parsed.get(key) == expected.get(key) for key in ("files", "methods", "calls"))
                            and sorted(parsed.get("file_names") or []) == sorted(expected.get("file_names") or [])
                        )
                attempt["seconds"] = time.monotonic() - started
                record["attempts"].append(attempt)
                save()
                # A poisoned session cannot serve the next candidate honestly.
                if not session.alive and index + 1 < len(candidates):
                    session.close()
                    session = fresh(name)
                    if not session.alive:
                        break
            working = [a["mechanism"] for a in record["attempts"] if a.get("payload_matches_disposable")]
            record["verdict"] = {
                "status": "PASS" if working else "NO_MECHANISM_FOUND",
                "working": working,
                "warm_call_seconds": [a.get("call_seconds") for a in record["attempts"] if a.get("payload_matches_disposable")],
                "disposable_seconds": record["disposable"]["seconds"],
                "note": (
                    "Census only. A working mechanism must still be proven equivalent for taint, dominance and "
                    "configuration before any production switch, which is task 11.2."
                ),
            }
            save()
            return 0 if working else 1
        finally:
            session.close()


if __name__ == "__main__":
    raise SystemExit(main())
