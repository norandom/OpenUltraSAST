"""model-grounded-detection task 2.1: the Joern seam, out of process and capability-detected.

Joern is a JVM tool. The whole integration is one subprocess boundary so that the core install stays
zero-dependency and an absent engine degrades to `suspicion` with a recorded reason rather than a traceback.
Nothing here imports a JVM binding, and every test runs with Joern absent.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
from pathlib import Path

import pytest


def _is_overlay(command) -> bool:  # type: ignore[no-untyped-def]
    return any(str(part).endswith("overlay.sc") for part in command)


def _overlaid(command, cwd=None):  # type: ignore[no-untyped-def]
    """The build-time overlay step (`joern --script overlay.sc --param cpgFile=...`, run in the scratch dir),
    answered the way Joern answers it: a saved graph under `workspace/<name>/cpg.bin` and a fenced payload.

    Returned by a fake runner whenever it sees the script, so tests that count frontend invocations or
    dispatch on `-o` / `--script` keep counting only what they are about.
    """
    import subprocess

    from openultrasast.cpg.backend import BEGIN, END

    cpg = Path(next(p for p in command if str(p).startswith("cpgFile=")).split("=", 1)[1])
    saved = Path(cwd or cpg.parent) / "workspace" / cpg.name / "cpg.bin"
    saved.parent.mkdir(parents=True, exist_ok=True)
    saved.write_text("cpg+overlays")
    return subprocess.CompletedProcess(args=command, returncode=0, stdout=f'{BEGIN}\n{{"files": "1", "methods": "1"}}\n{END}\n', stderr="")


def test_without_joern_the_resolved_backend_is_the_null_one(monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.cpg.backend import NullBackend, resolve_cpg_backend

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "off")
    backend = resolve_cpg_backend()
    assert isinstance(backend, NullBackend)
    assert backend.available() is False
    assert backend.build(Path(".")) is None, "an absent engine yields no CPG, and the caller degrades"


def test_the_capability_probe_reuses_the_existing_joern_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """`semantic/engines.joern_available` already exists; the model layer must not grow a second probe."""
    from openultrasast.cpg.capability import has_cpg

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "off")
    assert has_cpg() is False
    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    assert has_cpg() is True


def test_the_seam_imports_nothing_outside_the_standard_library() -> None:
    """Req 4.2: the core install has no dependencies, so the seam may not import one at module load."""
    import ast

    source = Path("src/openultrasast/cpg/backend.py").read_text()
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
    stdlib = {
        "__future__",
        "json",
        "os",
        "re",
        "shutil",
        "signal",
        "subprocess",
        "tempfile",
        "time",
        "dataclasses",
        "pathlib",
        "typing",
        "collections",
        "logging",
        "hashlib",
    }
    assert imported <= stdlib, f"the seam imports outside the standard library: {sorted(imported - stdlib)}"
    assert "import jpype" not in source and "py4j" not in source, "Joern is reached by subprocess, never in-process"


def test_a_scripted_backend_parses_a_query_result_without_joern(tmp_path: Path) -> None:
    """The parsing is exercised by canned JSON, so the query contract is testable with no engine installed."""
    from openultrasast.cpg.backend import CpgResult

    payload = [{"sink": "os.system", "source": "request.args", "path": ["a", "b"], "sanitized": False}]

    def run(query: str, params: dict[str, object]) -> object:
        assert query == "taint"
        return payload

    result = CpgResult(cpg_path=tmp_path / "cpg.bin", run=run)
    assert result.run("taint", {}) == payload


def test_joern_output_is_read_from_a_delimited_block_not_from_noisy_stdout() -> None:
    """Joern prints a banner and a REPL prompt; the payload is fenced so the parse cannot swallow either."""
    from openultrasast.cpg.backend import BEGIN, END, extract_payload

    noisy = f"Compiling...\nJoern v4.0\n{BEGIN}\n{json.dumps([{'sink': 'eval'}])}\n{END}\njoern> \n"
    assert extract_payload(noisy) == [{"sink": "eval"}]
    assert extract_payload("no markers at all") is None
    assert extract_payload(f"{BEGIN}\nnot json\n{END}") is None


def test_a_failing_or_slow_engine_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail closed: a build or query that errors yields no verdict, never a wrong one."""
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    def boom(*args: object, **kwargs: object) -> object:
        raise subprocess.TimeoutExpired(cmd="joern-parse", timeout=1)

    backend = JoernBackend(runner=boom)
    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    assert backend.build(tmp_path) is None


def test_the_query_scripts_are_shipped_beside_the_seam() -> None:
    """The CPGQL is ours and is data: it lives with the package, not inlined in a Python string."""
    queries = Path("src/openultrasast/cpg/queries")
    assert (queries / "taint.sc").is_file(), "the injection taint query must ship with the package"


def test_a_batch_is_one_invocation_carrying_many_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    """The cost that dominates a repository scan is JVM startup, not CPG construction.

    Every `joern --script` call starts a JVM (~30s). The driver issued one per region per family, so a
    ten-line Python file -- six families, one region -- took over four minutes, and 1000 regions would take
    ~50 hours. Batching collapses that to one invocation per query kind.
    """
    from openultrasast.cpg.backend import BEGIN, END, JoernBackend

    calls: list[list[str]] = []

    class _Done:
        returncode = 0
        stderr = ""
        stdout = f'{BEGIN}\n{{"r1": [{{"sink": "os.system(x)"}}], "r2": []}}\n{END}\n'

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        calls.append(list(command))
        return _Done()

    backend = JoernBackend(runner=runner)
    rows = backend.query_batch(
        Path("/tmp/c.bin"),
        "taint",
        {"r1": {"sources": ("request.args",), "sinks": ("os.system",)}, "r2": {"sources": ("request.args",), "sinks": ("eval",)}},
    )
    assert len(calls) == 1, "a batch must be ONE invocation, whatever it carries"
    assert rows["r1"] and rows["r2"] == []


def test_a_failed_batch_yields_no_rows_for_any_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail closed, as everywhere else: an engine that could not answer must not read as 'nothing here'."""
    from openultrasast.cpg.backend import JoernBackend

    class _Bad:
        returncode = 1
        stdout = ""
        stderr = "boom"

    backend = JoernBackend(runner=lambda c, **k: _Bad())
    assert backend.query_batch(Path("/tmp/c.bin"), "taint", {"r1": {}}) is None, (
        "None means COULD NOT ASK; {} would mean the engine answered and found nothing, and a caller that "
        "cannot tell them apart reports a failed scan as a clean repository"
    )


def test_a_batch_result_that_omits_a_request_returns_nothing_for_it() -> None:
    """A missing key is not an empty answer: the caller must be able to tell them apart."""
    from openultrasast.cpg.backend import BEGIN, END, JoernBackend

    class _Partial:
        returncode = 0
        stderr = ""
        stdout = f'{BEGIN}\n{{"r1": []}}\n{END}\n'

    backend = JoernBackend(runner=lambda c, **k: _Partial())
    rows = backend.query_batch(Path("/tmp/c.bin"), "taint", {"r1": {}, "r2": {}})
    assert rows.get("r1") == [] and "r2" not in rows


def test_a_built_cpg_offers_the_batch_path_to_its_driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The capability must be reachable through the object the driver is handed, not merely present.

    ``query_batch`` was implemented, tested and committed while ``build`` returned a result carrying only
    ``run``. The driver discovers batching by looking for ``run_batch`` on that result, found nothing, and
    fell back to one JVM per region -- silently, because every test called ``query_batch`` directly. A
    repository scan is what made it visible: ~14s per region-family, one ``--param function=`` invocation at
    a time.
    """
    from openultrasast.cpg.backend import BEGIN, END, JoernBackend

    scripts: list[list[str]] = []

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))

        class _Done:
            returncode = 0
            stderr = ""
            stdout = f'{BEGIN}\n{{"r1": [{{"sink": "os.system(x)"}}]}}\n{END}\n'

        if "--output" in command:  # the parse step; make the artifact it promises
            Path(command[command.index("--output") + 1]).write_text("cpg")
        else:
            scripts.append(list(command))
        return _Done()

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    result = JoernBackend(runner=runner).build(tmp_path)

    assert result is not None
    assert result.run_batch is not None, "a backend that can batch must expose it, or the driver cannot find it"
    rows = result.run_batch("taint", {"r1": {"sources": ("request.args",), "sinks": ("os.system",)}})
    assert rows["r1"], "the batch path must reach the engine, not just exist"
    assert len(scripts) == 1, "one invocation for the batch"
    assert not any(arg.startswith("function=") for arg in scripts[0]), "a batch carries requests, not one function"


def test_the_engine_runs_under_a_bounded_heap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A JVM with no -Xmx claims a quarter of physical RAM.

    That is not a tuning preference. The first repository measurements were killed under memory pressure at
    different points, so their numbers described the host rather than the engine, and on a contributor's
    laptop an unbounded heap is the difference between a scan running in the background and a scan the
    machine notices.
    """
    from openultrasast.cpg.backend import JoernBackend

    commands: list[list[str]] = []

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))

        class _Done:
            returncode = 0
            stderr = ""
            stdout = ""

        commands.append(list(command))
        if "--output" in command:
            Path(command[command.index("--output") + 1]).write_text("cpg")
        return _Done()

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.delenv("OPENULTRASAST_CPG_HEAP_MB", raising=False)
    result = JoernBackend(runner=runner).build(tmp_path)
    assert result is not None
    result.run("taint", {})

    assert commands, "nothing ran"
    for command in commands:
        assert any(arg.startswith("-J-Xmx") for arg in command), f"unbounded heap in {command[0]}"


def test_the_operator_can_raise_the_heap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A bound that cannot be lifted is a bound that gets removed. A big repository may need a big heap."""
    from openultrasast.cpg.backend import JoernBackend

    commands: list[list[str]] = []

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))

        class _Done:
            returncode = 0
            stderr = ""
            stdout = ""

        commands.append(list(command))
        if "--output" in command:
            Path(command[command.index("--output") + 1]).write_text("cpg")
        return _Done()

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setenv("OPENULTRASAST_CPG_HEAP_MB", "6144")
    JoernBackend(runner=runner).build(tmp_path)

    assert "-J-Xmx6144m" in commands[0]


def test_a_failed_joern_parse_retries_through_the_language_frontend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Measured on a 637-file WordPress plugin: `joern-parse` threw after applying overlays while `php2cpg`
    on the same tree produced a 4.3MB CPG with no errors. Joern's own message recommends the direct route for
    a large codebase, so this is the documented fallback rather than a workaround.

    Uses a language OUTSIDE `_PREFER_FRONTEND`, because php no longer waits for joern-parse to fail first --
    see the test below.
    """
    from openultrasast.cpg.backend import JoernBackend

    tried: list[str] = []

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))

        class _Result:
            stderr = ""
            stdout = ""

        tried.append(Path(command[0]).name)
        if Path(command[0]).name == "joern-parse":
            _Result.returncode = 1
            return _Result()
        _Result.returncode = 0
        Path(command[command.index("-o") + 1]).write_text("cpg")
        return _Result()

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/joern/{name}")

    result = JoernBackend(runner=runner).build(tmp_path, language="python")

    assert result is not None, "the frontend succeeded where joern-parse did not"
    assert tried == ["joern-parse", "pysrc2cpg"]


def test_an_unknown_language_has_nothing_to_retry_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No guessing at a frontend name: a language with no mapping fails closed, as it did before."""
    from openultrasast.cpg.backend import JoernBackend

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))

        class _Result:
            returncode = 1
            stderr = ""
            stdout = ""

        return _Result()

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    assert JoernBackend(runner=runner).build(tmp_path, language="cobol") is None
    assert JoernBackend(runner=runner).build(tmp_path) is None


def test_a_batch_goes_through_a_file_not_the_command_line(tmp_path: Path) -> None:
    """Linux caps a SINGLE argument at MAX_ARG_STRLEN (128KB) whatever ARG_MAX says.

    2500 taint requests over a 637-file WordPress plugin is a 1.49MB payload. As `--param requests=<json>`
    execve returned E2BIG, the runner caught the OSError, query_batch returned {} -- and {} reads as "no rows
    found". The scan reported 500 regions examined, nothing found, and 0.05 seconds of taint query: a quiet
    failure the rung ladder cannot catch, because no verdict was ever produced to label.
    """
    from openultrasast.cpg.backend import BEGIN, END, JoernBackend

    commands: list[list[str]] = []

    class _Done:
        returncode = 0
        stderr = ""
        stdout = f'{BEGIN}\n{{"r0": []}}\n{END}\n'

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        commands.append(list(command))
        return _Done()

    cpg = tmp_path / "cpg.bin"
    cpg.write_text("cpg")
    big = {f"r{i}": {"sources": ("request.args",) * 40, "sinks": ("execute",) * 40} for i in range(2000)}

    JoernBackend(runner=runner).query_batch(cpg, "taint", big)

    argv = commands[0]
    assert not any(len(arg) > 131072 for arg in argv), "no argument may approach MAX_ARG_STRLEN"
    staged = [arg for arg in argv if arg.startswith("requestsFile=")]
    assert staged, "the batch is staged to a file"
    written = Path(staged[0].split("=", 1)[1])
    assert written.is_file() and len(written.read_text()) > 200_000, "and the file holds the whole payload"


def test_a_file_the_frontend_dropped_is_carried_off_the_build() -> None:
    """A Joern frontend fails a file without failing the build, and exits 0 with the rest of the graph.

    php2cpg 4.0.623 does exactly this: one oversized file corrupts the batched parser stream, that file is
    logged at WARN and dropped, and the CPG comes back missing it. A scan over the remainder that says
    nothing is a clean bill of health over code nobody looked at.
    """
    warning = (
        "2026-09-09 17:46:21.892 WARN  AstCreationPass  Failed to process '/src/class.memberorder.php'\n"
        "2026-09-09 17:46:21.892 WARN  SymbolSummaryPass  Failed to process '/src/class.memberorder.php'\n"
        "2026-09-09 17:46:21.893 WARN  AstCreationPass  Failed to process '/src/rest-api.php'\n"
    )
    from openultrasast.cpg.backend import _unparsed_files

    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=warning)
    assert _unparsed_files(completed) == ("/src/class.memberorder.php", "/src/rest-api.php")


def test_a_build_with_nothing_dropped_reports_no_unparsed_files() -> None:
    from openultrasast.cpg.backend import _unparsed_files

    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="Successfully wrote graph", stderr="")
    assert _unparsed_files(completed) == ()
    assert _unparsed_files(None) == ()


def test_a_joern_log_line_inside_the_fence_does_not_destroy_the_payload() -> None:
    """Joern logs to stdout while the script runs, so a log line can land ahead of the payload.

    `[INFO ] Attempting to determine flows from empty list of sources.` did, and because the batch is one
    JSON document the driver lost all 205 answers in it and reported `query_failed` for every one.
    """
    from openultrasast.cpg.backend import BEGIN, END, extract_payload

    noisy = f'{BEGIN}\n[INFO ] Attempting to determine flows from empty list of sources.\n{{"0": [], "1": [1]}}\n{END}\n'
    assert extract_payload(noisy) == {"0": [], "1": [1]}


def test_php_builds_through_the_frontend_and_retries_while_files_are_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """php2cpg fails INTERMITTENTLY, and unlike joern-parse it says so.

    Measured on one WordPress slice: joern-parse produced a usable graph 5 times in 8 and reported nothing
    when it did not -- exit 0, "Successfully wrote graph", no methods in the graph. php2cpg on the same tree
    managed 11 in 12 and named every file it dropped. So php goes straight to the frontend, and a build that
    reports dropped files is simply attempted again.
    """
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    tried: list[str] = []
    warning = "WARN AstCreationPass Failed to process '/src/big.php'\n"

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")
        if "--script" in command:  # the census on the clean build
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout='---OUSAST-CPG-BEGIN---\n{"files": "1", "methods": "1"}\n---OUSAST-CPG-END---\n',
                stderr="",
            )
        tried.append(Path(command[0]).name)
        Path(command[command.index("-o") + 1]).write_text("cpg")
        # Drops a file on the first two attempts, clean on the third.
        stderr = warning if len(tried) <= 2 else ""
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr=stderr)

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/joern/{name}")

    result = JoernBackend(runner=runner).build(tmp_path, language="php")

    assert result is not None
    assert tried == ["php2cpg", "php2cpg", "php2cpg"], "joern-parse is not consulted for php, and it retried"
    assert result.unparsed == (), "the third attempt was clean, so nothing is reported as dropped"


def test_a_php_build_that_never_stops_dropping_files_reports_them(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Retrying is not the same as pretending. When every attempt drops the same file, the caller is told."""
    import subprocess

    from openultrasast.cpg.backend import FRONTEND_BUILD_ATTEMPTS, JoernBackend

    attempts = 0

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal attempts
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")
        attempts += 1
        Path(command[command.index("-o") + 1]).write_text("cpg")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="WARN Failed to process '/src/stubborn.php'\n")

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/joern/{name}")

    result = JoernBackend(runner=runner).build(tmp_path, language="php")

    assert attempts >= FRONTEND_BUILD_ATTEMPTS, "it retried"
    assert attempts < 100, "and it gave up rather than retrying forever"
    assert result is not None and result.unparsed == ("/src/stubborn.php",), "the file is named, not silently lost"


def test_files_the_frontend_refuses_get_a_cpg_of_their_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A dropped file is dropped from the ONLY graph there is, and every question about it then has no
    answer. The same file builds fine alone -- the failure is per-invocation -- so it is excluded from the
    main build and given a second CPG, and queries run over both."""
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    (tmp_path / "big.php").write_text("<?php function a() {}")
    (tmp_path / "ok.php").write_text("<?php function b() {}")
    commands: list[list[str]] = []

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        commands.append(list(command))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")  # the input probe
        if "--script" in command:
            # The census, asked because the frontend warned. Here the warning is real: the graph is short a
            # file, so the caller should go on to exclude it and build it separately.
            body = '---OUSAST-CPG-BEGIN---\n{"files": "1", "methods": "1"}\n---OUSAST-CPG-END---\n'
            return subprocess.CompletedProcess(args=command, returncode=0, stdout=body, stderr="")
        Path(command[command.index("-o") + 1]).write_text("cpg")
        # The whole tree always drops big.php; any build that excludes it, or covers it alone, is clean.
        excluded = "--exclude" in command
        island = "excluded-root" in command[2]
        stderr = "" if excluded or island else f"WARN Failed to process '{tmp_path / 'big.php'}'\n"
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr=stderr)

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/joern/{name}")

    result = JoernBackend(runner=runner).build(tmp_path, language="php")

    assert result is not None
    assert result.unparsed == (), "the excluded file built on its own, so nothing is finally unparsed"
    assert any("--exclude" in command for command in commands), "the main build excluded the difficult file"
    assert any("excluded-root" in command[2] for command in commands), "and the difficult file got its own build"
    assert (tmp_path / "big.php").exists(), "the source tree is untouched"


def test_rows_from_every_shard_reach_the_caller(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two graphs, one answer. The census is summed and carries the shard count, so `cpg_empty` still means
    "no graph anywhere" rather than "the first of two was small"."""
    from openultrasast.cpg.backend import JoernBackend

    backend = JoernBackend()
    answers = {
        "a.bin": {"0": [{"sink": "one"}], "__census__": [{"methods": "3", "files": "1"}]},
        "b.bin": {"0": [{"sink": "two"}], "1": [{"sink": "three"}], "__census__": [{"methods": "4", "files": "2"}]},
    }
    monkeypatch.setattr(JoernBackend, "query_batch", lambda self, path, query, requests: answers[path.name])

    merged = backend.query_batch_across([Path("a.bin"), Path("b.bin")], "taint", {})

    assert merged is not None
    assert merged["0"] == [{"sink": "one"}, {"sink": "two"}]
    assert merged["1"] == [{"sink": "three"}]
    assert merged["__census__"] == [{"methods": "7", "files": "3", "shards": "2"}]


def test_a_shard_that_cannot_answer_does_not_lose_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.cpg.backend import JoernBackend

    backend = JoernBackend()
    monkeypatch.setattr(
        JoernBackend,
        "query_batch",
        lambda self, path, query, requests: None if path.name == "a.bin" else {"0": [{"sink": "kept"}]},
    )

    merged = backend.query_batch_across([Path("a.bin"), Path("b.bin")], "taint", {})
    assert merged is not None and merged["0"] == [{"sink": "kept"}]

    monkeypatch.setattr(JoernBackend, "query_batch", lambda self, path, query, requests: None)
    assert backend.query_batch_across([Path("a.bin")], "taint", {}) is None, "no shard answered is not an empty answer"


def test_a_warning_about_a_file_the_graph_actually_holds_does_not_split_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`php2cpg` logs `Failed to process` for files that are nonetheless in the finished graph. Measured: a
    build reporting two drops produced a graph holding both its files and all 139 methods, the same size as
    a clean one.

    Acting on the warning alone is destructive rather than merely wasteful -- shards cannot see each other's
    flows, and a two-file WordPress pair lost its CVE that way. So the graph is asked before it is split.
    """
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    (tmp_path / "a.php").write_text("<?php function a() {}")
    (tmp_path / "b.php").write_text("<?php function b() {}")
    commands: list[list[str]] = []

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        commands.append(list(command))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")  # the input probe
        if "--script" in command:
            body = '---OUSAST-CPG-BEGIN---\n{"files": "2", "methods": "9"}\n---OUSAST-CPG-END---\n'
            return subprocess.CompletedProcess(args=command, returncode=0, stdout=body, stderr="")
        Path(command[command.index("-o") + 1]).write_text("cpg")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr=f"WARN Failed to process '{tmp_path / 'a.php'}'\n")

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/joern/{name}")

    result = JoernBackend(runner=runner).build(tmp_path, language="php")

    assert result is not None
    assert result.unparsed == (), "the graph holds both files, so nothing is missing"
    assert not any("--exclude" in command for command in commands), "and it was not split"


def test_a_build_is_refused_when_the_interpreter_cannot_read_the_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The failure this project keeps having: the input is unreadable and the tool reports a plausible ZERO.

    `php2cpg` drives PHP-Parser through whatever `php` is on PATH. Give it a `php` that cannot see the tree
    -- a wrapper, a container missing a bind mount, symlinks pointing outside a sandbox -- and it does not
    fail. It parses nothing, writes a graph with no methods in it, and exits 0 with no warnings. That has
    cost this project four wrong diagnoses, including "php2cpg cannot handle 637 files" from a run that read
    none of them.

    Checking the output cannot tell that from an empty repository. Checking that the input arrived can.
    """
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    (tmp_path / "a.php").write_text("<?php function a() {}")
    built: list[str] = []

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=3, stdout="", stderr="")  # cannot read
        built.append(Path(command[0]).name)
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/bin/{name}")

    backend = JoernBackend(runner=runner)
    assert backend.build(tmp_path, language="php") is None, "an unreadable tree must not produce a graph"
    assert not built, "and nothing should have been built at all"
    assert "cannot read" in backend.last_failure, "the reason is named, not left as a bare build failure"


def test_a_readable_tree_builds_normally(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The probe must not stand in the way of the ordinary case."""
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    (tmp_path / "a.php").write_text("<?php function a() {}")

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")
        if "--script" in command:
            body = '---OUSAST-CPG-BEGIN---\n{"files": "1", "methods": "1"}\n---OUSAST-CPG-END---\n'
            return subprocess.CompletedProcess(args=command, returncode=0, stdout=body, stderr="")
        Path(command[command.index("-o") + 1]).write_text("cpg")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/bin/{name}")

    result = JoernBackend(runner=runner).build(tmp_path, language="php")
    assert result is not None and result.unparsed == ()


def test_a_silently_short_graph_is_reported_even_with_no_warnings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A build that warns about nothing is exactly the build that needs checking.

    A graph holding nothing arrives with no warnings at all -- silence is the symptom that has no symptom --
    so the census is taken on every build, not only on one the frontend complained about.
    """
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    for name in ("a.php", "b.php", "c.php"):
        (tmp_path / name).write_text("<?php function f() {}")

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")
        if "--script" in command:
            body = '---OUSAST-CPG-BEGIN---\n{"files": "1", "methods": "2"}\n---OUSAST-CPG-END---\n'
            return subprocess.CompletedProcess(args=command, returncode=0, stdout=body, stderr="")
        Path(command[command.index("-o") + 1]).write_text("cpg")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")  # no warnings

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/bin/{name}")

    backend = JoernBackend(runner=runner)
    backend.build(tmp_path, language="php")

    assert "1 of 3 source files" in backend.last_failure, "three files went in, one came out, and it said so"


def test_a_file_php2cpg_miscompiles_is_excluded_and_named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A `global` inside a closure makes php2cpg emit a node with two AST parents, and Joern then refuses to
    apply its dataflow overlay -- to the WHOLE graph, not that file. Every query over the repository fails at
    load, so one such file costs everything.

    Four lines reproduce it; `use` is irrelevant, and a `global` at function scope is fine. It appears in
    about 0.2% of files (1 of 637 in Paid Memberships Pro, 1 of 357 in WP Statistics, 0 of 169 in MW WP
    Form), so excluding it saves the other 99.8% -- and it is reported, not silently dropped.
    """
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    (tmp_path / "ok.php").write_text("<?php\nfunction a() { global $g; return $g; }\n")
    (tmp_path / "bad.php").write_text('<?php\nfunction f($n) {\n  h("p", function($p) { global $g; return $p . $g; });\n}\n')
    commands: list[list[str]] = []

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")
        commands.append(list(command))
        if "--script" in command:
            body = '---OUSAST-CPG-BEGIN---\n{"files": "1", "methods": "2"}\n---OUSAST-CPG-END---\n'
            return subprocess.CompletedProcess(args=command, returncode=0, stdout=body, stderr="")
        Path(command[command.index("-o") + 1]).write_text("cpg")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/bin/{name}")

    result = JoernBackend(runner=runner).build(tmp_path, language="php")

    assert result is not None
    assert [Path(name).name for name in result.unparsed] == ["bad.php"], "the miscompiled file is named"
    build = next(c for c in commands if "--script" not in c)
    assert "--exclude" in build and any("bad.php" in part for part in build), "and excluded from the build"
    assert not any("ok.php" in part for part in build if part != str(tmp_path)), "a global at function scope is fine"


def test_a_timed_out_query_kills_the_jvm_not_just_the_script(tmp_path: Path) -> None:
    """`joern` is a shell script that launches a JVM as a separate process.

    `subprocess.run(timeout=)` kills the script and leaves the JVM resident, holding its heap. Measured the
    hard way: after a day of 300s and 2,400s taint timeouts, four orphaned JVMs three hours old were still
    using about a gigabyte each and the machine ran out of memory. On CI that is an OOM rather than a
    degradation, and it would look like the scan needing more memory -- the wrong lesson entirely.

    Uses a real shell script that backgrounds a child, because the whole bug is about grandchildren.
    """
    import os
    import time

    from openultrasast.cpg.backend import JoernBackend

    marker = tmp_path / "child-alive"
    script = tmp_path / "fake-joern.sh"
    script.write_text(
        f"#!/bin/sh\n( while true; do echo x > '{marker}'; sleep 0.2; done ) &\necho $! > " + str(tmp_path / "child.pid") + "\nsleep 60\n"
    )
    script.chmod(0o755)

    started = time.monotonic()
    assert JoernBackend()._run([str(script)], timeout=2) is None, "a timeout reports nothing, never a verdict"
    assert time.monotonic() - started < 30, "and it does not wait for the script's own sleep"

    child = int((tmp_path / "child.pid").read_text().strip())
    time.sleep(0.5)
    alive = True
    try:
        os.kill(child, 0)
    except ProcessLookupError:
        alive = False
    if alive:  # cleanup, so a failure here does not leak the process it is complaining about
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(child, 9)
    assert not alive, "the grandchild JVM must die with the script, or every timeout leaks a gigabyte"


def test_a_built_cpg_can_dispose_of_its_scratch_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every build allocates a temp directory for the graph, its request files and joern's own working copy.

    Nothing reclaimed it. A day of scanning left 1,055 directories and 355MB behind, on a disk already at
    95%, and the scans that leaked hardest were the ones that failed -- which is the wrong way round.
    """
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    (tmp_path / "a.php").write_text("<?php function a() {}")

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")
        if "--script" in command:
            body = '---OUSAST-CPG-BEGIN---\n{"files": "1", "methods": "1"}\n---OUSAST-CPG-END---\n'
            return subprocess.CompletedProcess(args=command, returncode=0, stdout=body, stderr="")
        Path(command[command.index("-o") + 1]).write_text("cpg")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/bin/{name}")

    result = JoernBackend(runner=runner).build(tmp_path, language="php")
    assert result is not None and callable(result.cleanup)

    scratch = result.cpg_path.parent
    assert scratch.is_dir()
    result.cleanup()
    assert not scratch.exists(), "the scratch tree is gone once the caller is done with the graph"


def test_the_sweep_removes_only_old_scratch_and_only_ours(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A process killed mid-scan never runs its cleanup, which is how most of the 1,055 died. The sweep is
    the backstop -- and it must not touch a scan running in another process, nor anything that is not ours."""
    import os
    import time

    from openultrasast.cpg.backend import SCRATCH_MAX_AGE_SECONDS, SCRATCH_PREFIX, _sweep_stale_scratch

    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    old = tmp_path / f"{SCRATCH_PREFIX}old"
    fresh = tmp_path / f"{SCRATCH_PREFIX}fresh"
    foreign = tmp_path / "someone-elses-work"
    for path in (old, fresh, foreign):
        path.mkdir()
        (path / "cpg.bin").write_text("x")
    stale = time.time() - SCRATCH_MAX_AGE_SECONDS - 60
    os.utime(old, (stale, stale))
    os.utime(foreign, (stale, stale))

    _sweep_stale_scratch()

    assert not old.exists(), "an abandoned tree older than the ceiling is reclaimed"
    assert fresh.is_dir(), "a scan running right now is left alone"
    assert foreign.is_dir(), "and nothing outside this module's own prefix is ever touched"


def test_heap_reaches_the_forked_script_jvm(monkeypatch: pytest.MonkeyPatch) -> None:
    """`-J-Xmx` sizes only the launcher; the JVM that runs the script is forked without it, so the heap has
    to travel as JAVA_TOOL_OPTIONS too -- appended, so an operator's own options survive."""
    from openultrasast.cpg.backend import JoernBackend

    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Dfile.encoding=UTF-8")
    monkeypatch.setenv("OPENULTRASAST_CPG_HEAP_MB", "1536")
    backend = JoernBackend(runner=lambda c, **k: None)
    assert backend._heap_flag() == "-J-Xmx1536m"
    assert backend._jvm_env()["JAVA_TOOL_OPTIONS"] == "-Dfile.encoding=UTF-8 -Xmx1536m"
    monkeypatch.delenv("JAVA_TOOL_OPTIONS")
    assert JoernBackend(runner=lambda c, **k: None, heap_mb=1024)._jvm_env()["JAVA_TOOL_OPTIONS"] == "-Xmx1024m"


def test_a_frontend_build_gets_its_overlays_once_at_build_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """php2cpg writes a raw graph; `importCpg` computes every missing overlay each time a JVM opens it.

    That cost 54 s per query batch on a 637-file plugin and ran WP Statistics out of heap. The build runs
    `queries/overlay.sc` once, after the last frontend attempt, and the saved graph replaces the raw one
    under the same path -- and a failed overlay pass keeps the raw graph rather than losing it.
    """
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    commands: list[list[str]] = []

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        commands.append(list(command))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        if "--script" in command:
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout='---OUSAST-CPG-BEGIN---\n{"files": "1", "methods": "1"}\n---OUSAST-CPG-END---\n',
                stderr="",
            )
        Path(command[command.index("-o") + 1]).write_text("raw")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/joern/{name}")

    result = JoernBackend(runner=runner).build(tmp_path, language="php")
    assert result is not None
    overlay_runs = [c for c in commands if _is_overlay(c)]
    assert len(overlay_runs) == 1, "once, not per attempt"
    assert f"cpgFile={result.cpg_path}" in overlay_runs[0]
    assert result.cpg_path.read_text() == "cpg+overlays", "the overlaid graph replaced the raw one, same path"
    assert not (result.cpg_path.parent / "workspace").exists(), "Joern's workspace does not outlive the step"

    def failing(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return subprocess.CompletedProcess(args=command, returncode=1, stdout="", stderr="OutOfMemoryError")
        return runner(command, **kwargs)

    kept = JoernBackend(runner=failing).build(tmp_path, language="php")
    assert kept is not None and kept.cpg_path.read_text() == "raw", "a failed overlay pass degrades, it does not lose the graph"


def test_a_source_file_the_size_of_a_data_table_is_excluded_and_named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """WP Statistics vendors two browser-profile files of 1.6 MB and 1.5 MB, each one array literal. They
    were 60% of its graph, and the reaching-definitions overlay never finished on them -- 25 minutes at 4 GB,
    OutOfMemoryError at every `--max-num-def`, because one giant assignment is ONE definition. Nothing a
    scan could name flows through a lookup table, so a file over `MAX_SOURCE_BYTES` stays out of the build,
    is excluded by name, and is reported rather than silently dropped.
    """
    import subprocess

    from openultrasast.cpg.backend import MAX_SOURCE_BYTES, JoernBackend

    (tmp_path / "code.php").write_text("<?php\nfunction a($x) { return $x; }\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "profiles.php").write_text("<?php\nreturn [" + "'x' => 1,\n" * (MAX_SOURCE_BYTES // 10) + "];\n")
    commands: list[list[str]] = []

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")
        commands.append(list(command))
        if "--script" in command:
            body = '---OUSAST-CPG-BEGIN---\n{"files": "1", "methods": "1"}\n---OUSAST-CPG-END---\n'
            return subprocess.CompletedProcess(args=command, returncode=0, stdout=body, stderr="")
        Path(command[command.index("-o") + 1]).write_text("cpg")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/bin/{name}")

    result = JoernBackend(runner=runner).build(tmp_path, language="php")
    assert result is not None
    build = next(c for c in commands if "-o" in c)
    assert "--exclude" in build and "vendor/profiles.php" in build, "the data table is excluded from the build by name"
    assert not any("code.php" in part for part in build), "and the code is not"
    assert [Path(name).name for name in result.unparsed] == ["profiles.php"], "and it is reported, not silently dropped"


def test_a_clean_build_whose_census_cannot_be_taken_is_a_failed_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`cpg query census failed: timeout` was logged as a warning during a build whose every later query
    then timed out too. A graph that cannot answer the census inside the query timeout cannot answer a taint
    batch either, so the build fails, by name, instead of handing back a graph that reads as clean."""
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    (tmp_path / "a.php").write_text("<?php\nfunction a($x) { return $x; }\n")

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if _is_overlay(command):
            return _overlaid(command, kwargs.get("cwd"))
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")
        if "--script" in command:
            raise subprocess.TimeoutExpired(command, 1)  # the census never answers
        if "--output" in command:  # the joern-parse fallback the backend tries after a failed frontend build
            return subprocess.CompletedProcess(args=command, returncode=1, stdout="", stderr="")
        Path(command[command.index("-o") + 1]).write_text("cpg")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/bin/{name}")
    backend = JoernBackend(runner=runner)
    assert backend.build(tmp_path, language="php") is None
    assert "census" in backend.last_failure


def test_the_census_checks_the_instrument(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Two facts about the engine, each once wrong for a day with nothing saying so: a graph without its
    dataflow overlay saved (every batch recomputes it) and a worker JVM whose heap is not the configured one
    (the knob governs nothing). Both are named in the log; neither fails the scan."""
    import logging
    import subprocess

    from openultrasast.cpg.backend import BEGIN, END, JoernBackend

    (tmp_path / "a.php").write_text("<?php\n")
    monkeypatch.setenv("OPENULTRASAST_CPG_HEAP_MB", "2048")

    def census(body: str):  # type: ignore[no-untyped-def]
        def runner(command, **kwargs):  # type: ignore[no-untyped-def]
            return subprocess.CompletedProcess(args=command, returncode=0, stdout=f"{BEGIN}\n{body}\n{END}\n", stderr="")

        return runner

    monkeypatch.setattr("shutil.which", lambda name: f"/opt/bin/{name}")
    with caplog.at_level(logging.WARNING):
        JoernBackend(
            runner=census('{"files": "1", "methods": "1", "overlays": "base,controlflow,typerel,callgraph", "maxHeapMB": "1979"}')
        )._graph_census(tmp_path / "c.bin", tmp_path, "php")
    assert "not dataflowOss" in caplog.text and "recompute" in caplog.text
    assert "heap" not in caplog.text, "1979 MB for a 2048 MB setting is the JVM's own rounding, not a missing knob"
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        JoernBackend(
            runner=census(
                '{"files": "1", "methods": "1", "overlays": "base,controlflow,typerel,callgraph,dataflowOss", "maxHeapMB": "512"}'
            )
        )._graph_census(tmp_path / "c.bin", tmp_path, "php")
    assert "512 MB heap where 2048 MB is configured" in caplog.text
    assert "recompute" not in caplog.text


def test_a_build_that_fails_on_both_launchers_leaves_no_scratch_behind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Measured: a measurement that asked for the wrong language failed both `joern-parse` and the frontend
    and left a 9.6 MB `ousast-cpg-*` directory in /tmp. Failure paths dispose too."""
    import subprocess
    import tempfile

    from openultrasast.cpg.backend import JoernBackend

    (tmp_path / "a.php").write_text("<?php\n")
    scratch_root = tmp_path / "scratch"
    scratch_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch_root))

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")
        return subprocess.CompletedProcess(args=command, returncode=1, stdout="", stderr="boom")

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: f"/opt/bin/{name}")
    assert JoernBackend(runner=runner).build(tmp_path, language="javascript") is None
    assert list(scratch_root.iterdir()) == [], "the failed build's scratch directory is gone"


def test_the_closure_exclusion_stops_at_the_release_that_fixed_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """joern#6281 is fixed in v4.0.625. Below it the miscompiled file is excluded (the whole graph is the
    alternative); at or above it nothing is excluded, because a loss with nothing to buy is only a loss.
    An install whose version cannot be read keeps the exclusion: unknown is not "fixed"."""
    from openultrasast.cpg.backend import JoernBackend, joern_version

    (tmp_path / "bad.php").write_text('<?php\nfunction f($n) {\n  h("p", function($p) { global $g; return $p . $g; });\n}\n')

    def install(version: str) -> Path:
        home = tmp_path / f"joern-{version}"
        (home / "lib").mkdir(parents=True)
        (home / "lib" / f"io.joern.joern-cli-{version}.jar").write_bytes(b"")
        (home / "joern").write_text("#!/bin/sh\n")
        return home / "joern"

    old, new = install("4.0.623"), install("4.0.625")
    backend = JoernBackend(runner=lambda c, **k: None)

    monkeypatch.setattr("shutil.which", lambda name: str(old) if name == "joern" else None)
    assert joern_version() == (4, 0, 623)
    assert [Path(n).name for n in backend._files_with_frontend_defect(tmp_path, "php")] == ["bad.php"]

    monkeypatch.setattr("shutil.which", lambda name: str(new) if name == "joern" else None)
    assert joern_version() == (4, 0, 625)
    assert backend._files_with_frontend_defect(tmp_path, "php") == ()

    monkeypatch.setattr("shutil.which", lambda name: "/opt/bin/joern")
    assert joern_version() is None
    assert [Path(n).name for n in backend._files_with_frontend_defect(tmp_path, "php")] == ["bad.php"], "unknown keeps the workaround"


def test_the_interpreter_must_read_the_frontend_parser_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """php2cpg drives PHP-Parser through `php` from a script inside its own install. An interpreter that can
    read the repository but not that script parses nothing, exits 0, and looks like a frontend regression --
    measured with a second Joern install the containerised `php` had no mount for. Refused by name."""
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "a.php").write_text("<?php\n")
    install = tmp_path / "joern-cli"
    parser = install / "frontends" / "php2cpg" / "bin" / "php-parser" / "php-parser.php"
    parser.parent.mkdir(parents=True)
    parser.write_text("<?php\n")
    (install / "php2cpg").write_text("#!/bin/sh\n")

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        if "-r" in command:
            # The interpreter's view: the repository is readable, the frontend's install is not.
            return subprocess.CompletedProcess(args=command, returncode=3 if "php-parser.php" in command[-1] else 0, stdout="", stderr="")
        raise AssertionError("no build may start when the precondition fails")

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    monkeypatch.setattr("shutil.which", lambda name: str(install / "php2cpg") if name == "php2cpg" else f"/opt/bin/{name}")
    backend = JoernBackend(runner=runner)
    assert backend.build(tmp_path / "repo", language="php") is None
    assert "php-parser.php" in backend.last_failure and "mounts the repository but not this install" in backend.last_failure
