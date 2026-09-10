"""model-grounded-detection task 2.1: the Joern seam, out of process and capability-detected.

Joern is a JVM tool. The whole integration is one subprocess boundary so that the core install stays
zero-dependency and an absent engine degrades to `suspicion` with a recorded reason rather than a traceback.
Nothing here imports a JVM binding, and every test runs with Joern absent.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest


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
        "subprocess",
        "tempfile",
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
        if "-r" in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")
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
