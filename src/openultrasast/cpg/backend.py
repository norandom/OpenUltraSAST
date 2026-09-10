"""The Joern subprocess seam — the single place this codebase touches a CPG engine (Req 4.1, 4.4, 4.5).

Joern is JVM/Scala. Everything crosses one subprocess boundary: ``joern-parse`` builds a ``cpg.bin`` from a
source tree, then ``joern --script`` runs a CPGQL script that prints a JSON payload. Nothing is imported
in-process, so the core install keeps ``dependencies = []`` and an absent engine costs a recorded reason
rather than a traceback.

Two rules hold everywhere below:

* **Fail closed.** A build or query that errors, times out, or prints something unparseable yields *no*
  verdict. The model layer then reports ``suspicion``. A wrong verdict is worse than no verdict — that is the
  whole reason this arbiter exists.
* **Fence the payload.** Joern prints a banner, compilation notices and a REPL prompt on stdout. The script
  brackets its JSON between markers so parsing can never swallow the noise around it.

We do not build a control-flow or dataflow engine here (Req 4.4): the CFG, PDG and call graph our flat IR
lacks are exactly what is being adopted.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)

QUERIES_DIR = Path(__file__).resolve().parent / "queries"

# The payload fence. Joern's stdout carries a banner and a prompt; the script prints these around its JSON.
BEGIN = "---OUSAST-CPG-BEGIN---"
END = "---OUSAST-CPG-END---"

BUILD_TIMEOUT_SECONDS = 900  # a large tree takes minutes; the go/no-go records what it actually cost
QUERY_TIMEOUT_SECONDS = 300
# A JVM with no -Xmx takes a quarter of physical RAM for its heap. On a contributor's laptop that is the
# difference between a scan running in the background and a scan the machine notices, and it made the
# first repository measurements unreproducible: runs were killed under memory pressure at different
# points, so the numbers described the host, not the engine. Bound it, and let the operator raise it.
CPG_HEAP_MB = 2048
HEAP_ENV = "OPENULTRASAST_CPG_HEAP_MB"

# `joern-parse` detects the language and then shells out to a frontend, and on a large tree it can fail where
# the frontend alone succeeds -- measured on a 637-file WordPress plugin, where joern-parse threw after
# applying overlays while `php2cpg` on the same tree produced a 4.3MB CPG with no errors. Joern's own message
# recommends the direct route for large codebases, so this is the documented fallback rather than a
# workaround. The names are Joern's frontend executables.
_FRONTENDS = {
    "php": "php2cpg",
    "python": "pysrc2cpg",
    "javascript": "jssrc2cpg",
    "typescript": "jssrc2cpg",
    "java": "javasrc2cpg",
    "c": "c2cpg",
    "c_cpp": "c2cpg",
}

# Languages where the frontend is run DIRECTLY instead of through `joern-parse`, and how many times.
#
# `joern-parse` invokes the same frontend, but measured on one WordPress slice it succeeds far less often
# and, worse, tells you nothing when it does not: thirteen lines of output, exit status 0, "Successfully
# wrote graph", and a graph with no methods in it. The frontend logs a warning per file it drops.
#
#     joern-parse   5 of 8 builds usable
#     php2cpg      11 of 12 builds usable, and names the files it dropped
#
# php2cpg 4.0.623 fails intermittently when it reads its PHP parser's output: the parser's bytes are
# complete and valid -- verified by capturing them -- so the defect is inside the frontend's own JSON
# reading, and nothing outside it can repair a given attempt. What CAN be done is notice (the warning is
# right there) and try again. Compacting the parser's output to a fifth of its size, running the parser
# through a shim, and pinning `ForkJoinPool.common.parallelism=1` were each tried and each changed nothing.
_PREFER_FRONTEND = frozenset({"php"})
FRONTEND_BUILD_ATTEMPTS = 4

Runner = Callable[..., subprocess.CompletedProcess[str]]


def extract_payload(stdout: str) -> object | None:
    """The JSON between the fence markers, or ``None`` when it is absent or malformed."""
    start = stdout.find(BEGIN)
    end = stdout.find(END, start + 1) if start >= 0 else -1
    if start < 0 or end < 0:
        return None
    body = stdout[start + len(BEGIN) : end].strip()
    # Joern logs to STDOUT, and it does so while the script is running -- so a log line can land INSIDE the
    # fence, ahead of the payload. `[INFO ] Attempting to determine flows from empty list of sources.` did
    # exactly that and cost a 205-request batch every one of its answers, reported as `query_failed`. The
    # payload is always one JSON object or array, so trim to its own brackets rather than trusting the fence
    # to contain nothing else.
    payload = _decoded_json(body)
    if payload is None:
        logger.debug("cpg query payload was not valid JSON")
    return payload


def _decoded_json(body: str) -> object | None:
    """The first complete JSON document in ``body``, ignoring whatever Joern logged around it.

    Trimming to the outermost brackets is the obvious approach and the wrong one: a log line is `[INFO ] ...`,
    so its own bracket comes first. This starts a decode at each line that opens a document and keeps the
    first that parses, which is exactly one line of work when nothing was logged.
    """
    decoder = json.JSONDecoder()
    offset = 0
    for line in body.splitlines(keepends=True):
        if line.lstrip().startswith(("{", "[")):
            try:
                payload, _ = decoder.raw_decode(body, offset + len(line) - len(line.lstrip()))
            except ValueError:
                pass
            else:
                decoded: object = payload
                return decoded
        offset += len(line)
    return None


@dataclass(frozen=True)
class CpgResult:
    """A built CPG and the ways to query it. Opaque: only ``model/`` reads through these.

    ``run_batch`` is optional so a backend that cannot answer many questions in one invocation still fits
    this shape -- the driver falls back to ``run``, once per request. But a backend that CAN batch must
    attach it HERE, because this is the driver's only way to discover the capability. Leaving it off does
    not fail: it silently costs a JVM per region, which is how batching sat unreachable behind a passing
    test suite until a repository scan made the cost visible.
    """

    cpg_path: Path
    run: Callable[[str, Mapping[str, object]], object | None]
    run_batch: Callable[[str, Mapping[str, Mapping[str, object]]], dict[str, list[object]] | None] | None = None
    # Files the frontend read and could not turn into a graph. A CPG is not all-or-nothing: `php2cpg` logs a
    # warning per file it drops and still exits 0 with a graph that is missing them, so a scan over the
    # remainder is a scan of LESS CODE THAN IT WAS ASKED ABOUT, and silence about those files is the same
    # quiet failure as an empty query result. The names travel with the CPG so the driver can say so.
    unparsed: tuple[str, ...] = ()


class CpgBackend(Protocol):
    def available(self) -> bool: ...

    def build(self, root: Path) -> CpgResult | None: ...


@dataclass
class NullBackend:
    """No engine. Every verdict degrades to ``suspicion`` and the caller records ``cpg_unavailable``."""

    reason: str = "cpg_unavailable"

    def available(self) -> bool:
        return False

    def build(self, root: Path) -> CpgResult | None:
        del root
        return None


@dataclass
class JoernBackend:
    """``joern-parse`` then ``joern --script``, both out of process and both timeout-bounded."""

    runner: Runner | None = None
    build_timeout: int = BUILD_TIMEOUT_SECONDS
    query_timeout: int = QUERY_TIMEOUT_SECONDS
    heap_mb: int = 0  # 0 means read the environment, then fall back to CPG_HEAP_MB
    queries_dir: Path = field(default_factory=lambda: QUERIES_DIR)

    def available(self) -> bool:
        from .capability import has_cpg

        return has_cpg()

    def build(self, root: Path, *, language: str = "") -> CpgResult | None:
        """Build a CPG for ``root``. ``None`` on any failure — the caller degrades, never guesses.

        ``language`` lets a failed ``joern-parse`` retry through the frontend directly, which is what Joern
        itself advises for a large codebase and what a 637-file WordPress plugin needed.
        """
        parse = shutil.which("joern-parse")
        if parse is None and os.environ.get("OPENULTRASAST_JOERN_PROBE", "").strip().lower() not in {"1", "on", "true", "yes"}:
            return None
        scratch = Path(tempfile.mkdtemp(prefix="ousast-cpg-"))
        cpg_path = scratch / "cpg.bin"

        # A frontend whose failures are visible and retryable is worth more than one whose are not.
        if language.lower() in _PREFER_FRONTEND:
            shards, unparsed = self._build_sharded(root, scratch, language)
            if shards:
                if unparsed:
                    logger.warning("the frontend could not parse %d file(s) under %s: %s", len(unparsed), root, ", ".join(unparsed[:5]))
                if len(shards) > 1:
                    logger.info("querying %d cpg shards for %s; flows that cross them are not visible", len(shards), root)
                return CpgResult(
                    cpg_path=shards[0],
                    run=lambda query, params: self.query_across(shards, query, params),
                    run_batch=lambda query, requests: self.query_batch_across(shards, query, requests),
                    unparsed=unparsed,
                )
        command = [parse or "joern-parse", self._heap_flag(), str(root), "--output", str(cpg_path)]
        completed = self._run(command, timeout=self.build_timeout, cwd=scratch)
        unparsed = _unparsed_files(completed)
        if completed is None or completed.returncode != 0 or not cpg_path.is_file():
            detail = (completed.stderr or completed.stdout or "")[-400:] if completed is not None else "timeout"
            logger.warning("cpg build failed for %s: %s", root, detail)
            retried = self._build_with_frontend(root, cpg_path, scratch, language)
            if retried is None:
                return None
            unparsed = retried
        if unparsed:
            logger.warning("the frontend could not parse %d file(s) under %s: %s", len(unparsed), root, ", ".join(unparsed[:5]))
        return CpgResult(
            cpg_path=cpg_path,
            run=lambda query, params: self.query(cpg_path, query, params),
            run_batch=lambda query, requests: self.query_batch(cpg_path, query, requests),
            unparsed=unparsed,
        )

    def _build_sharded(self, root: Path, scratch: Path, language: str) -> tuple[tuple[Path, ...], tuple[str, ...]]:
        """Build the tree, and give the files it refuses a CPG of their OWN rather than losing them.

        A frontend that drops a file drops it from the only graph there is, and every question about that
        file then has no answer -- which is how a 637-file plugin became a scan of nothing. But the same
        files build perfectly well on their own: the failure is per-invocation, not per-file. So a file the
        main build refuses is excluded from it and put in a second CPG, and the queries run over both.

        What this does NOT buy is a flow that crosses the shard boundary. A source in the excluded file and
        its sink in the rest of the tree is invisible, and no merging of results can recover it -- which is
        why the driver reports the split rather than quietly serving a partial answer.

        Returns the CPGs to query and the files that defeated even a shard of their own.
        """
        main = scratch / "cpg.bin"
        dropped = self._build_with_retries(root, main, scratch, language)
        if dropped is None:
            return (), ()
        if not dropped:
            return (main,), ()

        # Second pass over the same tree, this time telling the frontend to leave the difficult files alone,
        # so the rest of the repository is analysed instead of nothing being analysed.
        remainder = self._build_with_retries(root, main, scratch, language, exclude=dropped)
        shards: list[Path] = []
        if remainder is not None and main.is_file():
            shards.append(main)

        island = self._island_root(root, scratch, dropped)
        if island is None:
            return tuple(shards), dropped
        second = scratch / "cpg-excluded.bin"
        still = self._build_with_retries(island, second, scratch, language)
        if still is not None and second.is_file():
            shards.append(second)
            return tuple(shards), tuple(still)
        return tuple(shards), dropped

    def _island_root(self, root: Path, scratch: Path, files: Sequence[str]) -> Path | None:
        """A tree holding only ``files``, at their original relative paths.

        The paths have to be preserved: a region asks about `classes/class.memberorder.php`, and the queries
        match a method's filename by suffix, so a flattened copy would answer about a file nobody asked
        about. Symlinks, because the alternative is copying a repository to analyse it.
        """
        island = scratch / "excluded-root"
        made = 0
        for name in files:
            source = Path(name)
            if not source.is_absolute():
                source = root / name
            if not source.is_file():
                continue
            try:
                relative = source.relative_to(root)
            except ValueError:
                relative = Path(source.name)
            destination = island / relative
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not destination.exists():
                    destination.symlink_to(source)
                made += 1
            except OSError as exc:  # noqa: PERF203 - one bad file must not lose the rest
                logger.warning("could not stage %s for its own cpg: %s", source, exc)
        return island if made else None

    def query_across(self, shards: Sequence[Path], query: str, params: Mapping[str, object]) -> object | None:
        """One question over every shard, answers concatenated. ``None`` only when no shard could answer."""
        merged: list[object] = []
        answered = 0
        for shard in shards:
            rows = self.query(shard, query, params)
            if rows is None:
                continue
            answered += 1
            if isinstance(rows, list):
                merged.extend(rows)
        return merged if answered else None

    def query_batch_across(
        self, shards: Sequence[Path], query: str, requests: Mapping[str, Mapping[str, object]]
    ) -> dict[str, list[object]] | None:
        """The batch over every shard, rows concatenated per request id.

        The census is summed rather than taken from one shard, and carries the shard count, because
        `cpg_empty` has to mean "no graph anywhere" and not "the first of two graphs was small".
        """
        merged: dict[str, list[object]] = {}
        methods = 0
        files = 0
        answered = 0
        for shard in shards:
            one = self.query_batch(shard, query, requests)
            if one is None:
                continue
            answered += 1
            census = one.pop("__census__", None)
            if census and isinstance(census[0], Mapping):
                methods += int(str(census[0].get("methods", "0")) or 0)
                files += int(str(census[0].get("files", "0")) or 0)
            for rid, rows in one.items():
                merged.setdefault(rid, []).extend(rows)
        if not answered:
            return None
        merged["__census__"] = [{"methods": str(methods), "files": str(files), "shards": str(len(shards))}]
        return merged

    def _build_with_retries(
        self, root: Path, cpg_path: Path, scratch: Path, language: str, exclude: Sequence[str] = ()
    ) -> tuple[str, ...] | None:
        """Build through the frontend, trying again while it reports files it could not parse.

        Retrying is only sound because the failure is INTERMITTENT and the frontend says when it happened.
        Retrying a silent failure would be superstition; retrying a reported one is just using the report.
        The loop stops at the first clean build, and returns the last attempt's dropped files rather than
        pretending a partial graph is a whole one.

        ``None`` means there was nothing to build with, so the caller falls back to ``joern-parse``.
        """
        best: tuple[str, ...] | None = None
        for attempt in range(FRONTEND_BUILD_ATTEMPTS):
            unparsed = self._build_with_frontend(root, cpg_path, scratch, language, exclude)
            if unparsed is None:
                return best  # the frontend is missing or failed outright; keep any earlier partial build
            if not unparsed:
                return ()
            best = unparsed
            logger.info(
                "frontend dropped %d file(s) on attempt %d of %d for %s; retrying",
                len(unparsed),
                attempt + 1,
                FRONTEND_BUILD_ATTEMPTS,
                root,
            )
        return best

    def _build_with_frontend(
        self, root: Path, cpg_path: Path, scratch: Path, language: str, exclude: Sequence[str] = ()
    ) -> tuple[str, ...] | None:
        """Retry the build through the language frontend alone.

        Returns the files the frontend dropped -- possibly none -- or ``None`` when there is nothing to retry
        with or the retry failed too. An empty tuple and ``None`` are different answers here for the same
        reason they are everywhere else in this module: one means "built, and complete", the other means
        "could not build".
        """
        frontend = _FRONTENDS.get(language.lower())
        if not frontend:
            return None
        binary = shutil.which(frontend)
        if binary is None:
            logger.warning("no frontend %s on PATH to retry the build for %s", frontend, root)
            return None
        command = [binary, self._heap_flag(), str(root), "-o", str(cpg_path)]
        for name in exclude:
            command += ["--exclude", name]
        completed = self._run(command, timeout=self.build_timeout, cwd=scratch)
        if completed is None or completed.returncode != 0 or not cpg_path.is_file():
            detail = (completed.stderr or completed.stdout or "")[-400:] if completed is not None else "timeout"
            logger.warning("%s also failed for %s: %s", frontend, root, detail)
            return None
        logger.info("built the cpg for %s with %s after joern-parse failed", root, frontend)
        return _unparsed_files(completed)

    def query_batch(self, cpg_path: Path, query: str, requests: Mapping[str, Mapping[str, object]]) -> dict[str, list[object]] | None:
        """Run ONE script invocation carrying many requests, keyed back to their ids.

        JVM startup, not CPG construction, is what dominates a repository scan: every ``joern --script`` call
        starts a JVM of roughly thirty seconds, and issuing one per region per family put a ten-line Python
        file at four minutes and a thousand regions at about fifty hours. The CPG is already built and loaded
        by then; the work itself is milliseconds. So the batch carries the whole scan's questions in one
        parameter and the script loops over them.

        Fails closed like every other path here, and says which kind of nothing it is: an engine that could
        not answer returns ``None`` while a genuine empty answer is ``{}``. That distinction is the whole
        point -- "no rows" and "could not ask" look identical to a caller that only sees a dict, and a
        117k-line PHP CPG that threw while loading turned a failed scan into a clean bill of health.
        """
        script = self.queries_dir / f"{query}.sc"
        if not script.is_file():
            logger.warning("no such cpg query: %s", script)
            return None
        payload = json.dumps({rid: {k: _render(v) for k, v in req.items()} for rid, req in requests.items()})
        # Through a FILE, never the command line. Linux caps a single argument at MAX_ARG_STRLEN (128KB)
        # whatever ARG_MAX says, and a repository blows through that: 2500 taint requests over a 637-file
        # WordPress plugin is a 1.49MB payload. execve returns E2BIG, `_run` catches the OSError, this returns
        # {} -- and {} reads as "no rows found". The scan reported 500 regions examined and nothing found, in
        # 0.05 seconds of taint query, which is a quiet failure of exactly the kind the rung ladder cannot
        # catch because no verdict was ever produced to label.
        requests_file = cpg_path.parent / f"{query}-requests.json"
        try:
            requests_file.write_text(payload)
        except OSError as exc:
            logger.warning("could not stage cpg batch %s: %s", query, exc)
            return None
        command = [
            shutil.which("joern") or "joern",
            self._heap_flag(),
            "--script",
            str(script),
            "--param",
            f"cpgFile={cpg_path}",
            "--param",
            f"requestsFile={requests_file}",
        ]
        completed = self._run(command, timeout=self.query_timeout, cwd=cpg_path.parent)
        if completed is None or completed.returncode != 0:
            detail = (completed.stderr or "")[-400:] if completed is not None else "timeout"
            logger.warning("cpg batch %s failed: %s", query, detail)
            return None
        parsed = extract_payload(completed.stdout or "")
        if not isinstance(parsed, Mapping):
            # Unparseable output is a failure, not an empty answer. A 117k-line PHP CPG that throws while
            # loading printed a stack trace and no payload, and returning {} made the whole scan read as a
            # clean repository -- 500 regions examined, nothing found, no degradation recorded.
            logger.warning("cpg batch %s returned no parseable payload", query)
            return None
        # A request the engine did not answer is absent, not empty: the caller must be able to tell them apart.
        return {str(rid): list(rows) for rid, rows in parsed.items() if isinstance(rows, list)}

    def query(self, cpg_path: Path, query: str, params: Mapping[str, object]) -> object | None:
        """Run a shipped CPGQL script against a built CPG and return its fenced JSON payload."""
        script = self.queries_dir / f"{query}.sc"
        if not script.is_file():
            logger.warning("no such cpg query: %s", script)
            return None
        command = [shutil.which("joern") or "joern", self._heap_flag(), "--script", str(script), "--param", f"cpgFile={cpg_path}"]
        for key, value in sorted(params.items()):
            command += ["--param", f"{key}={_render(value)}"]
        # Joern writes a `workspace/` beside the working directory; run it inside the CPG's own scratch dir so
        # it can never land in the repository being analysed.
        completed = self._run(command, timeout=self.query_timeout, cwd=cpg_path.parent)
        if completed is None or completed.returncode != 0:
            detail = (completed.stderr or "")[-400:] if completed is not None else "timeout"
            logger.warning("cpg query %s failed: %s", query, detail)
            return None
        return extract_payload(completed.stdout or "")

    def _heap_flag(self) -> str:
        """``-J-Xmx``: both launchers forward ``-J`` arguments to the JVM."""
        if self.heap_mb > 0:
            return f"-J-Xmx{self.heap_mb}m"
        configured = os.environ.get(HEAP_ENV, "").strip()
        return f"-J-Xmx{configured if configured.isdigit() else CPG_HEAP_MB}m"

    def _run(self, command: list[str], *, timeout: int, cwd: Path | None = None) -> subprocess.CompletedProcess[str] | None:
        run = self.runner if self.runner is not None else subprocess.run
        try:
            return run(command, capture_output=True, text=True, timeout=timeout, check=False, cwd=str(cwd) if cwd else None)
        except (OSError, subprocess.SubprocessError):
            return None


# Every Joern frontend logs a dropped file the same way, at WARN, and then carries on:
#
#     WARN  AstCreationPass   Failed to process '/abs/path/to/file.php'
#
# The quotes are part of the line, which is what makes this safely greppable rather than a guess at column
# positions. Several passes report the same file, so the caller de-duplicates.
_UNPARSED = re.compile(r"Failed to process '([^']+)'")


def _unparsed_files(completed: subprocess.CompletedProcess[str] | None) -> tuple[str, ...]:
    """The files the frontend read and dropped, in first-seen order.

    This exists because a Joern frontend fails a file WITHOUT failing the build. `php2cpg` 4.0.623 feeds
    several files to one `php-parse` process and reads its stdout and stderr merged; php-parse writes a
    `====> File <next>:` banner to stderr the moment it starts the next file, while the previous file's JSON
    -- megabytes of it -- is still draining from a block-buffered stdout. The banner lands inside the JSON,
    ujson reports `expected json value got "="`, and the frontend drops that file. Reproducibly, on real
    plugin code:

        one 1834-line file alone            -> a 142KB CPG, no failures
        the same file plus a two-line file  -> a 5.7KB CPG, BOTH files dropped, exit status 0

    So the size that matters is one file's AST dump, not the repository's, and one oversized file can empty
    the whole graph. Before this, that arrived as a scan reporting no findings and no degradations -- a clean
    bill of health over a graph containing nothing at all.
    """
    if completed is None:
        return ()
    seen: dict[str, None] = {}
    for stream in (completed.stdout or "", completed.stderr or ""):
        for match in _UNPARSED.finditer(stream):
            seen.setdefault(match.group(1), None)
    return tuple(seen)


def _render(value: object) -> str:
    """CPGQL parameters are strings; a sequence becomes a comma-separated list the script splits."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, set, frozenset)):
        return ",".join(sorted(str(item) for item in value))
    return str(value)


def resolve_cpg_backend(*, runner: Runner | None = None) -> CpgBackend:
    """The backend for this machine: Joern when it is installed, else the null one."""
    from .capability import has_cpg

    return JoernBackend(runner=runner) if has_cpg() else NullBackend()


__all__ = [
    "BEGIN",
    "END",
    "CpgBackend",
    "CpgResult",
    "JoernBackend",
    "NullBackend",
    "extract_payload",
    "resolve_cpg_backend",
]
