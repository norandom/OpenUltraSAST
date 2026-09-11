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
import signal
import subprocess
import tempfile
import time
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
# A slice's questions answer in seconds; a repository's do not. Measured on a 637-file WordPress plugin:
# 13 dominance requests answer in 50s (most of it loading the graph) and 2,500 taint requests exceed 300s.
# The constant was chosen when a "scan" meant an excerpt, and a repository scan is not a slower slice -- it
# is a different order of question, so the ceiling is configurable rather than a number to keep raising.
QUERY_TIMEOUT_SECONDS = 300
QUERY_TIMEOUT_ENV = "OPENULTRASAST_CPG_QUERY_TIMEOUT"
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
# The extensions that count as source for a language, used to ask whether a graph is missing anything.
_LANGUAGE_EXTENSIONS: dict[str, tuple[str, ...]] = {"php": (".php",)}
# The script a frontend drives THROUGH the interpreter, relative to the frontend binary's directory. The
# interpreter has to be able to read it as much as the repository: php2cpg 4.0.625 in an install the
# containerised `php` had no mount for parsed 1 of 637 files -- "Could not open input file" 64 times,
# exit 0 -- and read for a minute as a frontend regression.
_FRONTEND_PARSER: dict[str, str] = {"php": "frontends/php2cpg/bin/php-parser/php-parser.php"}

# A source file above this size is a data table, not code: WP Statistics carries two vendored browser
# profile files of 1.6 MB and 1.5 MB, each one array literal, and they were 60% of the graph (9.6 MB with
# them, 3.6 MB without). The reaching-definitions overlay does not merely slow down on them, it never
# finishes -- 25 minutes at 4 GB, OutOfMemoryError inside `initGen` at every cap `--max-num-def` offers,
# because a single assignment of a hundred-thousand-element literal is ONE definition. Nothing flows
# through a lookup table that a scan could name, and the file is named in the log so the exclusion is
# visible rather than silent. Task 5.13.
MAX_SOURCE_BYTES = 1_000_000

# The overlay a graph must carry for `reachableByFlows` to be answered from the saved graph rather than
# recomputed at every load; Joern names it so in `cpg.metaData.overlays`.
DATAFLOW_OVERLAY = "dataflowOss"
# Frontends that shell out to a separate interpreter, and the command that proves it can read a file.
# `php2cpg` drives PHP-Parser through whatever `php` is on PATH, so the frontend is only as good as that
# interpreter's view of the filesystem -- and a `php` that cannot see the tree does not fail, it produces an
# empty graph with exit status 0 and no warnings.
_INTERPRETERS: dict[str, str] = {"php": "php"}

# A `global` declaration inside a CLOSURE makes php2cpg 4.0.623 emit a node with two AST parents, and Joern
# then refuses to apply its own dataflow overlay to the graph:
#
#     java.lang.AssertionError: Iterable was expected to have exactly one element, but it has 2.
#     Hint: trying to resolve astParent ... (which is probably a malformed cpg)
#
# Four lines reproduce it, and the whole graph is lost -- not the file, the GRAPH, so every query over the
# repository fails at load:
#
#     <?php
#     function f($n) {
#         h("p", function($p) { global $g; return $p . $g; });
#     }
#
# Controlled: `use` is irrelevant (it asserts with and without), and a `global` at function scope is fine.
# Bisected from a 637-file plugin down to one file, one function, this construct.
#
# It is rare enough to exclude rather than to give up over: 1 of 637 files in Paid Memberships Pro, 1 of 357
# in WP Statistics, 0 of 169 in MW WP Form -- about 0.2%. Excluding them costs those files and saves the
# other 99.8%, which is the difference between a scan and no scan at all. They are reported as `unparsed`,
# so the coverage section names them rather than implying they were clean.
_CLOSURE = re.compile(r"\bfunction\s*\(")

# The release that fixes the miscompile (joernio/joern#6281, same root cause as #6269, fixed by #6270).
# At or above it the exclusion below is a loss with nothing to buy, so it is not applied.
CLOSURE_DEFECT_FIXED_IN = (4, 0, 625)
_JOERN_JAR = re.compile(r"^io\.joern\.joern-cli-(\d+)\.(\d+)\.(\d+)\.jar$")


def joern_version() -> tuple[int, int, int] | None:
    """The installed Joern's version, read off the jar beside the launcher; ``None`` when it cannot be told.

    The launcher is a shell script with no `--version`, and every release ships `lib/io.joern.joern-cli-X.Y.Z.jar`
    next to it. Unknown is unknown: a caller gating a workaround on this keeps the workaround.
    """
    launcher = shutil.which("joern")
    if launcher is None:
        return None
    lib = Path(launcher).resolve().parent / "lib"
    try:
        names = [entry.name for entry in lib.iterdir()]
    except OSError:
        return None
    for name in names:
        match = _JOERN_JAR.match(name)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return None


_GLOBAL_IN_BODY = re.compile(r"\bglobal\s+\$")
FRONTEND_BUILD_ATTEMPTS = 4

# Request fields that describe the REPOSITORY rather than the region, and are therefore identical in every
# request of a batch. They are hoisted to a single `--param` instead of being repeated thousands of times.
#
# Not a micro-optimisation. `hookCallbacks` is 16,270 characters on a 637-file plugin, and repeating it
# across 2,500 requests made a 42.5MB request file of which 41.7MB was the same string over and over. Joern
# parsed that with ujson inside a 2GB heap and the whole batch died in ForkJoinPool, which the driver
# correctly reported as `query_failed` for all 2,500 regions -- a whole-repository scan that decided nothing.
_SHARED_REQUEST_FIELDS = ("hookCallbacks", "dispatchApply")

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
    # Removes the scratch tree this CPG lives in. A build allocates a temp directory holding the graph, its
    # request files and joern's own workspace copy; nothing reclaimed it, and a day of scanning left 1,055
    # directories and 355MB behind on a disk that was already at 95%. The driver disposes in a `finally`.
    cleanup: Callable[[], None] | None = None


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
    query_timeout: int = field(default_factory=lambda: _configured_timeout())
    heap_mb: int = 0  # 0 means read the environment, then fall back to CPG_HEAP_MB
    queries_dir: Path = field(default_factory=lambda: QUERIES_DIR)
    # Why the last build refused, so the driver can name it instead of reporting a bare `cpg_build_failed`.
    last_failure: str = ""

    def available(self) -> bool:
        from .capability import has_cpg

        return has_cpg()

    def build(self, root: Path, *, language: str = "", exclude: Sequence[str] = ()) -> CpgResult | None:
        """Build a CPG for ``root``. ``None`` on any failure — the caller degrades, never guesses.

        ``language`` lets a failed ``joern-parse`` retry through the frontend directly, which is what Joern
        itself advises for a large codebase and what a 637-file WordPress plugin needed.
        """
        parse = shutil.which("joern-parse")
        if parse is None and os.environ.get("OPENULTRASAST_JOERN_PROBE", "").strip().lower() not in {"1", "on", "true", "yes"}:
            return None
        _sweep_stale_scratch()
        scratch = Path(tempfile.mkdtemp(prefix=SCRATCH_PREFIX))
        cpg_path = scratch / "cpg.bin"
        dispose = lambda: shutil.rmtree(scratch, ignore_errors=True)  # noqa: E731 -- one expression, named

        # THE PRECONDITION. Before anything is built, make the toolchain open one file from the tree and say
        # how big it is. Every instrument failure this project has had takes the same shape -- the input was
        # unreadable and the tool reported a plausible ZERO -- and it has cost four wrong diagnoses:
        #
        #   a php that could not see ~/.cache      -> "php2cpg cannot handle 637 files"  (it read none of them)
        #   a php whose stdio was proxied          -> "php2cpg drops half its batches"   (it dropped none)
        #   a container missing a bind mount       -> "0 files dropped", 5,703-byte graph
        #
        # None of those announced themselves. `file_exists()` returns false, the parser writes nothing, the
        # frontend exits 0, and "no errors" reads exactly like success. Checking the OUTPUT cannot separate
        # those from a genuinely empty repository; checking that the INPUT arrived can, and costs one exec.
        unreadable = self._interpreter_cannot_read(root, language)
        if unreadable:
            logger.error("cpg build refused for %s: %s", root, unreadable)
            self.last_failure = unreadable
            return None

        # A frontend whose failures are visible and retryable is worth more than one whose are not.
        if language.lower() in _PREFER_FRONTEND:
            self.last_failure = ""
            shards, unparsed = self._build_sharded(root, scratch, language, exclude=exclude)
            if not shards and self.last_failure:
                # A build that FAILED BY NAME is not one to retry through the other launcher: the graph the
                # census could not load would be rebuilt the same and never asked again.
                dispose()
                return None
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
                    cleanup=dispose,
                )
        command = [parse or "joern-parse", self._heap_flag(), str(root), "--output", str(cpg_path)]
        completed = self._run(command, timeout=self.build_timeout, cwd=scratch)
        unparsed = _unparsed_files(completed)
        if completed is None or completed.returncode != 0 or not cpg_path.is_file():
            detail = (completed.stderr or completed.stdout or "")[-400:] if completed is not None else "timeout"
            logger.warning("cpg build failed for %s: %s", root, detail)
            retried = self._build_with_frontend(root, cpg_path, scratch, language)
            if retried is None:
                dispose()  # a failed build's scratch is nobody's to sweep six hours later
                return None
            self._apply_overlays(cpg_path, scratch)
            unparsed = retried
        if unparsed:
            logger.warning("the frontend could not parse %d file(s) under %s: %s", len(unparsed), root, ", ".join(unparsed[:5]))
        return CpgResult(
            cpg_path=cpg_path,
            run=lambda query, params: self.query(cpg_path, query, params),
            run_batch=lambda query, requests: self.query_batch(cpg_path, query, requests),
            unparsed=unparsed,
            cleanup=dispose,
        )

    def _files_too_large_to_flow(self, root: Path, language: str) -> tuple[str, ...]:
        """Source files over `MAX_SOURCE_BYTES`, relative to the root, in the language the build is about."""
        extensions = _LANGUAGE_EXTENSIONS.get(language.lower())
        if not extensions:
            return ()
        found: list[str] = []
        for path in sorted(root.rglob("*")):
            if path.suffix.lower() not in extensions or not path.is_file():
                continue
            try:
                if path.stat().st_size > MAX_SOURCE_BYTES:
                    found.append(str(path.relative_to(root)))
            except OSError:
                continue
        return tuple(found)

    def _files_with_frontend_defect(self, root: Path, language: str) -> tuple[str, ...]:
        """Files carrying a construct this frontend miscompiles, found by reading the source.

        Excluding a file is a real loss and is only justified when the alternative is losing everything. It
        is here: one such file makes the whole graph unqueryable, so the choice is 99.8% of the repository or
        none of it. See `_CLOSURE` above for the construct, the reproducer, and the controls.
        """
        if language.lower() != "php":
            return ()
        version = joern_version()
        if version is not None and version >= CLOSURE_DEFECT_FIXED_IN:
            return ()  # fixed upstream; nothing to exclude and every file to keep
        found: list[str] = []
        for path in sorted(root.rglob("*.php")):
            if not path.is_file():
                continue
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            for match in _CLOSURE.finditer(text):
                opening = text.find("{", match.end())
                if opening < 0:
                    continue
                depth, index = 0, opening
                while index < len(text):
                    if text[index] == "{":
                        depth += 1
                    elif text[index] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    index += 1
                if _GLOBAL_IN_BODY.search(text[opening:index]):
                    found.append(str(path))
                    break
        return tuple(found)

    def _interpreter_cannot_read(self, root: Path, language: str) -> str:
        """``""`` when the language's interpreter can read the tree, else why not.

        Deliberately narrow: it proves one file is openable and non-empty FROM THE INTERPRETER'S OWN VIEW,
        which is the thing that differs when `php` is a wrapper, a container without the right bind mount, or
        a tree of symlinks pointing somewhere the sandbox cannot follow. Nothing else here can see that
        difference, because every other signal is downstream of the parse that never happened.
        """
        interpreter = _INTERPRETERS.get(language.lower())
        extensions = _LANGUAGE_EXTENSIONS.get(language.lower())
        if not interpreter or not extensions:
            return ""
        binary = shutil.which(interpreter)
        if binary is None:
            return ""  # absent is a different failure, and the frontend reports it plainly
        sample = next((path for path in sorted(root.rglob("*")) if path.suffix.lower() in extensions and path.is_file()), None)
        if sample is None:
            return ""  # nothing of this language to read; not the interpreter's fault
        probe = "$f = $argv[1]; if (!is_readable($f) || filesize($f) < 1) { exit(3); } exit(0);"
        completed = self._run([binary, "-r", probe, str(sample)], timeout=60)
        if completed is None:
            return f"the {interpreter} interpreter did not respond when asked to read {sample.name}"
        if completed.returncode != 0:
            return (
                f"the {interpreter} interpreter cannot read {sample}, so the frontend would parse nothing and "
                f"write an empty graph. Check that {interpreter} is a real interpreter with access to this "
                f"tree -- a container or wrapper without the right mount fails exactly this way."
            )
        # The same question about the frontend's own parser script, which the interpreter also has to open.
        frontend = _FRONTENDS.get(language.lower())
        relative = _FRONTEND_PARSER.get(language.lower())
        frontend_binary = shutil.which(frontend) if frontend else None
        if frontend_binary and relative:
            parser = Path(frontend_binary).resolve().parent / relative
            if parser.is_file():
                completed = self._run([binary, "-r", probe, str(parser)], timeout=60)
                if completed is not None and completed.returncode != 0:
                    return (
                        f"the {interpreter} interpreter cannot read {parser}, the script {frontend} drives it with, "
                        f"so every file would fail to parse and the graph would be empty. A container or wrapper "
                        f"that mounts the repository but not this install fails exactly this way."
                    )
        return ""

    def _build_sharded(
        self, root: Path, scratch: Path, language: str, exclude: Sequence[str] = ()
    ) -> tuple[tuple[Path, ...], tuple[str, ...]]:
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
        # Excluded from the start, because one of them costs the entire graph rather than itself.
        # `exclude` is the caller's: the vendored trees the `[[layout]]` facts put out of scope. This seam
        # imports only the standard library, so it is handed the names rather than reading the table.
        defective = (*exclude, *self._files_with_frontend_defect(root, language))
        if defective:
            logger.warning(
                "excluding %d file(s) under %s that php2cpg miscompiles (a `global` inside a closure): %s",
                len(defective),
                root,
                ", ".join(Path(name).name for name in defective[:5]),
            )
        oversized = self._files_too_large_to_flow(root, language)
        if oversized:
            logger.warning(
                "excluding %d file(s) under %s over %d bytes (data tables the dataflow overlay never finishes on): %s",
                len(oversized),
                root,
                MAX_SOURCE_BYTES,
                ", ".join(f"{Path(name).name} ({(root / name).stat().st_size // 1024} KB)" for name in oversized[:5]),
            )
            defective = (*defective, *oversized)

        main = scratch / "cpg.bin"
        dropped = self._build_with_retries(root, main, scratch, language, exclude=defective)
        if dropped is None:
            return (), ()
        if not dropped:
            # A build that warned about nothing is exactly the build that needs checking, because a graph
            # holding nothing arrives with no warnings at all. Silence is the symptom that has no symptom.
            census = self._graph_census(main, root, language)
            if census is None:
                # A graph the census cannot load inside the query timeout cannot answer a taint batch
                # either; every one would time out and read as "nothing here". Measured: `cpg query census
                # failed: timeout` was logged as a warning during a build whose every later query then
                # timed out, and the warning was read as a warning. A build with no usable graph has failed.
                self.last_failure = "the graph could not answer the census (timeout or no payload), so no query would be answered either"
                logger.error("cpg build for %s: %s", root, self.last_failure)
                return (), ()
            if census[0] < census[1] - len(defective):
                self.last_failure = f"the frontend reported no failures but the graph holds {census[0]} of {census[1]} source files"
                logger.error("cpg build for %s: %s", root, self.last_failure)
            return (main,), defective

        # A warning is a symptom, not a verdict. `php2cpg` logs `Failed to process` for files that are
        # nonetheless in the finished graph -- measured: a build reporting two drops produced a graph holding
        # both of its files and all 139 methods, the same size as a clean one. Splitting on that evidence is
        # actively harmful, because shards cannot see each other's flows: it cost a two-file WordPress pair
        # its CVE. So ask the graph before doing anything drastic to it.
        if self._graph_is_complete(main, root, language):
            logger.info("the frontend warned about %d file(s) under %s but the graph holds them all", len(dropped), root)
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

    def _graph_census(self, cpg_path: Path, root: Path, language: str) -> tuple[int, int] | None:
        """``(files_in_graph, files_expected)``, or ``None`` when the question cannot be asked.

        Always asked, not only when the frontend warned. The dangerous build is the SILENT one: a graph that
        holds nothing, reported with no errors at all, which is what an unreadable tree produces and what a
        genuinely clean scan of an empty repository looks like. A warning is a symptom; this is the evidence.
        """
        extensions = _LANGUAGE_EXTENSIONS.get(language.lower())
        if not extensions:
            return None
        expected = sum(1 for path in root.rglob("*") if path.suffix.lower() in extensions and path.is_file())
        if not expected:
            return (0, 0)  # nothing to count is not a failed count: an empty tree's graph is complete
        payload = self.query(cpg_path, "census", {})
        if not isinstance(payload, Mapping):
            return None
        self._check_instrument(payload)
        try:
            return int(str(payload.get("files", "0"))), expected
        except ValueError:
            return None

    def _check_instrument(self, census: Mapping[str, object]) -> None:
        """Two facts the census carries about the engine itself, checked because each was once silently wrong.

        A graph whose saved overlays lack the dataflow layer has it recomputed by every query batch -- 54 s
        of fixed cost per batch on a 637-file plugin, an OutOfMemoryError on a larger one -- and nothing
        else in the pipeline can tell. A worker JVM whose heap is not the configured one means the heap
        knob governs nothing, which was true for a day. Both are warnings, not failures: the scan still
        runs, slower or smaller, and the log says why. Task 5.13.
        """
        overlays = str(census.get("overlays", ""))
        if overlays and DATAFLOW_OVERLAY not in overlays.split(","):
            logger.warning(
                "the graph carries overlays [%s] but not %s: every query batch will recompute the dataflow layer",
                overlays,
                DATAFLOW_OVERLAY,
            )
        reported = str(census.get("maxHeapMB", ""))
        if reported.isdigit():
            configured = self._heap_mb()
            if abs(int(reported) - configured) > configured // 4:
                logger.warning(
                    "the query JVM reports a %s MB heap where %d MB is configured; the heap setting is not reaching it",
                    reported,
                    configured,
                )

    def _graph_is_complete(self, cpg_path: Path, root: Path, language: str) -> bool:
        """Conservative: when the census cannot be taken, the answer is "no" and the caller is careful."""
        census = self._graph_census(cpg_path, root, language)
        return census is not None and census[1] > 0 and census[0] >= census[1]

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

    def _apply_overlays(self, cpg_path: Path, scratch: Path) -> bool:
        """Run Joern's default overlays ONCE, at build time, and keep the result in the graph.

        A frontend writes a raw graph. Everything that answers a dataflow question -- the call graph, the
        type layer, the reaching-definitions pass `OssDataFlow` -- is an OVERLAY, and `importCpg` computes
        every overlay the graph lacks each time a JVM opens it. `joern-parse` applies them once and saves;
        `php2cpg` output has none, so from the day PHP builds went through the frontend directly
        (2026-09-09, 1ce7e9d) every query batch has paid the whole pass again before its first request.
        Measured: 54 s of fixed cost per batch on a 637-file plugin, and on WP Statistics the pass alone
        ran the default 2 GB heap out of memory after 21 minutes -- a graph the same tool had entailed
        CVE-2022-25148 on, one hour before the switch, from a `joern-parse` build. Task 5.13.

        `queries/overlay.sc` is that once: `importCpg`, `save`, and the saved graph replaces the raw one
        under the same path. (`joern-parse --overlaysonly` is the obvious tool and is broken in 4.0.623: joernio/joern#6283.)
        A failure here is logged and the raw graph kept, so the scan degrades to the old cost rather than
        losing its graph.
        """
        joern = shutil.which("joern")
        if joern is None:
            return False
        script = self.queries_dir / "overlay.sc"
        command = [joern, self._heap_flag(), "--script", str(script), "--param", f"cpgFile={cpg_path}"]
        completed = self._run(command, timeout=self.build_timeout, cwd=scratch)
        workspace = scratch / "workspace"
        saved = workspace / cpg_path.name / "cpg.bin"
        try:
            answered = completed is not None and completed.returncode == 0 and extract_payload(completed.stdout or "") is not None
            if not answered or not saved.is_file():
                detail = (completed.stderr or completed.stdout or "")[-400:] if completed is not None else "timeout"
                logger.warning("overlays could not be applied to %s, keeping the raw graph: %s", cpg_path, detail)
                return False
            saved.replace(cpg_path)
            return True
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def _build_with_retries(
        self, root: Path, cpg_path: Path, scratch: Path, language: str, exclude: Sequence[str] = ()
    ) -> tuple[str, ...] | None:
        outcome = self._build_with_retries_raw(root, cpg_path, scratch, language, exclude)
        if outcome is not None:
            self._apply_overlays(cpg_path, scratch)
        return outcome

    def _build_with_retries_raw(
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
        rendered = {rid: {k: _render(v) for k, v in req.items()} for rid, req in requests.items()}
        shared = _hoist_shared(rendered)
        payload = json.dumps(rendered)
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
        for name, value in shared.items():
            command += ["--param", f"{name}={value}"]
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

    def _heap_mb(self) -> int:
        if self.heap_mb > 0:
            return self.heap_mb
        configured = os.environ.get(HEAP_ENV, "").strip()
        return int(configured) if configured.isdigit() else CPG_HEAP_MB

    def _heap_flag(self) -> str:
        """``-J-Xmx``: both launchers forward ``-J`` arguments to the JVM they start."""
        return f"-J-Xmx{self._heap_mb()}m"

    def _jvm_env(self) -> dict[str, str]:
        """The heap for the JVM that does the work, which is NOT the one ``-J`` reaches.

        ``joern --script`` starts a launcher JVM and forks a second one to run the script
        (``replpp.scripting.NonForkingScriptRunner``, despite the name), and the ``-J-Xmx`` goes to the
        launcher only: 163 MB resident, next to a worker with no ``-Xmx`` at all sitting at 2.26 GB -- the
        JVM default of a quarter of physical memory. So ``OPENULTRASAST_CPG_HEAP_MB`` governed nothing on an
        8 GB machine and would silently take 16 GB on a 64 GB one. ``JAVA_TOOL_OPTIONS`` is read by every
        JVM at start-up, forked ones included, and is appended to rather than replaced so an operator's own
        options survive.
        """
        env = dict(os.environ)
        env["JAVA_TOOL_OPTIONS"] = f"{env.get('JAVA_TOOL_OPTIONS', '').strip()} -Xmx{self._heap_mb()}m".strip()
        return env

    def _run(self, command: list[str], *, timeout: int, cwd: Path | None = None) -> subprocess.CompletedProcess[str] | None:
        """Run one Joern command, and on timeout kill the whole PROCESS GROUP rather than the child.

        `joern` and `joern-parse` are shell scripts that launch a JVM as a separate process. Killing the
        script -- which is all `subprocess.run(timeout=)` does -- leaves that JVM running, holding its heap,
        for as long as the machine lasts. Every `query_failed: timeout` leaked about a gigabyte.

        Measured the hard way: after a day of 300s and 2,400s taint timeouts, four orphaned JVMs three hours
        old were still resident and the machine ran out of memory. On a CI runner doing several scans in a
        row it would OOM rather than merely degrade -- and it would look like the SCAN needing more memory,
        which is the wrong lesson entirely.
        """
        run = self.runner if self.runner is not None else subprocess.run
        if self.runner is not None:  # tests inject a fake runner and never spawn anything
            try:
                return run(command, capture_output=True, text=True, timeout=timeout, check=False, cwd=str(cwd) if cwd else None)
            except (OSError, subprocess.SubprocessError):
                return None
        try:
            with subprocess.Popen(  # noqa: S603 -- the command is built here, never from user input
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(cwd) if cwd else None,
                env=self._jvm_env(),
                start_new_session=True,  # its own process group, so the JVM dies with the script
            ) as process:
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    _terminate_group(process)
                    return None
                return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        except (OSError, subprocess.SubprocessError):
            return None


SCRATCH_PREFIX = "ousast-cpg-"
# How long an abandoned scratch tree may survive. Long enough that a scan running in another process is never
# disturbed, short enough that a machine scanning all day does not fill its disk.
SCRATCH_MAX_AGE_SECONDS = 6 * 60 * 60


def _sweep_stale_scratch() -> None:
    """Remove scratch trees older than `SCRATCH_MAX_AGE_SECONDS`, best effort and never fatal.

    Belt as well as braces: `cleanup` disposes of a scan's own tree, but a process killed mid-scan -- which
    is how most of them died here -- never runs its `finally`. Only directories under the system temp root
    carrying this module's own prefix are touched.
    """
    root = Path(tempfile.gettempdir())
    cutoff = time.time() - SCRATCH_MAX_AGE_SECONDS
    try:
        candidates = list(root.glob(f"{SCRATCH_PREFIX}*"))
    except OSError:
        return
    for path in candidates:
        try:
            if path.is_dir() and path.stat().st_mtime < cutoff:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:  # noqa: PERF203 -- one unreadable entry must not stop the sweep
            continue


def _terminate_group(process: subprocess.Popen[str]) -> None:
    """SIGTERM the process group, then SIGKILL what is left. Never raises: this is cleanup, not logic."""
    for signal_number in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(process.pid), signal_number)
        except (OSError, ProcessLookupError):
            return
        try:
            process.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            continue


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


def _hoist_shared(rendered: dict[str, dict[str, str]]) -> dict[str, str]:
    """Pull the repository-wide fields out of every request, returning them once.

    A field only lifts if it is IDENTICAL across the whole batch, so a value that genuinely varies per
    region stays where it belongs and nothing is silently shared between questions.
    """
    if not rendered:
        return {}
    shared: dict[str, str] = {}
    for name in _SHARED_REQUEST_FIELDS:
        values = {request.get(name, "") for request in rendered.values()}
        if len(values) == 1:
            value = values.pop()
            if value:
                shared[name] = value
            for request in rendered.values():
                request.pop(name, None)
    return shared


def _configured_timeout() -> int:
    """The query ceiling, from the environment or the default. Never zero or negative."""
    raw = os.environ.get(QUERY_TIMEOUT_ENV, "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return QUERY_TIMEOUT_SECONDS


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
