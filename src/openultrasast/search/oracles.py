"""Owned canaries. Only app captures enter these oracles, never attack output.

The attacker may supply CLI arguments through TARGET. Fixtures and app config
are mounted only in the app sandbox. Nonces are fresh per run and absent from
artefact env. A browser executor is trusted verifier code, never a demo script.
"""

from __future__ import annotations

import json
import os
import secrets
import selectors
import shutil
import sqlite3
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Protocol
from urllib.parse import quote

if __name__ != "__main__":
    from . import _sandbox


@dataclass(frozen=True)
class Canary:
    root: Path
    nonce: str

    @classmethod
    def fresh(cls, root: Path) -> Canary:
        root.mkdir(mode=0o700)
        return cls(root, secrets.token_hex(24))


class Oracle(Protocol):
    namespace_pid: int | None
    placeholders: dict[str, str]

    def prepare(self, canary: Canary) -> dict[str, str]: ...
    def capture(self, output: str) -> None: ...
    def observe(self) -> tuple[bool, str]: ...
    def close(self) -> None: ...


class OutputOracle:
    namespace_pid: int | None = None

    def prepare(self, canary: Canary) -> dict[str, str]:
        self.canary = canary
        self.seen = False
        self.placeholders: dict[str, str] = {}
        return {}

    def capture(self, output: str) -> None:
        self.seen |= self.canary.nonce in output

    def observe(self) -> tuple[bool, str]:
        return self.seen, "canary in verifier-captured app output" if self.seen else "no canary in app output"

    def close(self) -> None:
        pass


class PathOracle(OutputOracle):
    def prepare(self, canary: Canary) -> dict[str, str]:
        super().prepare(canary)
        (canary.root / "public").mkdir()
        (canary.root / "canary").write_text(canary.nonce)
        (canary.root / "canary").chmod(0o600)
        self.placeholders = {"served_root": "/fixture/public"}
        return {"SERVED_ROOT": "/fixture/public"}


class SQLOracle(OutputOracle):
    def prepare(self, canary: Canary) -> dict[str, str]:
        super().prepare(canary)
        with sqlite3.connect(canary.root / "fixture.db") as db:
            db.execute("CREATE TABLE records (name TEXT, value TEXT, public INTEGER)")
            db.executemany("INSERT INTO records VALUES (?, ?, ?)", [("ordinary", "public value", 1), ("secret", canary.nonce, 0)])
        (canary.root / "fixture.db").chmod(0o600)
        self.placeholders = {"database_path": "/fixture/fixture.db", "database_url": "sqlite:////fixture/fixture.db"}
        return {"DATABASE": "/fixture/fixture.db"}


class CommandOracle(OutputOracle):
    def prepare(self, canary: Canary) -> dict[str, str]:
        super().prepare(canary)
        # Marker is in app-only writable scratch, inaccessible in artefact sandbox.
        self.marker = canary.root / "marker"
        self.placeholders = {"marker_dir": "/scratch"}
        return {}

    def observe(self) -> tuple[bool, str]:
        observed = self.marker.is_file() and not self.marker.is_symlink()
        return observed, "injected command marker exists" if observed else "no command marker"


class SSRFOracle(OutputOracle):
    """Separate listener process and private loopback namespace; no external egress."""

    task_boundary = False
    process: subprocess.Popen[str] | None = None

    def prepare(self, canary: Canary) -> dict[str, str]:
        super().prepare(canary)
        self.process = subprocess.Popen(
            [
                *(
                    []
                    if self.task_boundary
                    else ["/usr/bin/unshare", *(["--user", "--map-root-user"] if _sandbox.isolation_mode() == "userns" else []), "--net"]
                ),
                "/usr/bin/python3",
                "-I",
                str(Path(__file__).resolve()),
                "--task-listener" if self.task_boundary else "--listener",
                canary.nonce,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert self.process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if not selector.select(3):
                raise OSError("listener namespace readiness timed out")
            line = self.process.stdout.readline()
        if not line:
            raise OSError("private loopback listener unavailable")
        self.namespace_pid, port = json.loads(line)
        if self.task_boundary:
            self.namespace_pid = None
        self.placeholders = {"callback_url": f"http://127.0.0.1:{port}/{canary.nonce}"}  # loopback: private oracle listener
        return {"CALLBACK_URL": self.placeholders["callback_url"]}

    def observe(self) -> tuple[bool, str]:
        assert self.process is not None and self.process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            observed = bool(selector.select(0.2)) and self.process.stdout.readline().strip() == "observed"
        return observed, "nonce request received" if observed else "no nonce request"

    def close(self) -> None:
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=3)
            if self.process.stdout:
                self.process.stdout.close()


class BrowserExecutor:
    """Run captured HTML with a verifier-owned alert canary.

    Payloads call alert("ousast-xss"). Reflection/escaped HTML cannot set the fresh
    DOM marker. A restrictive CSP disables external resources and connections;
    Chromium's sandbox stays enabled for userns; root containers use the outer
    boundary and drop the browser uid. Each capture uses a fresh profile.
    Launch failures are unavailable execution, never a negative observation.
    """

    def __init__(self, binary: str | None = None, *, timeout_seconds: float = 15, task_boundary: bool = False) -> None:
        selected = binary or shutil.which("chromium") or shutil.which("chromium-browser")
        self.timeout_seconds = timeout_seconds
        if not selected:
            raise OSError("headless chromium unavailable")
        self.binary: str = selected
        self.task_boundary = task_boundary
        self.no_sandbox = task_boundary or _sandbox.isolation_mode() == "root-no-userns"

    def __call__(self, document: str, nonce: str) -> bool:
        marker = secrets.token_hex(24)
        # Neither the marker nor its attribute appears in app output. The bootstrap
        # source does appear in dump-dom, so inspect an actual DOM attribute only.
        attribute = "data-proof-" + secrets.token_hex(12)
        prelude = (
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
            "script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
            '<script>window.alert=function(value){if(value==="ousast-xss"||value==='
            + json.dumps(nonce)
            + "){document.documentElement.setAttribute("
            + json.dumps(attribute)
            + ","
            + json.dumps(marker)
            + ");}};</script>"
        )
        with tempfile.TemporaryDirectory(prefix="ousast-browser-") as profile:
            # HTML can navigate even with CSP. A private network namespace, not
            # browser flags, is the no-egress boundary. Expose runtime only.
            if not self.task_boundary:
                _sandbox.writable_directory(Path(profile))
            namespaces = ["--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net"] if self.no_sandbox else ["--unshare-all"]
            sandbox = ["bwrap", *namespaces, "--die-with-parent", "--new-session", *_sandbox.capability_args()]
            for path in ("/usr", "/bin", "/lib", "/lib64"):
                if Path(path).exists():
                    sandbox += ["--ro-bind", path, path]
            sandbox += [
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--tmpfs",
                "/tmp",
                "--bind",
                profile,
                "/profile",
                "--setenv",
                "HOME",
                "/profile",
                "--",
            ]
            if self.task_boundary:
                sandbox = []
            try:
                done = subprocess.run(
                    [
                        *sandbox,
                        *(_sandbox.drop_privileges() if self.no_sandbox and not self.task_boundary else []),
                        self.binary,
                        *(["--no-sandbox"] if self.no_sandbox else []),
                        "--headless",
                        "--dump-dom",
                        "--disable-gpu",
                        "--disable-background-networking",
                        "--disable-extensions",
                        "--no-first-run",
                        "--no-default-browser-check",
                        "--disable-sync",
                        "--user-data-dir=" + (profile if self.task_boundary else "/profile"),
                        "--virtual-time-budget=1000",
                        "data:text/html;charset=utf-8," + quote(prelude + document),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    env={"PATH": "/usr/bin:/bin", "HOME": profile},
                )
            except subprocess.SubprocessError as exc:
                raise OSError("headless chromium failed") from exc
        if done.returncode or "<html" not in done.stdout.lower():
            raise OSError("headless chromium did not produce a document: " + done.stderr[-500:])

        class Marker(HTMLParser):
            seen = False

            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                if tag == "html" and (attribute, marker) in attrs:
                    self.seen = True

        parser = Marker()
        parser.feed(done.stdout)
        return parser.seen


Browser = Callable[[str, str], bool]


class XSSOracle(OutputOracle):
    def __init__(self, executor: Browser) -> None:
        self.executor = executor

    def capture(self, output: str) -> None:
        self.seen |= self.executor(output, self.canary.nonce)


def oracle_for(family: str, browser: Browser | None = None) -> Oracle | None:
    factories = {"path": PathOracle, "sql": SQLOracle, "command": CommandOracle, "ssrf": SSRFOracle}
    if family == "xss":
        return XSSOracle(browser) if browser else None
    factory = factories.get(family)
    return factory() if factory else None


def _listen(nonce: str, *, task_boundary: bool = False) -> None:
    import fcntl
    import socket
    import struct
    from http.server import BaseHTTPRequestHandler, HTTPServer

    # unshare created only loopback; bring it up without iproute2 or any egress.
    if not task_boundary:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            fcntl.ioctl(sock, 0x8914, struct.pack("16sH14s", b"lo", 0x49, b""))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.split("?", 1)[0] == "/" + nonce:
                print("observed", flush=True)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_TRACE = do_CONNECT = do_GET

        def log_message(self, format: str, *args: object) -> None:
            pass

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        print(json.dumps([os.getpid(), server.server_port]), flush=True)
        server.serve_forever()


if __name__ == "__main__":
    import sys

    _listen(sys.argv[2], task_boundary=sys.argv[1] == "--task-listener")
