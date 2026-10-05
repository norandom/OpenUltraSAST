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
import sqlite3
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class Canary:
    root: Path
    nonce: str

    @classmethod
    def fresh(cls, root: Path) -> Canary:
        root.mkdir()
        return cls(root, secrets.token_hex(24))


class Oracle(Protocol):
    namespace_pid: int | None

    def prepare(self, canary: Canary) -> dict[str, str]: ...
    def capture(self, output: str) -> None: ...
    def observe(self) -> tuple[bool, str]: ...
    def close(self) -> None: ...


class OutputOracle:
    namespace_pid: int | None = None

    def prepare(self, canary: Canary) -> dict[str, str]:
        self.canary = canary
        self.seen = False
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
        return {"SERVED_ROOT": "/fixture/public"}


class SQLOracle(OutputOracle):
    def prepare(self, canary: Canary) -> dict[str, str]:
        super().prepare(canary)
        with sqlite3.connect(canary.root / "fixture.db") as db:
            db.execute("CREATE TABLE records (name TEXT, value TEXT, public INTEGER)")
            db.executemany("INSERT INTO records VALUES (?, ?, ?)", [("ordinary", "public value", 1), ("secret", canary.nonce, 0)])
        return {"DATABASE": "/fixture/fixture.db"}


class CommandOracle(OutputOracle):
    def prepare(self, canary: Canary) -> dict[str, str]:
        super().prepare(canary)
        # Marker is in app-only writable scratch, inaccessible in artefact sandbox.
        self.marker = canary.root / canary.nonce
        return {"PROOF_MARKER": "/scratch/" + canary.nonce}

    def observe(self) -> tuple[bool, str]:
        observed = self.marker.is_file() and not self.marker.is_symlink()
        return observed, "injected command marker exists" if observed else "no command marker"


class SSRFOracle(OutputOracle):
    """Separate listener process and private loopback namespace; no external egress."""

    process: subprocess.Popen[str] | None = None

    def prepare(self, canary: Canary) -> dict[str, str]:
        super().prepare(canary)
        self.process = subprocess.Popen(
            [
                "/usr/bin/unshare",
                "--user",
                "--map-root-user",
                "--net",
                "/usr/bin/python3",
                "-I",
                str(Path(__file__).resolve()),
                "--listener",
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
        return {"CALLBACK_URL": f"http://127.0.0.1:{port}/{canary.nonce}"}  # loopback: oracle listener inside the private sandbox namespace

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


BrowserExecutor = Callable[[str, str], bool]


class XSSOracle(OutputOracle):
    def __init__(self, executor: BrowserExecutor) -> None:
        self.executor = executor

    def capture(self, output: str) -> None:
        self.seen |= self.executor(output, self.canary.nonce)


def oracle_for(family: str, browser: BrowserExecutor | None = None) -> Oracle | None:
    factories = {"path": PathOracle, "sql": SQLOracle, "command": CommandOracle, "ssrf": SSRFOracle}
    if family == "xss":
        return XSSOracle(browser) if browser else None
    factory = factories.get(family)
    return factory() if factory else None


def _listen(nonce: str) -> None:
    import fcntl
    import socket
    import struct
    from http.server import BaseHTTPRequestHandler, HTTPServer

    # unshare created only loopback; bring it up without iproute2 or any egress.
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

    _listen(sys.argv[2])
