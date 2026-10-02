"""An S3-shaped memory store for the delivery tests: objects in a dict, presigned URLs served by a local HTTP server
that accepts PUT, GET and HEAD by key (``/<bucket>/<key>?X-Amz-Expires=N&X-Amz-Signature=fake``), the way a
presigned S3 URL looks to the runner. Nothing here is imported by the product."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from openultrasast.plane.memory import MemoryStore


class HttpObjectStore(MemoryStore):
    """``presign_*`` hand out URLs on a local server; ``requests`` records every HTTP call (method, key)."""

    def __init__(self, bucket: str = "fake-bucket", host: str = "localhost") -> None:
        self.objects: dict[str, bytes] = {}
        self.bucket, self.host = bucket, host
        self.requests: list[tuple[str, str]] = []
        self.presigned: list[tuple[str, str, int]] = []
        self.lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.store = self  # type: ignore[attr-defined]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def describe(self) -> str:
        return f"fake://{self.bucket}"

    def _get(self, key: str) -> tuple[bytes, str | None] | None:
        with self.lock:
            data = self.objects.get(key)
        return None if data is None else (data, "v1")

    def _put(self, key: str, data: bytes, labels: Mapping[str, str] | None = None) -> None:
        with self.lock:
            self.objects[key] = bytes(data)

    def _delete(self, key: str) -> None:
        with self.lock:
            self.objects.pop(key, None)

    def _keys(self, prefix: str) -> list[str]:
        with self.lock:
            return sorted(k for k in self.objects if k.startswith(prefix))

    def _url(self, method: str, key: str, expires: timedelta) -> str:
        self.presigned.append((method, key, int(expires.total_seconds())))
        port = self.server.server_address[1]
        return f"http://{self.host}:{port}/{self.bucket}/{key}?X-Amz-Expires={int(expires.total_seconds())}&X-Amz-Signature=fake"

    def presign_put(self, key: str, expires: timedelta = timedelta(hours=1)) -> str:
        return self._url("PUT", key, expires)

    def presign_get(self, key: str, expires: timedelta = timedelta(hours=1)) -> str:
        return self._url("GET", key, expires)


class _Handler(BaseHTTPRequestHandler):
    def _key(self) -> str | None:
        store: HttpObjectStore = self.server.store  # type: ignore[attr-defined]
        path = unquote(urlsplit(self.path).path)
        prefix = f"/{store.bucket}/"
        return path[len(prefix) :] if path.startswith(prefix) else None

    def do_PUT(self) -> None:  # noqa: N802
        store: HttpObjectStore = self.server.store  # type: ignore[attr-defined]
        key = self._key()
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        store.requests.append(("PUT", key or self.path))
        if key is None:
            return self._answer(404)
        store._put(key, body)
        self._answer(200)

    def do_GET(self) -> None:  # noqa: N802
        store: HttpObjectStore = self.server.store  # type: ignore[attr-defined]
        key = self._key()
        store.requests.append(("GET", key or self.path))
        got = store._get(key) if key else None
        if got is None:
            return self._answer(404)
        self.send_response(200)
        self.send_header("Content-Length", str(len(got[0])))
        self.end_headers()
        self.wfile.write(got[0])

    def do_HEAD(self) -> None:  # noqa: N802
        store: HttpObjectStore = self.server.store  # type: ignore[attr-defined]
        key = self._key()
        store.requests.append(("HEAD", key or self.path))
        got = store._get(key) if key else None
        self.send_response(404 if got is None else 200)
        self.send_header("Content-Length", "0" if got is None else str(len(got[0])))
        self.end_headers()

    def _answer(self, code: int) -> None:
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass
