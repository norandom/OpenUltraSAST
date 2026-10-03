"""The start signal through Agent Substrate's router (ai-service-plane Requirements 4.5, 4.6): port-forward
lifecycle with a fake kubectl, retry and refusal against a fake router, credentials from the environment."""

from __future__ import annotations

import json
import stat
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from openultrasast.plane.manifests import Metadata, Model, SecretKey
from openultrasast.plane.router import START_PATH, StartError, credentials, open_router

SECRET = "sk-router-test-5d1e-never-logged"

FAKE_KUBECTL = """#!{python}
import json, os, sys, time
from pathlib import Path
here = Path(__file__).resolve().parent
(here / "kubectl.json").write_text(json.dumps({{"argv": sys.argv[1:], "pid": os.getpid()}}))
mode = os.environ.get("FAKE_KUBECTL_MODE", "ok")
if mode == "fail":
    print('error: services "atenet-router" not found', flush=True)
    sys.exit(1)
print("Forwarding from 127.0.0.1:{port} -> 80", flush=True)
print("Forwarding from [::1]:{port} -> 80", flush=True)
time.sleep(600)
"""


class FakeRouter(ThreadingHTTPServer):
    """Answers the start path from ``codes`` in turn (the last one repeats) and records every request."""

    daemon_threads = True

    def __init__(self, codes: list[tuple[int, str]]) -> None:
        super().__init__(("127.0.0.1", 0), _RouterHandler)
        self.codes = codes
        self.requests: list[tuple[str, dict[str, str], dict]] = []
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class _RouterHandler(BaseHTTPRequestHandler):
    server: FakeRouter

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
        self.server.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
        code, text = self.server.codes[min(len(self.server.requests), len(self.server.codes)) - 1]
        payload = text.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@pytest.fixture
def fake_router(request: pytest.FixtureRequest) -> Iterator[FakeRouter]:
    server = FakeRouter(getattr(request, "param", [(202, "started")]))
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def write_kubectl(tmp_path: Path, port: int) -> Path:
    path = tmp_path / "kubectl"
    path.write_text(FAKE_KUBECTL.format(python=sys.executable, port=port), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def alive(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(")")[-1].split()[0] != "Z"
    except (FileNotFoundError, IndexError):
        return False


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("OUSAST_ROUTER_URL", "OUSAST_START_TIMEOUT", "FAKE_KUBECTL_MODE"):
        monkeypatch.delenv(key, raising=False)


def test_port_forward_port_is_parsed_and_the_child_is_terminated_on_exit(tmp_path: Path, fake_router: FakeRouter) -> None:
    port = int(fake_router.server_address[1])
    kubectl = write_kubectl(tmp_path, port)
    with open_router("kind-test", kubectl=str(kubectl)) as router:  # the profile's context, as the reconciler passes it
        assert router.url == f"http://127.0.0.1:{port}"
        seen = json.loads((tmp_path / "kubectl.json").read_text())
        assert seen["argv"] == ["--context", "kind-test", "-n", "ate-system", "port-forward", "svc/atenet-router", ":80"]
        assert alive(seen["pid"])
        router.start_task("default", "run-t", "run", {})
    deadline = time.monotonic() + 5
    while alive(seen["pid"]) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not alive(seen["pid"]), "the port-forward child is terminated when the block ends"
    assert fake_router.requests[0][1]["ate-target-actor"] == "default/run-t"


def test_a_failing_port_forward_raises_with_kubectls_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_KUBECTL_MODE", "fail")
    kubectl = write_kubectl(tmp_path, 1)
    with pytest.raises(StartError, match="atenet-router.*not found"), open_router("kind-other", kubectl=str(kubectl)):
        pass
    assert json.loads((tmp_path / "kubectl.json").read_text())["argv"][1] == "kind-other"


def test_router_url_override_starts_no_port_forward(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_router: FakeRouter) -> None:
    monkeypatch.setenv("OUSAST_ROUTER_URL", fake_router.url)
    with open_router("kind-test", kubectl=str(tmp_path / "no-such-kubectl")) as router:
        assert router.url == fake_router.url
    assert not (tmp_path / "kubectl.json").exists()
    monkeypatch.delenv("OUSAST_ROUTER_URL")
    with open_router("kind-test", url=fake_router.url, kubectl=str(tmp_path / "no-such-kubectl")) as router:
        assert router.url == fake_router.url, "the profile's router_url is the same override"


def test_open_router_refuses_to_build_a_context(tmp_path: Path) -> None:
    with pytest.raises(StartError, match="kube context"), open_router("", kubectl=str(tmp_path / "no-such-kubectl")):
        pass


@pytest.mark.parametrize("fake_router", [[(503, "no actor yet"), (502, "bad gateway"), (202, "started")]], indirect=True)
def test_start_retries_503_and_502_then_succeeds(monkeypatch: pytest.MonkeyPatch, fake_router: FakeRouter) -> None:
    monkeypatch.setenv("OUSAST_ROUTER_URL", fake_router.url)
    with open_router("kind-test") as router:
        router.start_task("default", "chain-verify", "chain", {"DEEPSEEK_API_KEY": SECRET})
    assert len(fake_router.requests) == 3
    path, headers, body = fake_router.requests[-1]
    assert path == START_PATH and headers["ate-target-actor"] == "default/chain-verify"
    assert body == {"run": "chain", "task": "chain-verify", "credentials": {"DEEPSEEK_API_KEY": SECRET}}


@pytest.mark.parametrize("fake_router", [[(409, f"this actor runs task 'x' (echo {SECRET})")]], indirect=True)
def test_a_409_is_raised_at_once_with_the_response_text_redacted(monkeypatch: pytest.MonkeyPatch, fake_router: FakeRouter) -> None:
    monkeypatch.setenv("OUSAST_ROUTER_URL", fake_router.url)
    with open_router("kind-test") as router, pytest.raises(StartError, match="HTTP 409.*runs task 'x'") as caught:
        router.start_task("default", "t", "r", {"DEEPSEEK_API_KEY": SECRET})
    assert len(fake_router.requests) == 1 and SECRET not in str(caught.value)
    assert router.starter("default", "t", "r", {})() is not None, "the starter returns the refusal instead of raising"


@pytest.mark.parametrize("fake_router", [[(409, "this task was already started on this boot")]], indirect=True)
def test_a_restart_after_re_resume_accepts_a_running_command(monkeypatch: pytest.MonkeyPatch, fake_router: FakeRouter) -> None:
    """First start: 'already started' is a refusal. After a re-resume the actor may not have rebooted; then the
    runner's 'already started on this boot' means the command still runs, not a failure."""
    monkeypatch.setenv("OUSAST_ROUTER_URL", fake_router.url)
    with open_router("kind-test") as router:
        start = router.starter("default", "t", "r", {})
        assert start() is not None, "a first start that finds the command running is a refusal"
        assert start() is None, "a re-sent start after a re-resume is not"
    fake_router.codes = [(409, "task t already ran and was delivered (done)")]
    assert start() is not None, "any other refusal stays one"


@pytest.mark.parametrize("fake_router", [[(503, "workspaces not materialised")]], indirect=True)
def test_start_gives_up_after_the_start_timeout(monkeypatch: pytest.MonkeyPatch, fake_router: FakeRouter) -> None:
    monkeypatch.setenv("OUSAST_ROUTER_URL", fake_router.url)
    monkeypatch.setenv("OUSAST_START_TIMEOUT", "1")
    with open_router("kind-test") as router, pytest.raises(StartError, match="OUSAST_START_TIMEOUT.*workspaces not materialised"):
        router.start_task("default", "t", "r", {})
    assert len(fake_router.requests) >= 2


def test_connection_errors_are_retried_until_the_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUSAST_ROUTER_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("OUSAST_START_TIMEOUT", "1")
    with open_router("kind-test") as router, pytest.raises(StartError, match="within 1s"):
        router.start_task("default", "t", "r", {})


def model(secret: SecretKey | None) -> Model:
    return Model(metadata=Metadata(name="deepseek-flash"), provider="deepseek", model="deepseek-flash", secret_key=secret)


def test_credentials_come_from_the_models_secret_key_variable() -> None:
    key = SecretKey(name="deepseek", key="DEEPSEEK_API_KEY")
    assert credentials(None, {}) == {} and credentials(model(None), {"DEEPSEEK_API_KEY": SECRET}) == {}
    assert credentials(model(key), {"DEEPSEEK_API_KEY": SECRET}) == {"DEEPSEEK_API_KEY": SECRET}
    with pytest.raises(StartError, match="needs DEEPSEEK_API_KEY"):
        credentials(model(key), {"DEEPSEEK_API_KEY": ""})
