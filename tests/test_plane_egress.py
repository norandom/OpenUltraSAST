"""ai-service-plane task 0: the per-task egress policy, its kubectl-ate calls, and the runner's dialled delivery.

Agent Substrate's egress gateway denies by default; :func:`egress.policy_for` must grant exactly the receiver (HTTP
by name), the bound Workspaces' Git hosts and the bound Model's API host (TLS passthrough), and nothing a gateway
would reject or that would intercept TLS: no IP address, no wildcard, no ``https`` rule.
"""

from __future__ import annotations

import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from openultrasast.plane import egress, runner
from openultrasast.plane.manifests import ManifestError, load_manifests, parse_manifest

MANIFESTS = """
apiVersion: ax.io/v1alpha1
kind: Model
metadata:
  name: deepseek-flash
  annotations: {openultrasast.io/provider-extension: "true", openultrasast.io/egress-hosts: api.deepseek.com}
spec: {provider: deepseek, model: deepseek-flash, secretKey: {name: deepseek, key: DEEPSEEK_API_KEY}}
---
apiVersion: ax.io/v1alpha1
kind: Workspace
metadata: {name: cases}
spec:
  git:
    - {name: a, repo: https://github.com/example-org/alpha}
    - {name: b, repo: https://github.com/example-org/beta.git}
    - {name: c, repo: "git@gitlab.example.org:group/repo.git"}
    - {name: d, repo: https://10.0.0.7/mirror/repo.git}
---
apiVersion: ax.io/v1alpha1
kind: Task
metadata: {name: verify, annotations: {openultrasast.io/model: deepseek-flash}}
spec: {command: [verify], workspaces: [{name: cases, path: /workspace}]}
---
apiVersion: ax.io/v1alpha1
kind: Task
metadata: {name: facts}
spec: {command: [repo-facts]}
"""


@pytest.fixture
def manifests(tmp_path: Path):
    path = tmp_path / "m.yaml"
    path.write_text(MANIFESTS, encoding="utf-8")
    return load_manifests([path])


def hostnames(policy: dict) -> list[str]:
    return [h for rule in policy["rules"] for body in rule.values() for h in body["hostnames"]]


def assert_tight(policy: dict) -> None:
    for rule in policy["rules"]:
        assert set(rule) <= {"http", "tlsPassthrough"}, f"only http and passthrough rules, got {rule}"
        body = next(iter(rule.values()))
        assert "all" not in body["ports"], "never every port"
    for host in hostnames(policy):
        assert "*" not in host, f"no wildcard: {host}"
        with pytest.raises(ValueError):
            ipaddress.ip_address(host)


def test_model_free_task_gets_only_the_receiver(manifests) -> None:
    policy = egress.policy_for(manifests.tasks["facts"], [], None, egress.RECEIVER_HOST)
    assert policy == {"rules": [{"http": {"hostnames": [egress.RECEIVER_HOST], "ports": {"numbers": [80]}}}]}
    assert_tight(policy)


def test_model_bound_task_with_git_workspaces(manifests) -> None:
    task = manifests.tasks["verify"]
    policy = egress.policy_for(task, [manifests.workspaces["cases"]], manifests.models["deepseek-flash"], egress.RECEIVER_HOST)
    assert policy["rules"] == [
        {"http": {"hostnames": [egress.RECEIVER_HOST], "ports": {"numbers": [80]}}},
        {"tlsPassthrough": {"hostnames": ["api.deepseek.com", "github.com"], "ports": {"numbers": [443]}}},
    ], "one github.com for two repos; the ssh and IP-address repos add nothing"
    assert_tight(policy)


def test_an_ip_receiver_is_not_granted(manifests) -> None:
    assert egress.policy_for(manifests.tasks["facts"], [], None, "127.0.0.1") == {"rules": []}


def test_deepseek_model_manifest_names_the_endpoint_host() -> None:
    from openultrasast.model.endpoint import DEEPSEEK_BASE_URL

    model = load_manifests([Path("plane/models/deepseek-flash.yaml")]).models["deepseek-flash"]
    assert model.egress_hosts == (DEEPSEEK_BASE_URL.removeprefix("https://"),)


@pytest.mark.parametrize("hosts", ["*.deepseek.com", "10.1.2.3", "https://api.deepseek.com", "api.deepseek.com:443", "API.deepseek.com"])
def test_egress_hosts_annotation_is_validated(hosts: str) -> None:
    doc = {
        "apiVersion": "ax.io/v1alpha1",
        "kind": "Model",
        "metadata": {"name": "m", "annotations": {"openultrasast.io/provider-extension": "true", "openultrasast.io/egress-hosts": hosts}},
        "spec": {"provider": "deepseek", "model": "x"},
    }
    with pytest.raises(ManifestError, match="egress-hosts"):
        parse_manifest(doc)


# --- kubectl-ate ---------------------------------------------------------------------------------------------------


def actor(tmp_path: Path, name: str, gone: bool = False) -> None:
    (tmp_path / "applied").mkdir(exist_ok=True)
    (tmp_path / "applied" / f"{name}.json").write_text(json.dumps({"gone": gone}), encoding="utf-8")


def calls(tmp_path: Path) -> list[str]:
    return [" ".join(line.split()[2:4]) for line in (tmp_path / "ax.log").read_text().splitlines()]


POLICY = {"rules": [{"http": {"hostnames": [egress.RECEIVER_HOST], "ports": {"numbers": [80]}}}]}


def test_apply_creates_reads_back_and_delete_confirms_the_cascade(tmp_path: Path, kubectl_ate: Path) -> None:
    cli = egress.Egress(str(kubectl_ate), context="kind-test")
    actor(tmp_path, "t1")
    cli.apply("t1", "default", POLICY)
    stored = cli.get("t1", "default")
    assert stored is not None and egress.rules_of(stored) == egress.rules_of(POLICY)
    assert cli.delete("t1", "default") == "egress policy for default/t1 outlived its actor"
    actor(tmp_path, "t1", gone=True)  # ax delete task: the actor, and with it the policy, is gone
    assert cli.delete("t1", "default") is None
    assert calls(tmp_path) == ["get t1", "create t1", "get t1", "get t1", "get t1", "get t1"]
    assert {line.split()[-1] for line in (tmp_path / "ax.log").read_text().splitlines()} == {"kind-test"}, "the given context"


def test_apply_replaces_an_existing_policy(tmp_path: Path, kubectl_ate: Path) -> None:
    cli = egress.Egress(str(kubectl_ate), context="kind-test")
    actor(tmp_path, "t2")
    cli.apply("t2", "default", {"rules": []})
    cli.apply("t2", "default", POLICY)
    assert calls(tmp_path) == ["get t2", "create t2", "get t2", "get t2", "update t2", "get t2"]
    assert json.loads((tmp_path / "policies" / "default_t2.json").read_text())["metadata"]["version"] == 2


def test_apply_waits_for_the_actor_then_gives_up(tmp_path: Path, kubectl_ate: Path) -> None:
    cli = egress.Egress(str(kubectl_ate), context="kind-test")
    with pytest.raises(RuntimeError, match="not found"):
        cli.apply("missing", "default", POLICY, timeout=0.2)
    timer = threading.Timer(0.3, actor, args=(tmp_path, "late"))
    timer.start()
    cli.apply("late", "default", POLICY, timeout=10)
    timer.join()


def test_receiver_address_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUSAST_ARTIFACT_HOST", "127.0.0.1")
    assert egress.receiver_address(4242, None) == ("http://127.0.0.1:4242/", None)
    monkeypatch.delenv("OUSAST_ARTIFACT_HOST")
    monkeypatch.setenv("OUSAST_ARTIFACT_DIAL", "172.19.0.1:80")
    assert egress.receiver_address(18090, "kind-test") == (f"http://{egress.RECEIVER_HOST}/", "172.19.0.1:80")
    monkeypatch.delenv("OUSAST_ARTIFACT_DIAL")
    with pytest.raises(RuntimeError, match="kube context"):
        egress.receiver_address(18090, None)  # no context to look the Service up in: never a built one


# --- the runner dials the gateway address with the receiver's name as Host ----------------------------------------


class _Seen(ThreadingHTTPServer):
    daemon_threads = True
    seen: list[tuple[str, str | None, bytes]]


class _Handler(BaseHTTPRequestHandler):
    server: _Seen

    def do_POST(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.seen.append((self.path, self.headers.get("Host"), body))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


def test_delivery_dials_the_override_with_the_url_host() -> None:
    server = _Seen(("127.0.0.1", 0), _Handler)
    server.seen = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        dial = f"127.0.0.1:{server.server_address[1]}"
        url = f"http://{egress.RECEIVER_HOST}/in"
        assert runner.deliver(url, b"tar", {"Content-Type": "application/x-tar"}, backoff=0, dial=dial) == 200
        assert server.seen == [("/in", egress.RECEIVER_HOST, b"tar")]
    finally:
        server.shutdown()
        server.server_close()
