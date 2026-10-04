"""Offline queue protocol, image imports and deployment contract controls."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
with pytest.MonkeyPatch.context() as patch:
    patch.syspath_prepend(str(ROOT / "benchmarks/learn"))
    service = importlib.import_module("engine_worker_service")
    transport = importlib.import_module("engine_trace_queue")


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.lock = threading.Lock()
        self.choosing = None

    def get(self, key):
        with self.lock:
            return (self.objects[key], None) if key in self.objects else None

    def put(self, key, data, labels):
        with self.lock:
            self.objects[key] = data
        if self.choosing and key.startswith(service.CLAIMED) and json.loads(data)["ticket"] == 0:
            self.choosing.wait(timeout=5)

    def delete(self, key):
        with self.lock:
            self.objects.pop(key, None)

    def keys(self, prefix):
        with self.lock:
            return sorted(k for k in self.objects if k.startswith(prefix))


def task():
    return dict(
        run="run",
        id="pin",
        task_id="run-pin",
        input="engine-queue/inputs/run/pin/source.tar",
        deadline=10,
        question_deadline=2,
        pin={"repo": "owner/repo", "pin": "commit", "units": []},
    )


def test_engine_worker_racing_claimants_run_exactly_once():
    store = FakeS3()
    item = task()
    service.put(store, service.PENDING + item["task_id"], item)
    store.choosing = threading.Barrier(2)
    called = []

    def execute(client, entry):
        called.append(entry["task_id"])
        time.sleep(0.05)
        return {**entry["pin"], "done": True, "instrument": {"bytes": 11}}

    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(service.Queue(store, identity).process_one, execute) for identity in ["worker-b", "worker-a"]]
        results = [f.result(timeout=10) for f in futures]
    assert sum(results) == 1
    assert called == ["run-pin"]
    result = service.read(store, service.result_key(item))
    assert result["worker"] in {"worker-a", "worker-b"}
    assert not store.keys(service.CLAIMED)
    assert not store.keys(service.PENDING)


def test_engine_worker_expired_lease_recovered_without_pending():
    store = FakeS3()
    item = task()
    service.put(store, "engine-queue/claimed/dead/run-pin", dict(task=item, ticket=1, expires=99))
    queue = service.Queue(store, "new", now=lambda: 100)
    assert queue.process_one(lambda *_: {**item["pin"], "done": True})
    assert service.read(store, service.result_key(item))["worker"] == "new"
    assert not store.keys(service.CLAIMED)


def test_engine_worker_late_arrival_cannot_displace_running_owner():
    store = FakeS3()
    item = task()
    first = service.Queue(store, "z-first")
    key = first.claim(item)
    assert key
    stop = threading.Event()
    later = service.Queue(store, "a-later", stop=stop)
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(later.claim, item)
        assert future.result(timeout=3) is None
        assert service.read(store, key) is not None
        service.put(store, service.result_key(item), {"done": True})
        store.delete(key)


def test_engine_queue_dispatch_roundtrip_and_timeout(tmp_path):
    store = FakeS3()
    checkout, output = tmp_path / "case", tmp_path / "out"
    checkout.mkdir()
    output.mkdir()
    (checkout / "app.py").write_text("print(1)\n")
    args = SimpleNamespace(deadline=10, question_deadline=2, queue_timeout=2, image="image@sha256:abc")
    unit = {"unit": "u", "supported": True, "reason": "", "family": "injection"}
    pin = {"repo": "owner/repo", "pin": "sha", "units": [unit], "questions": []}

    def execute(client, item):
        unpacked = tmp_path / "unpacked"
        unpacked.mkdir()
        service.unpack(client.get(item["input"])[0], unpacked)
        assert (unpacked / "app.py").read_bytes() == b"print(1)\n"
        return {
            **item["pin"],
            "done": True,
            "container_exit": 0,
            "units": [service.unit_record(unit, "asked-nothing")],
            "instrument": {"bytes": 9, "heap_mb": 2560},
        }

    queue = service.Queue(store, "pod-1")
    dispatcher = transport.Dispatcher(args, store, pause=lambda _: queue.process_one(execute))
    completed, worker = dispatcher.execute(checkout, output, pin, "pin")
    assert completed.returncode == 0
    assert worker == "pod-1"
    result = json.loads((output / "result.json").read_text())
    assert result["executor"] == "queue"
    assert result["units"][0]["status"] == "asked-nothing"
    assert result["instrument"]["heap_mb"] == 2560
    assert dispatcher.status() == {"pending": 0, "claimed": 0, "done": 1}
    assert not store.keys("engine-queue/inputs/")
    ticks = iter([0, 3])
    dispatcher = transport.Dispatcher(args, store, clock=lambda: next(ticks))
    assert dispatcher.execute(checkout, output, pin, "other") == (None, None)
    assert not store.keys(service.PENDING)


def test_engine_worker_imports_without_yaml():
    code = "import sys; sys.modules['yaml'] = None; import engine_worker_service; import engine_trace_worker"
    done = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": f"{ROOT / 'src'}:{ROOT / 'benchmarks/learn'}"},
    )
    assert done.returncode == 0, done.stderr


def test_engine_k8s_render_contract():
    base = ROOT / "ops/k8s/engine"
    config = yaml.safe_load((base / "kustomization.yaml").read_text())
    # Render this base's resource inclusion, namespace, image and replacement transforms offline.
    resources = [yaml.safe_load((base / name).read_text()) for name in config["resources"]]
    deployment = next(r for r in resources if r["kind"] == "Deployment")
    deployment["metadata"]["namespace"] = config["namespace"]
    image = config["images"][0]
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert container["image"] == image["name"]
    container["image"] = image["newName"] + "@" + image["digest"]
    replacement = config["replacements"][0]
    assert replacement["source"]["fieldPath"] == "spec.template.spec.containers.0.image"
    assert replacement["targets"][0]["fieldPaths"] == ["spec.template.spec.containers.0.env.0.value"]
    container["env"][0]["value"] = container["image"]
    assert "@sha256:" in container["image"]
    assert deployment["spec"]["replicas"] == 2
    assert container["resources"] == {"requests": {"memory": "3Gi", "cpu": "1"}, "limits": {"memory": "3Gi"}}
    affinity = pod["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][0]
    assert affinity["topologyKey"] == "kubernetes.io/hostname"
    assert affinity["labelSelector"]["matchLabels"] == deployment["spec"]["template"]["metadata"]["labels"]
    assert pod["terminationGracePeriodSeconds"] == 900
    assert container["envFrom"] == [{"secretRef": {"name": "ousast-engine-s3"}}]
    for probe in ["readinessProbe", "livenessProbe"]:
        assert container[probe]["httpGet"] == {"path": "/healthz", "port": "health"}
    assert not pod["automountServiceAccountToken"]
    assert pod["securityContext"]["runAsNonRoot"]
    assert "hostPath" not in json.dumps(resources)
    assert "privileged" not in json.dumps(resources)
    assert all(r["kind"] != "Secret" for r in resources)
    secret = yaml.safe_load((base / "secret.example.yaml").read_text())
    assert secret["stringData"] == {}
    assert "AWS_SECRET_ACCESS_KEY" not in json.dumps(resources)


def test_engine_image_and_rustfs_policy():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "COPY benchmarks ./benchmarks" in dockerfile
    assert ".[semantic,s3]" in dockerfile
    for name in ["engine_trace_worker.py", "engine_trace_parse.py", "engine_worker_service.py"]:
        assert (ROOT / "benchmarks/learn" / name).stat().st_size > 0
    doc = (ROOT / "docs/rustfs.md").read_text().split("## Scoped account for engine workers")[1]
    policy = json.loads(doc.split("```json\n")[1].split("```")[0])
    listing, objects = policy["Statement"]
    assert listing["Action"] == "s3:ListBucket"
    assert set(listing["Condition"]["StringLike"]["s3:prefix"]) == {
        "engine-queue/",
        "engine-queue/*",
        "engine-results/",
        "engine-results/*",
    }
    assert set(objects["Action"]) == {"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}
    assert set(objects["Resource"]) == {"arn:aws:s3:::sast-memory/engine-queue/*", "arn:aws:s3:::sast-memory/engine-results/*"}


@pytest.mark.parametrize("hang", [False, True])
def test_engine_worker_process_deadline_and_shipped_schema(tmp_path, monkeypatch, hang):
    store = FakeS3()
    item = task()
    item["image"] = "image@sha256:abc"
    item["deadline"] = 0.1 if hang else 5
    item["pin"]["units"] = [{"unit": "u", "supported": True, "reason": ""}]
    (tmp_path / "app.py").write_text("print(1)\n")
    store.put(item["input"], service.pack(tmp_path), {})
    monkeypatch.setenv("ENGINE_IMAGE", item["image"])

    def fake_worker(pin, root, out, deadline, question_deadline):
        assert (root / "app.py").read_bytes() == b"print(1)\n"
        if hang:
            time.sleep(10)
        out.write_text(json.dumps({**pin, "done": True, "units": [service.unit_record(pin["units"][0], "asked-nothing")]}))

    monkeypatch.setattr(service, "worker", fake_worker)
    result = service.execute_task(store, item)
    assert result["done"]
    assert result["units"][0]["status"] == ("timeout" if hang else "asked-nothing")
    assert result["container_exit"] == (None if hang else 0)
    assert result["seconds"] < 5


def test_engine_worker_stopping_does_not_claim():
    store = FakeS3()
    item = task()
    service.put(store, service.PENDING + item["task_id"], item)
    stop = threading.Event()
    stop.set()
    assert not service.Queue(store, stop=stop).process_one(lambda *_: pytest.fail("claimed after SIGTERM"))
    assert store.keys(service.PENDING)
    assert not store.keys(service.CLAIMED)


def test_engine_worker_rejects_archive_links_and_escape(tmp_path):
    import io
    import tarfile

    for name, kind in [("../escape", tarfile.REGTYPE), ("link", tarfile.SYMTYPE)]:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.linkname = "/etc/passwd"
            archive.addfile(member)
        with pytest.raises(ValueError, match="unsafe source archive"):
            service.unpack(stream.getvalue(), tmp_path)


def test_engine_worker_timeout_kills_separate_session_descendant(tmp_path, monkeypatch):
    store = FakeS3()
    item = task()
    item.update(image="image@sha256:abc", deadline=0.5)
    item["pin"]["units"] = [{"unit": "u", "supported": True, "reason": ""}]
    (tmp_path / "app.py").write_text("print(1)\n")
    store.put(item["input"], service.pack(tmp_path), {})
    monkeypatch.setenv("ENGINE_IMAGE", item["image"])
    pid_file = tmp_path / "escaped-pid"

    def fake_worker(*_):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
        pid_file.write_text(str(child.pid))
        time.sleep(30)

    monkeypatch.setattr(service, "worker", fake_worker)
    result = service.execute_task(store, item)
    assert result["units"][0]["status"] == "timeout"
    assert pid_file.exists(), "instrument: fake worker never launched its descendant"
    pid = int(pid_file.read_text())
    assert not Path(f"/proc/{pid}").exists(), "escaped session survived the task deadline"
