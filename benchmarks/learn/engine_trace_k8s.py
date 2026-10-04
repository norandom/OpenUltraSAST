"""Host Kubernetes transport; the embedded bootstrap uses only the standard library."""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import tarfile
import time
import uuid
from datetime import timedelta

from openultrasast.plane.memory import PRESIGNED_ARCHIVE_SUFFIX, S3Store, open_store

IMAGE = "ghcr.io/norandom/openultrasast:2.0.1"
BOOTSTRAP = r"""
import io, json, os, pathlib, subprocess, sys, tarfile, urllib.request

def get(name):
    with urllib.request.urlopen(os.environ[name], timeout=120) as response:
        return response.read()

def put(data):
    request = urllib.request.Request(os.environ['RESULT_URL'], data=data, method='PUT')
    with urllib.request.urlopen(request, timeout=120) as response:
        response.read()

try:
    if os.environ.get('CHECK') == '1':
        data = get('SOURCE_URL')
        assert len(data) == 1024
        subprocess.run([sys.executable, '-c', 'print(42)'], check=True)
        put(data)
    else:
        for name, target in [('SOURCE_URL', '/case'), ('ANALYZER_URL', '/frozen')]:
            pathlib.Path(target).mkdir(parents=True, exist_ok=True)
            with tarfile.open(fileobj=io.BytesIO(get(name))) as archive:
                archive.extractall(target, filter='data')
        out = pathlib.Path('/out')
        out.mkdir(exist_ok=True)
        (out / 'pin.json').write_text(os.environ['PIN'])
        env = dict(os.environ, PYTHONPATH='/frozen/src')
        for key in ['SOURCE_URL', 'ANALYZER_URL', 'RESULT_URL']:
            env.pop(key, None)
        with (out / 'container.log').open('w') as log:
            done = subprocess.run([sys.executable, '/frozen/benchmarks/learn/engine_trace_worker.py',
                '--worker', '/out/pin.json', '--deadline', os.environ['DEADLINE'],
                '--question-deadline', os.environ['QUESTION_DEADLINE']], env=env, stdout=log, stderr=log)
        (out / 'exit.json').write_text(json.dumps(done.returncode))
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for path in out.iterdir():
                archive.add(path, arcname=path.name)
        put(buffer.getvalue())
        sys.exit(done.returncode)
except Exception as exc:
    # urllib exceptions can contain bearer URLs. Never print exception text.
    print('engine bootstrap failed: ' + type(exc).__name__, file=sys.stderr)
    sys.exit(1)
"""


def pack(path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for child in sorted(path.iterdir()):
            archive.add(child, arcname=child.name)
    return buffer.getvalue()


def manifests(name, run, args, urls, pin, check=False):
    labels = {"engine-trace-run": run, "engine-trace-job": name, "engine-trace": "true"}
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": args.kube_namespace, "labels": labels},
        "type": "Opaque",
        "stringData": urls,
    }
    env = [{"name": key, "valueFrom": {"secretKeyRef": {"name": name, "key": key}}} for key in urls]
    env += [
        {"name": key, "value": value}
        for key, value in {
            "PIN": json.dumps(pin),
            "DEADLINE": str(args.deadline),
            "QUESTION_DEADLINE": str(args.question_deadline),
            "CHECK": "1" if check else "0",
        }.items()
    ]
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "namespace": args.kube_namespace, "labels": labels},
        "spec": {
            "activeDeadlineSeconds": args.deadline,
            "backoffLimit": 0,
            "ttlSecondsAfterFinished": 86400,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000},
                    "volumes": [{"name": name, "emptyDir": {}} for name in ("case", "frozen", "out")],
                    "affinity": {
                        "podAntiAffinity": {
                            "requiredDuringSchedulingIgnoredDuringExecution": [
                                {
                                    "labelSelector": {"matchLabels": {"engine-trace": "true"}},
                                    "topologyKey": "kubernetes.io/hostname",
                                }
                            ]
                        }
                    },
                    "containers": [
                        {
                            "name": "engine",
                            "image": args.image,
                            "command": ["python", "-c", BOOTSTRAP],
                            "env": env,
                            "volumeMounts": [{"name": name, "mountPath": "/" + name} for name in ("case", "frozen", "out")],
                            "resources": {"requests": {"memory": "3Gi", "cpu": "1"}, "limits": {"memory": "3Gi"}},
                        }
                    ],
                },
            },
        },
    }
    return job, secret


def redact(text):
    return re.sub(r"https?://[^\s\"'<>]+", "[redacted URL]", text)


class Kubernetes:
    def __init__(self, args, store=None):
        self.args = args
        self.run = uuid.uuid4().hex
        self.store = store if store is not None else open_store()
        if not isinstance(self.store, S3Store):
            raise ValueError("Kubernetes requires OUSAST_MEMORY=s3://bucket[/prefix]")

    def kubectl(self, *args, manifest=None, check=True):
        result = subprocess.run(
            ["kubectl", "--context", self.args.kube_context, "--namespace", self.args.kube_namespace, *args],
            input=json.dumps(manifest) if manifest is not None else None,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if check and result.returncode:
            # kubectl can echo submitted Secret data on errors; never expose stderr.
            raise ValueError(f"kubectl {args[0]} failed (exit {result.returncode})")
        return result

    def namespace(self):
        self.kubectl("get", "nodes", "-o", "json")
        self.kubectl("apply", "-f", "-", manifest={"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": self.args.kube_namespace}})

    def execute(self, source, checkout, output, pin, check=False):
        name = "engine-" + uuid.uuid4().hex[:24]
        pin_key = hashlib.sha256(json.dumps([pin.get("repo"), pin.get("pin")]).encode()).hexdigest()
        prefix = f"engine-jobs/{self.run}/{pin_key}/"
        keys = [prefix + name + PRESIGNED_ARCHIVE_SUFFIX for name in ("source", "analyzer", "result")]
        expiry = timedelta(seconds=self.args.deadline + 900)
        node = None
        try:
            self.store._put(keys[0], b"x" * 1024 if check else pack(checkout))
            self.store._put(keys[1], b"" if check else pack(source))
            urls = {
                "SOURCE_URL": self.store.presign_get(keys[0], expiry),
                "ANALYZER_URL": self.store.presign_get(keys[1], expiry),
                "RESULT_URL": self.store.presign_put(keys[2], expiry),
            }
            job, secret = manifests(name, self.run, self.args, urls, pin, check)
            # create avoids kubectl's last-applied annotation duplicating Secret values.
            created = json.loads(self.kubectl("create", "-f", "-", "-o", "json", manifest=job).stdout)
            secret["metadata"]["ownerReferences"] = [
                {
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "name": name,
                    "uid": created["metadata"]["uid"],
                }
            ]
            self.kubectl("create", "-f", "-", manifest=secret)
            end = time.monotonic() + self.args.deadline + 60
            reason = "host deadline waiting for Job"
            while time.monotonic() < end:
                state = json.loads(self.kubectl("get", "job", name, "-o", "json").stdout).get("status", {})
                pods = json.loads(self.kubectl("get", "pods", "-l", f"engine-trace-job={name}", "-o", "json").stdout)
                node = next((p.get("spec", {}).get("nodeName") for p in pods.get("items", []) if p.get("spec", {}).get("nodeName")), node)
                result = self.store._get(keys[2])
                failed = next((c for c in state.get("conditions", []) if c.get("type") == "Failed" and c.get("status") == "True"), None)
                if failed or state.get("failed"):
                    reason = (failed or {}).get("reason", "Job failed") + ": " + (failed or {}).get("message", "")
                    break
                if state.get("succeeded") and result is not None:
                    if check:
                        if result[0] != b"x" * 1024:
                            raise ValueError("round-trip bytes mismatch")
                    else:
                        with tarfile.open(fileobj=io.BytesIO(result[0])) as archive:
                            archive.extractall(output, filter="data")
                        if not (output / "result.json").is_file():
                            raise ValueError("Job produced no result.json")
                        record = json.loads((output / "result.json").read_text())
                        if not record.get("done") or {u["unit"] for u in record["units"]} != {u["unit"] for u in pin["units"]}:
                            raise ValueError("Job returned incomplete or mismatched units")
                    return subprocess.CompletedProcess([], 0, "", ""), node
                time.sleep(2)
            logs = self.kubectl("logs", f"job/{name}", "--tail=40", check=False)
            reason = redact(reason + "\n" + logs.stdout + logs.stderr)
            return subprocess.CompletedProcess([], 1, "", reason), node
        except Exception as exc:
            reason = "Kubernetes transport failed: " + type(exc).__name__ + ": " + redact(str(exc))
            try:
                logs = self.kubectl("logs", f"job/{name}", "--tail=40", check=False)
                reason += "\n" + redact(logs.stdout + logs.stderr)
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            return subprocess.CompletedProcess([], 1, "", reason), node
        finally:
            if not self.args.keep_jobs:
                # Attempt every cleanup even if an earlier deletion fails.
                errors = []
                for kind in ("job", "secret"):
                    try:
                        self.kubectl("delete", kind, name, "--ignore-not-found", "--wait=true", "--timeout=30s")
                    except Exception as exc:
                        errors.append(type(exc).__name__)
                for key in keys:
                    try:
                        self.store._delete(key)
                    except Exception as exc:
                        errors.append(type(exc).__name__)
                if errors:
                    raise RuntimeError("engine Job cleanup failed: " + ", ".join(errors))

    def check(self):
        self.namespace()
        nodes = json.loads(self.kubectl("get", "nodes", "-o", "json").stdout)
        for node in nodes["items"]:
            print(json.dumps({"node": node["metadata"]["name"], "allocatable_memory": node["status"]["allocatable"]["memory"]}))
        done, node = self.execute(None, None, None, {}, check=True)
        print(
            json.dumps(
                {
                    "k8s_check": "passed" if done.returncode == 0 else "failed",
                    "node": node,
                    "reason": done.stderr,
                    "round_trip_bytes": 1024 if done.returncode == 0 else 0,
                }
            )
        )
        return done.returncode
