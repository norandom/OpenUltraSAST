"""Offline overlay contract and installer staging; no Kubernetes executable needed."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "ops/ax/substrate-kind-lean"
DISABLED = {
    "OTEL_TRACES_EXPORTER": "none",
    "OTEL_METRICS_EXPORTER": "none",
    "OTEL_LOGS_EXPORTER": "none",
    "OTEL_SDK_DISABLED": "true",
}


def test_ax_lean_overlay_removes_observability_and_replaces_export_config() -> None:
    overlay = yaml.safe_load((OVERLAY / "kustomization.yaml").read_text())
    assert overlay["resources"] == ["../kind-upstream"]
    deletes = [p for p in overlay["patches"] if "target" in p]
    assert [p["target"] for p in deletes] == [
        {"namespace": "otel-system"},
        {"kind": "Namespace", "name": "otel-system"},
        {"kind": "ClusterRole", "name": "ate-prometheus"},
        {"kind": "RoleBinding", "name": "ate-prometheus", "namespace": "ate-system"},
    ]
    assert all(yaml.safe_load(p["patch"])["$patch"] == "delete" for p in deletes)
    config = yaml.safe_load((OVERLAY / overlay["patches"][-1]["path"]).read_text())
    assert config["metadata"] == {"name": "ate-otel-config", "namespace": "ate-system"}
    # Whole-data replacement drops the upstream endpoint, interval and timeout,
    # including any future keys that would otherwise survive a merge.
    assert config["data"] == {"$patch": "replace", **DISABLED}


def test_ax_staging_preserves_upstream_and_installer_prerequisites(tmp_path: Path) -> None:
    prepare = runpy.run_path(str(ROOT / "ops/ax/prepare-substrate.py"))["prepare"]
    source = tmp_path / "source"
    kind = source / "manifests/ate-install/kind"
    kind.mkdir(parents=True)
    original = "resources: [otel-collector.yaml, prometheus.yaml, ate-otel-config.yaml]\n"
    (kind / "kustomization.yaml").write_text(original)
    (kind / "ate-otel-config.yaml").write_text("upstream config")
    (kind / "postgres").mkdir()
    (kind / "postgres/kustomization.yaml").write_text("resources: [../../postgres]\n")
    (source / "go.mod").write_text("module test\n")
    (source / "hack").mkdir()
    (source / "hack/install-ate-kind.sh").write_text("upstream installer")
    stage = tmp_path / "stage"
    prepare(source, stage)
    install = stage / "manifests/ate-install"
    assert (install / "kind-upstream/kustomization.yaml").read_text() == original
    assert (install / "kind/postgres/kustomization.yaml").read_text() == "resources: [../../postgres]\n"
    assert (kind / "kustomization.yaml").read_text() == original
    assert (kind / "ate-otel-config.yaml").read_text() == "upstream config"
    assert (stage / "hack/install-ate-kind.sh").read_text() == "upstream installer"
    assert (stage / "go.mod").is_symlink()
    config = yaml.safe_load((install / "kind/ate-otel-config.yaml").read_text())
    assert config["data"] == DISABLED  # direct installer apply must not contain $patch
    overlay = yaml.safe_load((install / "kind/kustomization.yaml").read_text())
    patch = yaml.safe_load((install / "kind" / overlay["patches"][-1]["path"]).read_text())
    assert patch["data"] == {"$patch": "replace", **DISABLED}
    with pytest.raises(ValueError, match="must be empty"):
        prepare(source, stage)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("existing", [False, True])
def test_ax_reconciles_observability_on_ready_clusters(tmp_path: Path, enabled: bool, existing: bool) -> None:
    """Execute the reconciliation shell with a function double, never real kubectl."""
    import json
    import os
    import subprocess
    import sys

    script = (ROOT / "ops/ax/up.sh").read_text()
    section = script.split("# Reconcile the choice", 1)[1].split('kubectl --context "$CTX" -n ate-system get pods', 1)[0]
    section = "# Reconcile the choice" + section
    source = tmp_path / "substrate/manifests/ate-install/kind"
    source.mkdir(parents=True)
    upstream_data = {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4317", "OTEL_LOGS_EXPORTER": "otlp"}
    (source / "ate-otel-config.yaml").write_text(yaml.safe_dump({"data": upstream_data}))
    log = tmp_path / "calls"
    consumer = {
        "kind": "Deployment",
        "metadata": {"name": "ate-controller"},
        "spec": {"template": {"spec": {"containers": [{"envFrom": [{"configMapRef": {"name": "ate-otel-config"}}]}]}}},
    }
    nonconsumer = {"kind": "Deployment", "metadata": {"name": "unrelated"}, "spec": {"template": {"spec": {"containers": []}}}}
    mock = """
set -euo pipefail
kubectl() {
  printf '%s\\t' "$@" >> "$CALL_LOG"
  printf '\\n' >> "$CALL_LOG"
  case " $* " in
    *" get deployment "*)
      if [ "$EXISTING" = 1 ]; then printf 'deployment.apps/%s\\n' "$7"; fi ;;
    *" get deployments,daemonsets "*) printf '%s' "$WORKLOADS" ;;
  esac
  return 0
}
"""
    env = {
        **os.environ,
        "OBSERVABILITY": str(enabled).lower(),
        "EXISTING": str(int(existing)),
        "PY": sys.executable,
        "CTX": "test-context",
        "SRC": str(tmp_path),
        "REPO_ROOT": str(ROOT),
        "CALL_LOG": str(log),
        "WORKLOADS": json.dumps({"items": [consumer, nonconsumer]}),
    }
    result = subprocess.run(["bash", "-c", mock + section], env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    calls = [line.rstrip("\t").split("\t") for line in log.read_text().splitlines()]
    scales = [call for call in calls if "scale" in call]
    assert len(scales) == (3 if existing and not enabled else 0)
    assert all(call[-1] == "--replicas=0" for call in scales)
    applies = [call for call in calls if "apply" in call]
    assert len(applies) == (2 if enabled else 0)
    config_patch = next(call[-1] for call in calls if "configmap" in call)
    assert json.loads(config_patch) == [{"op": "replace", "path": "/data", "value": upstream_data if enabled else DISABLED}]
    assert not any("deployment/unrelated" in call for call in calls)
    assert any("deployment/ate-controller" in call for call in calls)
    if not enabled:
        assert "OUSAST_KIND_OBSERVABILITY=1" in result.stdout
