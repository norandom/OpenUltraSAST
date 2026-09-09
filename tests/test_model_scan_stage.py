"""contributor-scan task 1.3: the model layer reaches a user (Req 1).

`model-grounded-detection` finished 16/16 with the model layer having zero production callers: everything it
measured came from a harness. This is the stage that closes that, and it is deliberately additive — the
pattern, overlay and obligation findings all keep working, and a machine without a CPG engine scans exactly
as it does today.
"""

from __future__ import annotations

from pathlib import Path

import pytest


class _Runtime:
    """The two things `_run_model_layer` uses. A real HarnessRuntime needs a scan id, config and trace
    writer, none of which this behaviour depends on."""

    def __init__(self) -> None:
        self.state: dict[str, list] = {"degradations": []}

    def run_stage(self, name, fn):  # type: ignore[no-untyped-def]
        return fn()


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\n\n\ndef run():\n    cmd = request.args['c']\n    os.system(cmd)\n"
    )
    return tmp_path


def test_the_model_config_block_exists_and_is_conservative() -> None:
    """Req 8.4: optional planes default to something that cannot surprise a first-time user."""
    from openultrasast.config import load_config

    model = load_config(None).model
    assert model.max_model_calls > 0 and model.max_regions > 0
    assert model.max_model_calls <= 500, "a default budget should not be able to run away"


def test_the_config_is_readable_from_toml(tmp_path: Path) -> None:
    from openultrasast.config import load_config

    path = tmp_path / "ousast.toml"
    path.write_text("[model]\nenabled = false\nmax_model_calls = 7\nmax_regions = 3\n")
    model = load_config(path).model
    assert model.enabled is False and model.max_model_calls == 7 and model.max_regions == 3


def test_without_a_cpg_engine_the_stage_degrades_and_records_why(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Req 1.3: the model layer is additive. A machine without Joern must scan exactly as it does today."""
    from openultrasast.cli import _run_model_layer
    from openultrasast.config import load_config

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "off")
    runtime = _Runtime()
    findings, payload = _run_model_layer(
        root=_repo(tmp_path), targets=[], entries=[], settings=load_config(None).model, runtime=runtime, config=load_config(None)
    )
    assert findings == []
    assert any(d.get("reason") == "cpg_unavailable" for d in runtime.state["degradations"])
    assert payload["skipped"] == "cpg_unavailable"


def test_the_payload_reports_what_the_model_arbitrated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Req 1.5: a user should see how much of a result the model established, not have to infer it."""
    from openultrasast.cli import _run_model_layer
    from openultrasast.config import load_config

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "off")
    _, payload = _run_model_layer(
        root=_repo(tmp_path), targets=[], entries=[], settings=load_config(None).model, runtime=_Runtime(), config=load_config(None)
    )
    assert set(payload) >= {"by_rung", "regions_scanned", "regions_unjudged", "model_calls", "cost_usd"}


def test_unjudged_regions_are_reported_with_their_rank(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """What the budget could not reach is what a large-repository exclusion list should be built from, so the
    lowest-ranked skipped regions are named rather than merely counted."""
    from openultrasast.cli import _model_payload
    from openultrasast.model.scan import ModelScanResult

    result = ModelScanResult(by_rung={}, regions_scanned=2, regions_unjudged=8, model_calls=2, cost_usd=0.01)
    payload = _model_payload(result, unjudged_paths=("low/a.py", "low/b.py"))
    assert payload["regions_unjudged"] == 8
    assert payload["unjudged_sample"] == ["low/a.py", "low/b.py"]


def test_a_disabled_model_layer_runs_nothing(tmp_path: Path) -> None:
    from openultrasast.cli import _run_model_layer
    from openultrasast.config import ModelLayerConfig, load_config

    findings, payload = _run_model_layer(
        root=_repo(tmp_path), targets=[], entries=[], settings=ModelLayerConfig(enabled=False), runtime=_Runtime(), config=load_config(None)
    )
    assert findings == [] and payload["skipped"] == "disabled"
