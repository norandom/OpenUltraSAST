"""Positive-control keystone for the path oracle (HTTP mode).

The verifier prepends a benign in-root request for a planted control marker to the
first run. Its marker returning proves the interface serves the fixture
(``control_observed`` True); its absence is recorded, not trusted as a verdict,
because a valid app may answer only its own routes. A crash on the shared app start
is caught by the existing could_not_run path. These tests fake the HTTP driver so no
real sandbox is needed; they exercise the real PathOracle and the real _side wiring."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.search import verify as verify_module
from openultrasast.search.oracles import Canary, ControlProbe, PathOracle
from openultrasast.search.verify import CommandFailure, Side, VerificationRecord, _side, verify


def _http_demo(tmp_path: Path) -> tuple[Path, Side]:
    """A minimal HTTP path demo plus a checkout whose entrypoint exists."""
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "app.js").write_text("// entrypoint presence only; the driver is faked\n")
    demo_dir = tmp_path / "demo"
    demo_dir.mkdir()
    schema = {
        "oracle": "path",
        "build": {"recipe": "none", "arguments": []},
        "start": {"runtime": "node", "path": "app.js", "arguments": ["--port", "8080"], "mode": "http", "port": 8080},
        "steps": [{"type": "http", "method": "GET", "path": "/read"}],
    }
    (demo_dir / "demo.json").write_text(json.dumps(schema))
    return demo_dir, Side(checkout=checkout)


def _spy_oracle(monkeypatch):
    """Keep a handle on the real PathOracle _side builds, so a fake driver can echo
    its control token and the nonce the way a working app would."""
    holder: dict[str, PathOracle] = {}
    real = verify_module.oracle_for

    def spy(family, browser=None):
        oracle = real(family, browser)
        if isinstance(oracle, PathOracle):
            holder["oracle"] = oracle
        return oracle

    monkeypatch.setattr(verify_module, "oracle_for", spy)
    return holder


def _is_control_run(schema):
    return schema["steps"][0]["path"] == "/control"


def test_path_oracle_plants_control_distinct_from_secret(tmp_path):
    oracle = PathOracle()
    canary = Canary.fresh(tmp_path / "fixture")
    oracle.prepare(canary)
    probe = oracle.control()
    assert isinstance(probe, ControlProbe)
    assert probe.path == "/control"
    control_file = canary.root / "public" / "control"
    assert control_file.read_text() == probe.token
    assert probe.token != canary.nonce  # the control is benign, never the secret
    assert (canary.root / "canary").read_text() == canary.nonce  # secret stays outside served root


def test_control_marker_observed_sets_flag(tmp_path, monkeypatch):
    demo_dir, side = _http_demo(tmp_path)
    holder = _spy_oracle(monkeypatch)
    seen = {"control_runs": 0}

    def fake_http_steps(schema, command, job, scratch, mounts, env, ns, nonce, runner, ready_check, diagnostics):
        if _is_control_run(schema):
            seen["control_runs"] += 1
            return [holder["oracle"].control().token]  # the control's own app start returns the marker
        return [nonce]  # the attack start reflects the effect

    monkeypatch.setattr(verify_module, "_http_steps", fake_http_steps)
    record = _side(side, demo_dir, "path", 30, None)
    assert record.outcome == "observed"
    assert len(record.runs) == 3 and all(r.observed for r in record.runs)
    assert record.control_observed is True
    assert seen["control_runs"] == 1  # the control runs once, on the first run only


def test_absent_control_marker_does_not_block(tmp_path, monkeypatch):
    demo_dir, side = _http_demo(tmp_path)
    _spy_oracle(monkeypatch)

    def fake_http_steps(schema, command, job, scratch, mounts, env, ns, nonce, runner, ready_check, diagnostics):
        if _is_control_run(schema):
            return ["a custom-route body with no control marker"]
        return [nonce]

    monkeypatch.setattr(verify_module, "_http_steps", fake_http_steps)
    record = _side(side, demo_dir, "path", 30, None)
    # A valid custom-route app that never serves /control must NOT be failed:
    # the effect is still observed and only the annotation records the miss.
    assert record.outcome == "observed"
    assert len(record.runs) == 3 and all(r.observed for r in record.runs)
    assert record.control_observed is False


def test_control_failure_does_not_block_a_working_attack(tmp_path, monkeypatch):
    # The control's own app start fails (timeout/closed/oversize), but the attack
    # route works. The verdict must stand; only the annotation records the miss.
    demo_dir, side = _http_demo(tmp_path)
    _spy_oracle(monkeypatch)

    def fake_http_steps(schema, command, job, scratch, mounts, env, ns, nonce, runner, ready_check, diagnostics):
        if _is_control_run(schema):
            raise CommandFailure("run", 1, "control route hung", "HTTP application/steps failed")
        return [nonce]

    monkeypatch.setattr(verify_module, "_http_steps", fake_http_steps)
    record = _side(side, demo_dir, "path", 30, None)
    assert record.outcome == "observed"
    assert len(record.runs) == 3 and all(r.observed for r in record.runs)
    assert record.control_observed is False


def test_control_crash_is_could_not_run(tmp_path, monkeypatch):
    demo_dir, side = _http_demo(tmp_path)
    _spy_oracle(monkeypatch)

    def fake_http_steps(schema, command, job, scratch, mounts, env, ns, nonce, runner, ready_check, diagnostics):
        raise CommandFailure("start", -9, "TypeError: mime.lookup is not a function", "HTTP application/steps failed")

    monkeypatch.setattr(verify_module, "_http_steps", fake_http_steps)
    record = _side(side, demo_dir, "path", 30, None)
    assert record.outcome == "could_not_run"
    assert record.runs == ()


def test_verify_never_demonstrates_when_app_crashes(tmp_path, monkeypatch):
    demo_dir, affected = _http_demo(tmp_path)
    safe = Side(checkout=affected.checkout)
    _spy_oracle(monkeypatch)
    monkeypatch.setattr(verify_module._sandbox, "isolation_check", lambda **kwargs: None)
    monkeypatch.setattr(verify_module._sandbox, "isolation_mode", lambda: "userns")

    def fake_http_steps(schema, command, job, scratch, mounts, env, ns, nonce, runner, ready_check, diagnostics):
        raise CommandFailure("start", -9, "boom", "HTTP application/steps failed")

    monkeypatch.setattr(verify_module, "_http_steps", fake_http_steps)
    record = verify(affected, safe, demo_dir, "path", timeout_seconds=30)
    assert isinstance(record, VerificationRecord)
    assert record.outcome != "demonstrated"
    assert record.outcome in ("could_not_run", "inconclusive")
