"""Synthetic witnesses test containment; no detector admission or real provider calls."""

import json
import time
from dataclasses import replace

import pytest
from test_push_report import report_with

from openultrasast.config import ModelConfig, ResolvedConfig
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.push.assistance import assist
from openultrasast.tool_hunter import ChatResponse


def settings():
    return ResolvedConfig(models=ModelConfig(hunter="control-model", chat_base_url="http://127.0.0.1:1", chat_api_key_env="CONTROL_KEY"))


def budget(seconds=2):
    return ExecutionBudget(time.monotonic() + seconds, 0.3)


class Client:
    def __init__(self, log, response, delay=0):
        self.log, self.response, self.delay = log, response, delay
        self.usage = []

    def complete(self, **kwargs):
        self.log.write_text(json.dumps(kwargs))
        time.sleep(self.delay)
        self.usage.append({"prompt_tokens": 12, "completion_tokens": 6})
        return ChatResponse(content=self.response)


def test_default_never_resolves_endpoint(monkeypatch):
    import openultrasast.model.endpoint as endpoint

    def unexpected(*args, **kwargs):
        raise AssertionError("default must not resolve a provider")

    monkeypatch.setattr(endpoint, "resolve_chat_endpoint", unexpected)
    report = report_with()
    assert assist(report, config=None, budget=budget()) is report


def test_only_existing_witness_can_be_selected_and_input_redacted(tmp_path):
    report = report_with()
    secret = "sk-" + "z" * 24
    defect = report.admission.defects[0]
    report = replace(
        report,
        admission=replace(
            report.admission, defects=(replace(defect, witnesses=(defect.witnesses[0], "request -> exec; api_key = " + secret)),)
        ),
    )
    client = Client(tmp_path / "request", '{"selections":[{"defect_id":"defect-0","witness_index":1}]}')
    result = assist(report, config=settings(), budget=budget(), client=client)
    assert secret not in client.log.read_text()
    assert "REDACTED" in client.log.read_text()
    assert result.result == report.result and result.admission == report.admission and result.scans == report.scans
    assert result.model_assistance["status"] == "completed"
    assert result.model_assistance["selections"] == {"defect-0": 1}
    assert result.model_assistance["usage"][0]["prompt_tokens"] == 12
    assert result.model_assistance["cost_usd"] is None
    assert result.provenance["model"] == "control-model"
    assert result.model_assistance["prompt_sha256"]


@pytest.mark.parametrize(
    "reply",
    [
        '{"rung":"execution_confirmed","finding":"invented"}',
        '{"selections":[{"defect_id":"new-defect","witness_index":0}]}',
        '{"selections":[{"defect_id":"defect-0","witness_index":999}]}',
    ],
)
def test_misleading_response_cannot_create_claims(tmp_path, reply):
    report = report_with()
    result = assist(report, config=settings(), budget=budget(), client=Client(tmp_path / "request", reply))
    assert result.result == report.result and result.admission == report.admission
    assert result.model_assistance["status"] == "invalid_selection"
    assert result.model_assistance["selections"] == {}
    assert reply not in json.dumps(dict(result.model_assistance))


def test_delayed_model_cannot_extend_deadline(tmp_path):
    report = report_with()
    start = time.monotonic()
    result = assist(report, config=settings(), budget=budget(0.15), client=Client(tmp_path / "request", "{}", 5))
    assert time.monotonic() - start < 0.6
    assert result.result == report.result
    assert result.model_assistance["status"] == "deadline_exhausted"
    assert result.model_assistance["cost_usd"] is None
    assert json.loads((tmp_path / "request").read_text())["timeout_seconds"] <= 0.15


def test_unadmitted_candidates_never_sent(tmp_path):
    report = report_with(admitted=False)
    client = Client(tmp_path / "request", "{}")
    result = assist(report, config=settings(), budget=budget(), client=client)
    assert not client.log.exists()
    assert result.result == report.result
    assert result.model_assistance["status"] == "no_admitted_witnesses"


@pytest.mark.parametrize("priced", [False, True])
def test_existing_endpoint_adapter_and_cost_receipt(tmp_path, monkeypatch, priced):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    import openultrasast.model.endpoint as endpoints

    if priced:
        monkeypatch.setitem(endpoints._PRICES, "control-model", endpoints.Prices(1, 2, 3))
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            data = json.dumps(
                {
                    "choices": [{"message": {"content": '{"selections":[{"defect_id":"defect-0","witness_index":0}]}'}}],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 6},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.delenv(endpoints.CLIENT_ENV, raising=False)
    monkeypatch.setenv("CONTROL_KEY", "local-control-only")
    config = tmp_path / "models.toml"
    config.write_text(
        f'[models]\nhunter="control-model"\nchat_base_url="http://127.0.0.1:{server.server_port}"\nchat_api_key_env="CONTROL_KEY"\n'
    )
    try:
        report = report_with()
        result = assist(report, config=config, budget=budget(3))
        assert len(requests) == 1
        assert requests[0]["model"] == "control-model"
        assert result.model_assistance["status"] == "completed"
        assert result.model_assistance["completed_calls"] == 1
        assert result.model_assistance["usage"] == [{"prompt_tokens": 12, "completion_tokens": 6}]
        assert result.model_assistance["cost_status"] == ("recorded" if priced else "unknown")
        assert result.model_assistance["cost_usd"] == (pytest.approx(42 / 1_000_000) if priced else None)
        assert "local-control-only" not in json.dumps(dict(result.model_assistance))
        assert result.result == report.result
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_selected_witness_rendering_redacts_known_secret(tmp_path):
    from openultrasast.push.report import render_report

    report = report_with()
    defect = report.admission.defects[0]
    secret = "sk-" + "q" * 24
    disposition = report.admission.dispositions[0]
    disposition = replace(disposition, candidate=replace(disposition.candidate, delta=replace(disposition.candidate.delta, witness=secret)))
    report = replace(
        report, admission=replace(report.admission, defects=(replace(defect, witnesses=(secret,)),), dispositions=(disposition,))
    )
    result = assist(
        report,
        config=settings(),
        budget=budget(),
        client=Client(tmp_path / "request", '{"selections":[{"defect_id":"defect-0","witness_index":0}]}'),
    )
    assert secret not in render_report(result, artifact=None)
    assert "REDACTED" in render_report(result, artifact=None)


def test_explicit_config_does_not_read_project_dotenv(tmp_path, monkeypatch):
    import openultrasast.config as configuration
    from openultrasast.cli import main

    def forbidden(*args, **kwargs):
        raise AssertionError("push must not read project .env")

    monkeypatch.setattr(configuration, "load_dotenv", forbidden)
    monkeypatch.setattr("openultrasast.cli.load_dotenv", forbidden)
    config = tmp_path / "config.toml"
    config.write_text('[models]\nhunter="test"\nchat_base_url="http://127.0.0.1:1"\n')
    result = assist(report_with(admitted=False), config=config, budget=budget())
    assert result.model_assistance["status"] == "no_admitted_witnesses"
    with pytest.raises(SystemExit) as stopped:
        main(["pre-push", "--help"])
    assert stopped.value.code == 0


def test_selected_witness_keeps_its_location_and_change_binding():
    from openultrasast.push.report import render_report

    report = report_with()
    defect = report.admission.defects[0]
    disposition = report.admission.dispositions[0]
    delta = disposition.candidate.delta
    second = replace(delta, witness="second request -> exec", head_operation=replace(delta.head_operation, line=9))
    report = replace(
        report,
        admission=replace(
            report.admission,
            defects=(replace(defect, witnesses=(*defect.witnesses, second.witness), locations=(*defect.locations, ("handler.src", 9))),),
            dispositions=(*report.admission.dispositions, replace(disposition, candidate=replace(disposition.candidate, delta=second))),
        ),
        model_assistance={"selections": {"defect-0": 1}},
    )
    rendered = render_report(report, artifact=None)
    assert "handler.src:9" in rendered
    assert "second request -> exec" in rendered
    assert report.result.actionable_defect_ids == ("defect-0",)
