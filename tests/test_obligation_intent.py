"""authorization-obligations task 3.3: the hunter adjudicates intent without raising evidence (offline, scripted)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_obligation_check import _check  # noqa: E402

from openultrasast.tool_hunter import ChatResponse, ScriptedChatClient  # noqa: E402


def test_scripted_client_answers_are_recorded_on_the_finding_and_change_nothing_else() -> None:
    from openultrasast.semantic.obligations.intent import adjudicate_intent

    result = _check()
    before = {(f.operation.function, f.missing): (f.label, f.evidence) for f in result.findings}
    client = ScriptedChatClient([ChatResponse(content='{"intent": "public", "rationale": "health-style listing endpoint"}')] * 10)
    adjudicated = adjudicate_intent(result, client=client, model="test-model", texts={"app.py": "..."})
    leaky = next(f for f in adjudicated.findings if f.operation.function == "leaky" and f.missing == "identity_constraint")
    assert leaky.intent == "public" and leaky.label == before[("leaky", "identity_constraint")][0]
    assert {(f.operation.function, f.missing): (f.label, f.evidence) for f in adjudicated.findings} == before
    assert client.calls and all(call["model"] == "test-model" for call in client.calls)
    prompt = json.dumps(client.calls[0]["messages"])
    assert "meant to be public" in prompt and "app.py::constrained" in prompt  # the question names the route and its siblings
    assert not any(d["reason"] == "intent_adjudication_unavailable" for d in adjudicated.degradations)


def test_without_a_client_one_degradation_is_recorded_and_findings_are_identical() -> None:
    from openultrasast.semantic.obligations.intent import adjudicate_intent

    result = _check()
    adjudicated = adjudicate_intent(result, client=None, model="", texts={})
    assert [f.intent for f in adjudicated.findings] == [None] * len(result.findings)
    assert [(f.operation.function, f.missing, f.label) for f in adjudicated.findings] == [
        (f.operation.function, f.missing, f.label) for f in result.findings
    ]
    assert sum(1 for d in adjudicated.degradations if d["reason"] == "intent_adjudication_unavailable") == 1


def test_malformed_or_off_vocabulary_answers_are_recorded_as_unknown() -> None:
    from openultrasast.semantic.obligations.intent import adjudicate_intent

    result = _check()
    client = ScriptedChatClient([ChatResponse(content="sure, looks fine"), ChatResponse(content='{"intent": "banana"}')] * 10)
    adjudicated = adjudicate_intent(result, client=client, model="m", texts={})
    assert all(f.intent == "unknown" for f in adjudicated.findings if f.route)
    assert all(f.evidence == g.evidence and f.label == g.label for f, g in zip(adjudicated.findings, result.findings, strict=True))


def test_scan_records_intent_when_a_scripted_hunter_client_is_configured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from test_obligation_scan import APP, _repo, _run_dir

    from openultrasast.cli import main

    repo = _repo(tmp_path, monkeypatch)
    (repo / "app.py").write_text(APP)
    (repo / "openultrasast.toml").write_text('[obligations]\nmin_siblings = 2\n\n[models]\nhunter = "scripted-model"\n')
    monkeypatch.setenv("OPENULTRASAST_HUNTER_CLIENT", "scripted")
    assert main(["scan", str(repo), "--mode", "standard", "--config", str(repo / "openultrasast.toml")]) == 0
    sarif = json.loads((_run_dir(repo) / "report.sarif").read_text())
    props = [r["properties"] for r in sarif["runs"][0]["results"] if r["properties"]["finding_id"].startswith("obligation:")]
    assert props and all(p["evidence_level"] == "suspicion" for p in props)
    assert all("obligation_intent" in p for p in props)


def test_the_prompt_carries_the_handler_own_lines_only_and_is_redacted() -> None:
    """Round-3 findings: redacted handler text (design Security Considerations) and nothing beyond the handler's lines."""
    from test_obligation_check import APP

    from openultrasast.semantic.obligations.intent import adjudicate_intent

    result = _check()
    client = ScriptedChatClient([ChatResponse(content='{"intent": "protected", "rationale": "r"}')] * 10)
    adjudicate_intent(result, client=client, model="m", texts={"app.py": APP})
    leaky_prompt = next(json.dumps(call["messages"]) for call in client.calls if "def leaky" in json.dumps(call["messages"]))
    assert "@app.route('/books/any/<title>')" in leaky_prompt
    assert all(other not in leaky_prompt for other in ("def guarded", "def constrained", "def health"))
    key = "sk-" + "x" * 20  # assembled at runtime: never a contiguous key-shaped literal in a test
    leaky_with_secret = APP.replace("def leaky(title):\n", f"def leaky(title):\n    api_key = '{key}'\n")
    client = ScriptedChatClient([ChatResponse(content='{"intent": "protected", "rationale": "r"}')] * 10)
    adjudicate_intent(result, client=client, model="m", texts={"app.py": leaky_with_secret})
    prompts = json.dumps([call["messages"] for call in client.calls])
    assert "***REDACTED***" in prompts and key not in prompts
