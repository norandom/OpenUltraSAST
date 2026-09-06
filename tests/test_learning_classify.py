"""learning-harness task 2.1: the three-tier auto-classifier (offline)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.benchmark import ExpectedFinding
from openultrasast.findings import StaticFinding
from openultrasast.learning.families import load_families
from openultrasast.pairs import PairCase
from openultrasast.tool_hunter import ChatResponse, ScriptedChatClient

APP = (
    "from flask import request\n\n\n"
    "@app.route('/books/<title>')\n@login_required\ndef guarded(title):\n"
    "    return Book.query.filter_by(book_title=title).first()\n\n\n"
    "@app.route('/books/any/<title>')\ndef leaky(title):\n"
    "    owner = request.args.get('owner')\n"
    "    return Book.query.filter_by(user_id=owner, book_title=title).first()\n"
)


def _case(tmp_path: Path, **row: object) -> PairCase:
    (tmp_path / "v.py").write_text(APP)
    (tmp_path / "f.py").write_text(APP + "# fixed\n")
    expected = ExpectedFinding(
        cwe=str(row.get("cwe", "")),
        vulnerability_class="x",
        path="app.py",
        evidence="",
        function="leaky",
        mechanism=str(row.get("mechanism", "other")),
        family=row.get("family"),  # type: ignore[arg-type]
    )
    return PairCase(
        name="t",
        slice="vibe-py",
        language="python",
        origin="test",
        vuln_file=tmp_path / "v.py",
        fixed_file=tmp_path / "f.py",
        relpath="app.py",
        expected=(expected,),
        min_recall=1.0,
        fix_policy="silent",
    )


def test_tier_one_decides_from_a_declared_family_a_mechanism_or_a_weakness(tmp_path: Path) -> None:
    from openultrasast.learning.classify import classify_pair

    taxonomy = load_families()
    declared = classify_pair(_case(tmp_path, family="injection", cwe="CWE-639"), taxonomy, client=None)
    assert declared.families == ("injection",) and declared.tier == "static"  # a declared label wins
    mechanism = classify_pair(_case(tmp_path, mechanism="missing_auth_guard"), taxonomy, client=None)
    assert mechanism.families == ("access_control",) and mechanism.tier == "static"
    weakness = classify_pair(_case(tmp_path, cwe="CWE-89", mechanism="source_reaches_sink"), taxonomy, client=None)
    assert weakness.families == ("injection",) and weakness.tier == "static"  # the generic mechanism defers to the weakness
    nothing = classify_pair(_case(tmp_path, mechanism="other"), taxonomy, client=None)
    assert nothing.families == () and nothing.tier == "none"  # unknown, and no client to ask


def test_tier_one_reads_a_finding_from_its_tags_and_its_rule(tmp_path: Path) -> None:
    from openultrasast.learning.classify import classify_finding

    taxonomy = load_families()

    def finding(finding_id: str, tags: list[str]) -> StaticFinding:
        return StaticFinding(
            finding_id=finding_id,
            path="app.py",
            title="t",
            severity="medium",
            confidence="low",
            evidence_level="suspicion",
            rationale="r",
            line=12,
            function_name="leaky",
            reachability_status="unknown",
            reachability_evidence=[],
            reachability_conditions=[],
            tags=tags,
            ranking_priority=0.0,
        )

    tagged = classify_finding(finding("x:app.py:1", ["family:access_control"]), taxonomy, client=None)
    assert tagged.families == ("access_control",) and tagged.tier == "static"
    obligated = classify_finding(finding("obligation:protected_read:app.py:12:x", ["obligation:protected_read"]), taxonomy, client=None)
    assert obligated.families == ("access_control",)
    ruled = classify_finding(finding("python-os-command:app.py:3", ["tool-hunter"]), taxonomy, client=None)
    assert ruled.families == ("injection",) and ruled.tier == "static"  # the rule's weakness names the family
    assert classify_finding(finding("tool-hunter:app.py:3", ["tool-hunter"]), taxonomy, client=None).families == ()


def test_tier_one_classifies_the_shared_handler_without_any_client(tmp_path: Path) -> None:
    from openultrasast.learning.classify import classify_region

    (tmp_path / "app.py").write_text(APP)
    taxonomy = load_families()
    leaky = classify_region(tmp_path, "app.py", function="leaky", taxonomy=taxonomy, client=None)
    assert leaky.families == ("access_control",) and leaky.tier == "static"
    (tmp_path / "flow.py").write_text("from flask import request\nimport os\n\n\ndef run():\n    os.system(request.args.get('cmd'))\n")
    injected = classify_region(tmp_path, "flow.py", function="run", taxonomy=taxonomy, client=None)
    assert "injection" in injected.families


def test_tier_two_asks_the_model_only_when_static_signals_say_nothing(tmp_path: Path) -> None:
    from openultrasast.learning.classify import classify_pair

    taxonomy = load_families()
    client = ScriptedChatClient([ChatResponse(content=json.dumps({"families": ["output_encoding"]}), mean_logprob=-0.05)])
    answered = classify_pair(_case(tmp_path, mechanism="other"), taxonomy, client=client)
    assert answered.families == ("output_encoding",) and answered.tier == "model" and answered.confidence == -0.05
    quiet = ScriptedChatClient([ChatResponse(content=json.dumps({"families": ["injection"]}))])
    classify_pair(_case(tmp_path, mechanism="missing_auth_guard"), taxonomy, client=quiet)
    assert quiet.calls == []  # a static answer never spends a model call


def test_an_unsure_or_off_vocabulary_answer_becomes_unknown(tmp_path: Path) -> None:
    from openultrasast.learning.classify import classify_pair

    taxonomy = load_families()
    invented = ScriptedChatClient([ChatResponse(content=json.dumps({"families": ["sql_injection"]}), mean_logprob=-0.01)])
    assert classify_pair(_case(tmp_path, mechanism="other"), taxonomy, client=invented).families == ()
    unsure = ScriptedChatClient([ChatResponse(content=json.dumps({"families": ["injection"]}), mean_logprob=-4.0)])
    hedged = classify_pair(_case(tmp_path, mechanism="other"), taxonomy, client=unsure)
    assert hedged.families == () and hedged.tier == "none" and hedged.confidence == -4.0
    broken = ScriptedChatClient([ChatResponse(content="not json at all")])
    assert classify_pair(_case(tmp_path, mechanism="other"), taxonomy, client=broken).families == ()


def test_the_model_is_asked_in_json_mode_with_the_taxonomy_and_no_thinking(tmp_path: Path) -> None:
    from openultrasast.learning.classify import classify_pair

    taxonomy = load_families()
    client = ScriptedChatClient([ChatResponse(content=json.dumps({"families": ["path"]}), mean_logprob=-0.1)])
    classify_pair(_case(tmp_path, mechanism="other"), taxonomy, client=client)
    call = client.calls[0]
    prompt = json.dumps(call["messages"])
    assert "json" in prompt.lower() and "access_control" in prompt and "untrusted_destination" in prompt
    assert call.get("json_object") is True and call.get("logprobs") is True and call["tools"] == []


def test_multi_label_answers_are_kept_in_taxonomy_order(tmp_path: Path) -> None:
    from openultrasast.learning.classify import classify_pair

    taxonomy = load_families()
    client = ScriptedChatClient([ChatResponse(content=json.dumps({"families": ["access_control", "injection"]}), mean_logprob=-0.2)])
    answered = classify_pair(_case(tmp_path, mechanism="other"), taxonomy, client=client)
    assert answered.families == ("injection", "access_control")  # taxonomy order, so two runs compare equal


def test_a_fabricated_family_label_in_a_catalog_is_rejected_by_name(tmp_path: Path) -> None:
    from openultrasast.learning.classify import FamilyLabelError, validate_family_labels

    taxonomy = load_families()
    good = _case(tmp_path, family="access_control")
    validate_family_labels([good], taxonomy)
    with pytest.raises(FamilyLabelError, match="not_a_family"):
        validate_family_labels([_case(tmp_path, family="not_a_family")], taxonomy)
