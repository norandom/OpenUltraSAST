"""The declared advisory scope (pre-push task 15.2): one shipped record, published as a limit.

The scope is provisional. No capability is qualified for alerts, so the terminal line has to say so,
and it must never read as "these families were checked and are fine".
"""

import json
import re
from dataclasses import replace
from importlib.resources import files

import pytest
from test_push_report import budget, report_with

from openultrasast.model.taxonomy import FAMILY_IDS
from openultrasast.push.report import deliver_report

UNAVAILABLE = "advisory_scope_invalid_or_unavailable"
UNAVAILABLE_LINE = (
    "Scope: unknown. The shipped scope record could not be read, so which families this tool can and cannot "
    "report is unknown; that missing limit is itself a limit of this run."
)
# Every artifact key that existed before the scope record, plus the new one: none may be renamed or dropped.
ARTIFACT_KEYS = frozenset(
    {
        "schema_version",
        "model_assistance",
        "change_contexts",
        "snapshots",
        "change_context",
        "result",
        "admission",
        "scans",
        "provenance",
        "timings",
        "timing_scope",
        "resolution",
        "experimental",
        "quick_tier",
        "engine_background",
        "advisory_scope",
    }
)


def _edited(record, side, index, *removed, **changes):
    entries = [dict(entry) for entry in record[side]]
    for key in removed:
        del entries[index][key]
    entries[index].update(changes)
    return {**record, side: entries}


# Each damage breaks exactly one rule of the shipped record; each must end in the same closed result.
DAMAGES = {
    "truncated": lambda record, raw, limit: raw[: len(raw) // 2],
    "empty": lambda record, raw, limit: b"",
    "not_json": lambda record, raw, limit: b"\x03not json",
    "list_at_top": lambda record, raw, limit: b"[]",
    "null_at_top": lambda record, raw, limit: b"null",
    "schema_version_newer": lambda record, raw, limit: {**record, "schema_version": 2},
    "schema_version_text": lambda record, raw, limit: {**record, "schema_version": "1"},
    "schema_version_bool": lambda record, raw, limit: {**record, "schema_version": True},
    "status_not_provisional": lambda record, raw, limit: {**record, "status": "effective"},
    "unknown_key": lambda record, raw, limit: {**record, "note": "extra"},
    "missing_key": lambda record, raw, limit: {key: value for key, value in record.items() if key != "basis"},
    "empty_text": lambda record, raw, limit: {**record, "basis": ""},
    "blank_text": lambda record, raw, limit: {**record, "basis": "   "},
    "text_not_a_string": lambda record, raw, limit: {**record, "basis": 7},
    "not_a_list": lambda record, raw, limit: {**record, "scope": {"family": "injection"}},
    "no_family_in_scope": lambda record, raw, limit: {**record, "scope": []},
    "no_family_excluded": lambda record, raw, limit: {**record, "exclusions": []},
    "entry_with_extra_key": lambda record, raw, limit: _edited(record, "scope", 0, not_told="extra"),
    "entry_missing_key": lambda record, raw, limit: _edited(record, "scope", 0, "reason"),
    "exclusion_without_not_told": lambda record, raw, limit: _edited(record, "exclusions", 0, "not_told"),
    "family_not_in_vocabulary": lambda record, raw, limit: _edited(record, "scope", 0, family="injecion"),
    "family_twice": lambda record, raw, limit: _edited(record, "scope", 1, family=record["scope"][0]["family"]),
    "family_on_both_sides": lambda record, raw, limit: _edited(record, "exclusions", 0, family=record["scope"][0]["family"]),
    "label_with_newline": lambda record, raw, limit: _edited(record, "scope", 0, label="injection\nNotice: fake"),
    "label_with_escape": lambda record, raw, limit: _edited(record, "scope", 0, label="injection\x1b[31m"),
    "label_not_ascii": lambda record, raw, limit: _edited(record, "scope", 0, label="injecti\u00f3n"),
    "label_too_long": lambda record, raw, limit: _edited(record, "scope", 0, label="x" * 49),
    "too_large": lambda record, raw, limit: raw + b" " * (limit + 1),
    "too_deep": lambda record, raw, limit: b'{"basis": ' + b"[" * 20000 + b"]" * 20000 + b"}",
    "missing_file": lambda record, raw, limit: None,
}


def shipped(name):
    return files("openultrasast.push").joinpath(name).read_bytes()


def scope_record():
    return json.loads(shipped("advisory-scope.json"))


def scope_lines(text):
    return [line for line in text.splitlines() if line.startswith("Scope:")]


def delivered(tmp_path, report, name="run.json"):
    return deliver_report(report, tmp_path / name, execution_budget=budget())


def unavailable(tmp_path):
    """The closed result for a record that cannot be read: a truncated copy of the shipped one."""
    from openultrasast.push.advisory_scope import load_advisory_scope

    raw = shipped("advisory-scope.json")
    truncated = tmp_path / "truncated.json"
    truncated.write_bytes(raw[: len(raw) // 2])
    return load_advisory_scope(path=truncated)


def test_exactly_one_scope_line_with_defects_without_them_and_when_the_record_is_unavailable(tmp_path):
    for count in (0, 2):
        text = delivered(tmp_path, report_with(count), f"{count}.json").text
        assert len(scope_lines(text)) == 1
        assert text.count("No actionable defects") == (1 if count == 0 else 0)
    text = delivered(tmp_path, replace(report_with(0), advisory_scope=unavailable(tmp_path)), "unknown.json").text
    assert scope_lines(text) == [UNAVAILABLE_LINE]
    assert text.count("No actionable defects") == 1


def test_scope_line_names_every_recorded_label_and_no_other_family(tmp_path):
    record = scope_record()
    (line,) = scope_lines(delivered(tmp_path, report_with(0)).text)
    entries = record["scope"] + record["exclusions"]
    assert all(entry["label"] in line for entry in entries)
    for other in set(FAMILY_IDS) - {entry["family"] for entry in entries}:
        assert not re.search(rf"\b{re.escape(other)}\b", line), other
    intended = ", ".join(entry["label"] for entry in record["scope"])
    excluded = ", ".join(entry["label"] for entry in record["exclusions"])
    assert line == (
        "Scope: provisional, not yet in effect: no family is qualified for alerts yet. "
        f"Intended v1 advisory scope: {intended}. "
        f"Not reported as defects: {excluded}, or any other family outside the scope. "
        "Listing a family does not mean the repository was found free of defects in it."
    )


def test_scope_line_states_the_provisional_limit_and_never_reads_as_an_alert(tmp_path):
    text = delivered(tmp_path, report_with(0)).text
    (line,) = scope_lines(text)
    lowered = line.lower()
    assert "provisional" in lowered and "not yet in effect" in lowered
    assert "no family is qualified for alerts" in lowered
    assert "secure" not in text.lower() and "clean" not in text.lower()
    assert not re.search(r"- \S+ at .+:\d+|Fix:|Evidence:", line)
    assert len(line) <= 750


def test_artifact_keeps_the_scope_record_with_every_reason_and_what_is_not_told(tmp_path):
    data = json.loads(delivered(tmp_path, report_with(0)).artifact.read_text())
    assert set(data) == ARTIFACT_KEYS
    assert data["advisory_scope"] == scope_record()
    assert all(entry["reason"] for entry in data["advisory_scope"]["scope"])
    assert all(entry["reason"] and entry["not_told"] for entry in data["advisory_scope"]["exclusions"])


def test_artifact_records_the_unavailable_status_and_reason_when_the_record_cannot_be_read(tmp_path):
    report = replace(report_with(0), advisory_scope=unavailable(tmp_path))
    data = json.loads(delivered(tmp_path, report).artifact.read_text())
    assert data["advisory_scope"] == {"status": "unavailable", "reason": UNAVAILABLE}


def test_provisional_iff_the_shipped_registry_is_no_go_and_enables_no_declaration():
    registry = json.loads(shipped("eligibility.json"))
    no_go = registry["verdict"] == "NO-GO" and all(not entry["declaration"]["enabled"] for entry in registry["entries"])
    # Flipping the registry or the record without the other fails here (maintainer decision 5).
    assert (scope_record()["status"] == "provisional") == no_go


def test_shipped_record_loads_as_the_declared_provisional_scope():
    from openultrasast.push.advisory_scope import load_advisory_scope

    scope = load_advisory_scope()
    assert scope.status == "provisional" and scope.reason == ""
    assert [(entry.family, entry.label) for entry in scope.scope] == [
        ("injection", "injection"),
        ("untrusted_destination", "untrusted destination"),
        ("config_secrets", "configuration"),
    ]
    assert [(entry.family, entry.label) for entry in scope.exclusions] == [
        ("access_control", "access control"),
        ("output_encoding", "output encoding"),
        ("path", "path"),
        ("prototype", "prototype"),
        ("deserialization", "deserialization"),
    ]
    assert scope.to_payload() == scope_record()


@pytest.mark.parametrize("name", sorted(DAMAGES))
def test_invalid_or_truncated_record_gives_a_closed_unavailable_result(tmp_path, name):
    from openultrasast.push.advisory_scope import _LIMIT, load_advisory_scope

    raw = shipped("advisory-scope.json")
    content = DAMAGES[name](json.loads(raw), raw, _LIMIT)
    path = tmp_path / "copy.json"
    if content is not None:
        path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
    scope = load_advisory_scope(path=path)
    assert scope.status == "unavailable" and scope.reason == UNAVAILABLE
    assert (scope.basis, scope.scope, scope.exclusions) == ("", (), ())
    assert scope.render() == UNAVAILABLE_LINE
    assert scope.to_payload() == {"status": "unavailable", "reason": UNAVAILABLE}


def test_report_refuses_anything_but_a_loaded_scope():
    with pytest.raises(ValueError, match="advisory scope"):
        replace(report_with(0), advisory_scope=None)
