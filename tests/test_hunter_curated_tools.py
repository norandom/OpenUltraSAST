"""learning-harness task 1.5: curated repository tools and hunter-loop parameters (offline)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from openultrasast.hunter_tools import PathEscapesRepo
from openultrasast.tool_hunter import ChatResponse, ScriptedChatClient, ToolCall, run_tool_hunter

APP = (
    "from flask import request\n\n\n"
    "@app.route('/books/<title>')\n@login_required\ndef guarded(title):\n"
    "    return Book.query.filter_by(book_title=title).first()\n\n\n"
    "@app.route('/books/any/<title>')\ndef leaky(title):\n"
    "    owner = request.args.get('owner')\n"
    "    return Book.query.filter_by(user_id=owner, book_title=title).first()\n\n\n"
    "def helper(value):\n"
    "    return value.strip()\n"
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(APP)
    return tmp_path


def test_read_definition_returns_one_span_and_refuses_to_leave_the_repository(repo: Path) -> None:
    from openultrasast.hunter_tools import read_definition

    found = read_definition(repo, "leaky", max_chars=4000)
    assert found is not None
    assert found["path"] == "app.py" and found["name"] == "leaky"
    assert found["start_line"] == 10 and found["end_line"] == 13
    assert str(found["text"]).startswith("@app.route('/books/any/<title>')")  # a handler's decorators come with it
    assert "def leaky" in str(found["text"]) and "def guarded" not in str(found["text"])
    assert read_definition(repo, "not_a_function", max_chars=4000) is None
    with pytest.raises(PathEscapesRepo):
        read_definition(repo, "leaky", max_chars=4000, path="../outside.py")


def test_entry_points_lists_handlers_with_their_access_and_never_source_text(repo: Path) -> None:
    from openultrasast.hunter_tools import entry_points

    rows = entry_points(repo)
    by_function = {str(row["function"]): row for row in rows if row.get("function")}
    assert {"guarded", "leaky"} <= set(by_function)
    assert by_function["guarded"]["access_level"] == "authenticated" and by_function["leaky"]["access_level"] == "public"
    assert by_function["leaky"]["path"] == "app.py" and isinstance(by_function["leaky"]["line"], int)
    assert all("text" not in row and "content" not in row for row in rows)  # identifiers and spans only
    assert entry_points(repo, path="app.py") == rows
    with pytest.raises(PathEscapesRepo):
        entry_points(repo, path="../elsewhere.py")


def test_obligations_lists_what_a_function_owes_without_dumping_code(repo: Path) -> None:
    from openultrasast.hunter_tools import obligations

    rows = obligations(repo, path="app.py", function="leaky")
    assert rows and all(row["function"] == "leaky" for row in rows)
    assert {"protected_read"} == {str(row["operation"]) for row in rows}
    assert "identity_constraint" in {str(row["missing"]) for row in rows}
    assert all("text" not in row and "content" not in row for row in rows)
    assert obligations(repo, path="app.py", function="helper") == []
    with pytest.raises(PathEscapesRepo):
        obligations(repo, path="../outside.py", function="leaky")


def test_flows_lists_adjudicated_source_to_sink_records_for_one_function(repo: Path) -> None:
    from openultrasast.hunter_tools import flows

    (repo / "flow.py").write_text("from flask import request\nimport os\n\n\ndef run():\n    os.system(request.args.get('cmd'))\n")
    rows = flows(repo, path="flow.py", function="run")
    assert all(row["function"] == "run" and row["path"] == "flow.py" for row in rows)
    assert all(set(row) <= {"path", "function", "line", "sources", "sinks", "disposition", "cwe"} for row in rows)
    assert flows(repo, path="app.py", function="helper") == []
    with pytest.raises(PathEscapesRepo):
        flows(repo, path="/etc/passwd", function="run")


def test_the_loop_keeps_todays_behaviour_by_default(repo: Path) -> None:
    from openultrasast.complexity.map import Hotspot
    from openultrasast.tool_hunter import DEFAULT_TOOL_NAMES

    hotspot = Hotspot(
        path="app.py",
        function_name=None,
        score=1.0,
        band="high",
        signals={},
        rationale="fixture",
        test_hint=None,
        inventory_finding_ids=(),
    )
    client = ScriptedChatClient(
        [
            ChatResponse(tool_calls=(ToolCall(id="1", name="read_file", arguments={"path": "app.py"}),)),
            ChatResponse(content='[{"path": "app.py", "line": 12, "title": "t", "rationale": "r"}]'),
        ]
    )
    findings = run_tool_hunter(repo, [hotspot], client=client, model="m", max_steps=4)
    assert [finding.finding_id for finding in findings] == ["tool-hunter:app.py:12"]
    assert findings[0].tags == ["tool-hunter"] and findings[0].evidence_level == "suspicion"
    assert tuple(tool["function"]["name"] for tool in client.calls[0]["tools"]) == DEFAULT_TOOL_NAMES


def test_the_loop_takes_a_prompt_context_tools_and_tags_and_replays_reasoning(repo: Path) -> None:
    from openultrasast.complexity.map import Hotspot

    hotspot = Hotspot(
        path="app.py",
        function_name="leaky",
        score=1.0,
        band="high",
        signals={},
        rationale="fixture",
        test_hint=None,
        inventory_finding_ids=(),
    )
    client = ScriptedChatClient(
        [
            ChatResponse(
                content="looking",
                reasoning="first I check the route",
                tool_calls=(ToolCall(id="1", name="obligations", arguments={"path": "app.py", "function": "leaky"}),),
            ),
            ChatResponse(content='[{"path": "app.py", "line": 12, "title": "t", "rationale": "r"}]'),
        ]
    )
    findings = run_tool_hunter(
        repo,
        [hotspot],
        client=client,
        model="m",
        max_steps=4,
        system_prompt="You hunt access control only.",
        user_prompt="Look at leaky.",
        context_files=("app.py",),
        tools=("read_definition", "obligations"),
        tags=("family:access_control", "detector:access_control@1"),
    )
    first = client.calls[0]
    assert first["messages"][0]["content"] == "You hunt access control only."
    assert "Look at leaky." in str(first["messages"][1]["content"]) and "def leaky" in str(first["messages"][1]["content"])
    assert [tool["function"]["name"] for tool in first["tools"]] == ["read_definition", "obligations"]
    replayed = [message for message in client.calls[1]["messages"] if message.get("role") == "assistant"]
    assert replayed and replayed[0]["reasoning_content"] == "first I check the route"
    tool_reply = json.loads(str(client.calls[1]["messages"][-1]["content"]))
    assert tool_reply and tool_reply[0]["missing"] == "identity_constraint"
    assert findings[0].tags == ["family:access_control", "detector:access_control@1"]


def test_the_loop_asks_once_more_for_the_answer_instead_of_dropping_prose() -> None:
    """Measured live: the model spends its step budget on tools and then answers in prose, and the whole hunt is
    discarded (learning-harness Req 6.3).

    Four steps, three of them tool calls, and the fourth a paragraph that names the sink, the argument and the
    line — parsed as nothing. A detector that found the bug and reported zero is indistinguishable from one that
    found nothing, and every family in round zero would have baselined at zero for this reason alone."""
    from openultrasast.tool_hunter import ChatResponse, ScriptedChatClient, ToolCall, run_tool_hunter

    prose = "The function passes `command` straight to os.system at line 2, an OS command sink."
    answer = json.dumps([{"path": "app.py", "line": 2, "title": "command injection", "rationale": "os.system(command)"}])
    client = ScriptedChatClient(
        [
            ChatResponse(tool_calls=(ToolCall(id="c1", name="grep_repo", arguments={"pattern": "system"}),)),
            ChatResponse(tool_calls=(ToolCall(id="c2", name="read_file", arguments={"path": "app.py"}),)),
            ChatResponse(content=prose),
            ChatResponse(content=answer),  # the one extra turn, asked for explicitly
        ]
    )
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / "app.py").write_text("import os\ndef run(command):\n    return os.system(command)\n")
        findings = run_tool_hunter(root, [], client=client, model="m", max_steps=3)
    assert [item.line for item in findings] == [2]
    final = client.calls[-1]
    assert final.get("json_object") is True, "the last turn asks the provider for JSON, it does not hope for it"
    text = "\n".join(str(message.get("content") or "") for message in final["messages"])
    assert "JSON" in text and prose in text, "the prose it already wrote is what the final turn is asked to format"


def test_a_hunt_that_never_called_a_tool_still_reports_nothing() -> None:
    """The extra turn is for formatting an answer, never for inventing one."""
    from openultrasast.tool_hunter import ChatResponse, ScriptedChatClient, run_tool_hunter

    client = ScriptedChatClient([ChatResponse(content="I think there is an injection here."), ChatResponse(content="[]")])
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / "app.py").write_text("x = 1\n")
        assert run_tool_hunter(root, [], client=client, model="m", max_steps=3) == []
    assert len(client.calls) == 1, "no tool was called, so there is nothing to format"
