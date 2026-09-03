import json
from pathlib import Path

from openultrasast.complexity.map import Hotspot
from openultrasast.tool_hunter import ChatResponse, ToolCall, run_tool_hunter

SPLIT_SINK = """\
term = request.args["q"]
query = "select * from items where title like '%" + term + "%'"
return db.execute(query)
"""

_DUMP_FINDINGS = [
    {
        "path": "app.py",
        "line": 3,
        "title": "SQL injection",
        "rationale": "query is built from request input then executed",
        "evidence_level": "static_corroboration",
    }
]


class ScriptedChatClient:
    def __init__(self, turns: list[ChatResponse]) -> None:
        self._turns = turns
        self.calls: list[dict[str, object]] = []

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, object]],
        tools: list[dict[str, object]],
        timeout_seconds: int = 60,
    ) -> ChatResponse:
        self.calls.append({"model": model, "messages": list(messages), "tools": tools, "timeout_seconds": timeout_seconds})
        index = len(self.calls) - 1
        if index >= len(self._turns):
            return ChatResponse(content="")
        return self._turns[index]


def _repo_with_split_sink(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(SPLIT_SINK)
    return root


def _hotspot(path: str = "app.py") -> Hotspot:
    return Hotspot(
        path=path,
        function_name="search",
        score=7.5,
        band="high",
        signals={"loc": 3},
        rationale="reachable split-sink",
        test_hint=None,
        inventory_finding_ids=(),
    )


def _tool_names(tools: object) -> set[str]:
    names: set[str] = set()
    if not isinstance(tools, list):
        return names
    for item in tools:
        if not isinstance(item, dict):
            continue
        function = item.get("function")
        if isinstance(function, dict) and isinstance(function.get("name"), str):
            names.add(str(function["name"]))
        elif isinstance(item.get("name"), str):
            names.add(str(item["name"]))
    return names


def test_json_dump_without_tool_call_emits_no_findings(tmp_path: Path) -> None:
    root = _repo_with_split_sink(tmp_path)
    client = ScriptedChatClient([ChatResponse(content=json.dumps(_DUMP_FINDINGS))])

    findings = run_tool_hunter(root, [_hotspot()], client=client, model="test-hunter", max_steps=4)

    assert client.calls, "the hunter loop must run when a model client is provided"
    assert _tool_names(client.calls[0]["tools"]) >= {"read_file", "grep_repo", "find_refs"}
    assert findings == []


def test_grep_then_json_yields_suspicion_with_tool_hunter_prefix(tmp_path: Path) -> None:
    root = _repo_with_split_sink(tmp_path)
    client = ScriptedChatClient(
        [
            ChatResponse(tool_calls=(ToolCall(id="call_grep", name="grep_repo", arguments={"pattern": r"query\s*=", "max_matches": 10}),)),
            ChatResponse(content=json.dumps(_DUMP_FINDINGS)),
        ]
    )

    findings = run_tool_hunter(root, [_hotspot()], client=client, model="test-hunter", max_steps=4)

    assert len(client.calls) >= 2
    assert _tool_names(client.calls[0]["tools"]) >= {"read_file", "grep_repo", "find_refs"}
    tool_trace = json.dumps(client.calls[1]["messages"])
    assert "query =" in tool_trace
    assert len(findings) == 1
    assert findings[0].evidence_level == "suspicion"
    assert findings[0].finding_id.startswith("tool-hunter:")
    assert findings[0].path == "app.py"
    assert findings[0].line == 3
    assert findings[0].title == "SQL injection"


def test_loop_dispatches_read_file_grep_repo_and_find_refs(tmp_path: Path) -> None:
    root = _repo_with_split_sink(tmp_path)
    client = ScriptedChatClient(
        [
            ChatResponse(
                tool_calls=(
                    ToolCall(id="call_read", name="read_file", arguments={"path": "app.py", "max_chars": 4000}),
                    ToolCall(id="call_grep", name="grep_repo", arguments={"pattern": r"db\.execute", "max_matches": 5}),
                    ToolCall(id="call_refs", name="find_refs", arguments={"symbol": "query"}),
                )
            ),
            ChatResponse(content=json.dumps(_DUMP_FINDINGS)),
        ]
    )

    findings = run_tool_hunter(root, [_hotspot()], client=client, model="test-hunter", max_steps=4)

    assert findings
    assert findings[0].evidence_level == "suspicion"
    second_messages = json.dumps(client.calls[1]["messages"])
    assert "term = request.args" in second_messages
    assert "db.execute" in second_messages
    assert "query" in second_messages


def test_path_escape_stays_in_band_and_still_counts_as_tool_use(tmp_path: Path) -> None:
    root = _repo_with_split_sink(tmp_path)
    client = ScriptedChatClient(
        [
            ChatResponse(tool_calls=(ToolCall(id="call_escape", name="read_file", arguments={"path": "../etc/passwd"}),)),
            ChatResponse(content=json.dumps(_DUMP_FINDINGS)),
        ]
    )

    findings = run_tool_hunter(root, [_hotspot()], client=client, model="test-hunter", max_steps=4)

    assert findings
    assert findings[0].evidence_level == "suspicion"
    assert "error" in json.dumps(client.calls[1]["messages"]).lower()


def test_max_steps_stops_before_ungrounded_json(tmp_path: Path) -> None:
    root = _repo_with_split_sink(tmp_path)
    client = ScriptedChatClient(
        [
            ChatResponse(tool_calls=(ToolCall(id="call_grep", name="grep_repo", arguments={"pattern": "query"}),)),
            ChatResponse(content=json.dumps(_DUMP_FINDINGS)),
        ]
    )

    findings = run_tool_hunter(root, [_hotspot()], client=client, model="test-hunter", max_steps=1)

    assert findings == []
    assert len(client.calls) == 1
