import json
from pathlib import Path

import pytest

from openultrasast.complexity.map import Hotspot
from openultrasast.tool_hunter import ChatResponse, OpenRouterHunterClient, ScriptedChatClient, ToolCall, run_tool_hunter

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


_UNSAFE_SNIPPET = 'client = docker.DockerClient(base_url="unix://var/run/docker.sock")\n'
_VULN = "@app.route('/admin')\ndef admin():\n    return eval(request.data)\n"


def test_hunter_json_snippet_stays_suspicion_and_is_not_static_corroboration(tmp_path: Path) -> None:
    root = _repo_with_split_sink(tmp_path)
    payload = [{**_DUMP_FINDINGS[0], "snippet": _UNSAFE_SNIPPET, "evidence_level": "static_corroboration"}]
    client = ScriptedChatClient(
        [
            ChatResponse(tool_calls=(ToolCall(id="call_grep", name="grep_repo", arguments={"pattern": "query"}),)),
            ChatResponse(content=json.dumps(payload)),
        ]
    )

    findings = run_tool_hunter(root, [_hotspot()], client=client, model="test-hunter", max_steps=4)

    assert len(findings) == 1
    assert findings[0].evidence_level == "suspicion"
    assert findings[0].finding_id.startswith("tool-hunter:")
    assert findings[0].proposed_snippet == _UNSAFE_SNIPPET


def _write_hunter_config(tmp_path: Path, body: str = '[models]\nhunter = "test-hunter"\n') -> Path:
    config = tmp_path / "openultrasast.toml"
    config.write_text(body)
    return config


def _standard_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(_VULN)
    return repo


def _latest_run(repo: Path) -> Path:
    return sorted((repo / ".runs").iterdir())[-1]


def _guard_docker(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    import subprocess

    from openultrasast.sandbox import runner as sandbox_runner

    docker_argv: list[list[str]] = []
    original_run = subprocess.run

    def guarded_run(command: object, *args: object, **kwargs: object) -> object:
        argv = list(command) if isinstance(command, list | tuple) else [command]
        if argv and Path(str(argv[0])).name == "docker":
            docker_argv.append([str(item) for item in argv])
            raise AssertionError(f"hunter scan test must not start docker: {argv}")
        return original_run(command, *args, **kwargs)

    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("hunter scan test must not use DockerCliRunner")

    monkeypatch.setattr(subprocess, "run", guarded_run)
    monkeypatch.setattr(sandbox_runner.DockerCliRunner, "run", fail)
    return docker_argv


def test_standard_scripted_hunter_emits_tool_hunter_suspicion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast import cli, tool_hunter
    from openultrasast.cli import main

    repo = _standard_repo(tmp_path)
    config = _write_hunter_config(tmp_path)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_HUNTER_CLIENT", "scripted")
    monkeypatch.setattr(cli, "has_harnessx", lambda: False)
    docker_argv = _guard_docker(monkeypatch)
    hunter_calls: list[int] = []
    real_hunter = tool_hunter.run_tool_hunter

    def wrapped(*args: object, **kwargs: object) -> object:
        hunter_calls.append(1)
        return real_hunter(*args, **kwargs)

    monkeypatch.setattr(tool_hunter, "run_tool_hunter", wrapped)

    assert main(["scan", str(repo), "--mode", "standard", "--config", str(config)]) == 0

    run_dir = _latest_run(repo)
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    complexity_map = json.loads((run_dir / "complexity_map.json").read_text())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    hunter_findings = [item for item in findings if str(item["finding_id"]).startswith("tool-hunter:")]

    assert hunter_calls
    assert docker_argv == []
    assert hunter_findings
    assert all(item["evidence_level"] == "suspicion" for item in hunter_findings)
    assert all(item["evidence_level"] != "static_corroboration" for item in hunter_findings)
    assert complexity_map["heuristic_only"] is False
    assert manifest["complexity"]["heuristic_only"] is False
    assert not any(entry.get("reason") == "hunter_model_unavailable" for entry in manifest.get("degradations", []))


def test_dump_only_hunter_client_emits_no_hunter_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast import cli, tool_hunter
    from openultrasast.cli import main

    repo = _standard_repo(tmp_path)
    config = _write_hunter_config(tmp_path)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_HUNTER_CLIENT", "dump-only")
    monkeypatch.setattr(cli, "has_harnessx", lambda: False)
    docker_argv = _guard_docker(monkeypatch)
    hunter_calls: list[int] = []
    real_hunter = tool_hunter.run_tool_hunter

    def wrapped(*args: object, **kwargs: object) -> object:
        hunter_calls.append(1)
        return real_hunter(*args, **kwargs)

    monkeypatch.setattr(tool_hunter, "run_tool_hunter", wrapped)

    assert main(["scan", str(repo), "--mode", "standard", "--config", str(config)]) == 0

    run_dir = _latest_run(repo)
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    complexity_map = json.loads((run_dir / "complexity_map.json").read_text())
    hunter_findings = [item for item in findings if str(item["finding_id"]).startswith("tool-hunter:")]

    assert hunter_calls, "dump-only still runs the tool hunter loop"
    assert docker_argv == []
    assert hunter_findings == []
    assert complexity_map["heuristic_only"] is False


def test_resolve_hunter_client_scripted_and_dump_only_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast import tool_hunter

    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("OPENULTRASAST_HUNTER_CLIENT", "scripted")
    scripted = tool_hunter.resolve_hunter_client()
    assert scripted is not None
    assert type(scripted).__name__ == "ScriptedChatClient"

    monkeypatch.setenv("OPENULTRASAST_HUNTER_CLIENT", "dump-only")
    dump_only = tool_hunter.resolve_hunter_client()
    assert dump_only is not None
    assert type(dump_only).__name__ == "ScriptedChatClient"
    assert dump_only is not scripted

    monkeypatch.delenv("OPENULTRASAST_HUNTER_CLIENT", raising=False)
    assert tool_hunter.resolve_hunter_client() is None

    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    live = tool_hunter.resolve_hunter_client()
    assert isinstance(live, OpenRouterHunterClient)


def test_openrouter_hunter_client_maps_tool_calls_without_network() -> None:
    class _Inner:
        def complete_chat(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["model"] == "test-hunter"
            assert kwargs["tools"]
            return {
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_grep",
                        "type": "function",
                        "function": {"name": "grep_repo", "arguments": '{"pattern": "eval", "max_matches": 4}'},
                    }
                ],
            }

    client = OpenRouterHunterClient(_Inner())  # type: ignore[arg-type]
    response = client.complete(model="test-hunter", messages=[], tools=[{"type": "function"}], timeout_seconds=5)

    assert response.content is None
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].name == "grep_repo"
    assert response.tool_calls[0].arguments == {"pattern": "eval", "max_matches": 4}
