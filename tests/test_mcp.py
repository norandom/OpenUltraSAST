"""Narrow MCP server: tool listing, scan→status flow, and surface safety (Phase 12)."""

import io
import json
from pathlib import Path

from openultrasast.mcp import McpServer, serve

EXPECTED_TOOLS = {
    "openultrasast.scan",
    "openultrasast.status",
    "openultrasast.findings",
    "openultrasast.get_finding",
    "openultrasast.evidence",
    "openultrasast.artifacts",
    "openultrasast.benchmark",
    "openultrasast.explain",
    "openultrasast.propose_patch",
    "openultrasast.export_report",
}


def _call(server: McpServer, name: str, arguments: dict) -> dict:
    response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
    assert response is not None
    result = response["result"]
    payload = json.loads(result["content"][0]["text"]) if not result["isError"] else {"error": result["content"][0]["text"]}
    return {"isError": result["isError"], **payload}


# ---- protocol + tool listing ------------------------------------------------


def test_initialize_returns_server_info() -> None:
    server = McpServer()
    response = server.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
    assert response is not None
    assert response["result"]["serverInfo"]["name"] == "openultrasast"
    assert "protocolVersion" in response["result"]


def test_tools_list_is_exactly_the_narrow_surface() -> None:
    server = McpServer()
    response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    assert response is not None
    names = {tool["name"] for tool in response["result"]["tools"]}
    assert names == EXPECTED_TOOLS


def test_surface_exposes_no_shell_or_exec_tool() -> None:
    # The narrow surface must never expose arbitrary shell/exec/docker tools.
    server = McpServer()
    forbidden = ("shell", "exec", "command", "docker", "run_command", "bash")
    for name in server.tool_names:
        assert not any(token in name.lower() for token in forbidden), name
    for tool in McpServer()._tools.values():  # no tool accepts a free-form command argument
        assert "command" not in tool.input_schema.get("properties", {})


def test_notifications_get_no_response() -> None:
    server = McpServer()
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_unknown_method_returns_jsonrpc_error() -> None:
    server = McpServer()
    response = server.handle({"jsonrpc": "2.0", "id": 9, "method": "does/not/exist"})
    assert response is not None and response["error"]["code"] == -32602


# ---- scan -> status -> findings -> explain flow -----------------------------


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")
    return repo


def test_scan_then_status_and_findings(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(tmp_path / "runs"))
    server = McpServer()

    scan = _call(server, "openultrasast.scan", {"path": str(_repo(tmp_path)), "mode": "quick"})
    assert not scan["isError"] and scan["scan_id"]
    run_dir = scan["run_dir"]

    status = _call(server, "openultrasast.status", {"run_dir": run_dir})
    assert status["finding_count"] == scan["finding_count"]

    findings = _call(server, "openultrasast.findings", {"run_dir": run_dir})
    assert findings["count"] == scan["finding_count"]
    finding_id = findings["findings"][0]["finding_id"]

    explain = _call(server, "openultrasast.explain", {"run_dir": run_dir, "finding_id": finding_id})
    assert explain["finding_id"] == finding_id and explain["severity"]

    evidence = _call(server, "openultrasast.evidence", {"run_dir": run_dir, "finding_id": finding_id})
    assert "reachability_status" in evidence


def test_propose_patch_degrades_visibly(tmp_path: Path) -> None:
    server = McpServer()
    result = _call(server, "openultrasast.propose_patch", {"run_dir": str(tmp_path), "finding_id": "x"})
    assert result["status"] == "not_implemented"


def test_missing_required_argument_is_a_tool_error() -> None:
    server = McpServer()
    result = _call(server, "openultrasast.status", {})
    assert result["isError"] and "run_dir" in result["error"]


def test_export_report_returns_markdown(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(tmp_path / "runs"))
    server = McpServer()
    scan = _call(server, "openultrasast.scan", {"path": str(_repo(tmp_path)), "mode": "quick"})
    report = _call(server, "openultrasast.export_report", {"run_dir": scan["run_dir"], "format": "markdown"})
    assert report["format"] == "markdown" and report["content"]


# ---- stdio loop -------------------------------------------------------------


def test_serve_stdio_loop_handles_tools_list() -> None:
    stdin = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n")
    stdout = io.StringIO()
    assert serve(stdin, stdout) == 0
    response = json.loads(stdout.getvalue().strip())
    assert {tool["name"] for tool in response["result"]["tools"]} == EXPECTED_TOOLS
