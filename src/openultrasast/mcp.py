"""Narrow MCP server for OpenCode integration (Phase 12).

Exposes only stable, project-level operations over MCP stdio (newline-delimited
JSON-RPC 2.0), implemented with the standard library only. No tool exposes arbitrary
shell, Docker, or internal hunter tools — those stay inside controlled harness stages.
The pure :meth:`McpServer.handle` dispatch is separated from the :func:`serve` stdio
loop so the surface is unit-testable without a live client.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, cast

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "openultrasast"


def _server_version() -> str:
    try:
        from importlib.metadata import version

        return version("openultrasast")
    except Exception:  # noqa: BLE001 — version metadata is best-effort
        return "0"


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], dict[str, Any]]

    def descriptor(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "inputSchema": self.input_schema}


class McpToolError(ValueError):
    """Raised by a tool handler when its inputs are invalid or the artifact is missing."""


# ---- tool handlers (each maps to one bounded project operation) --------------


def _require(args: dict[str, Any], key: str) -> Any:
    if key not in args or args[key] in (None, ""):
        raise McpToolError(f"missing required argument: {key}")
    return args[key]


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise McpToolError(f"artifact not found: {path}")
    return cast(dict[str, Any], json.loads(path.read_text()))


def _scan(args: dict[str, Any]) -> dict[str, Any]:
    from .cli import _run_scan  # lazy: avoids an import cycle with the CLI dispatcher

    path = Path(_require(args, "path"))
    mode = str(args.get("mode", "quick"))
    if mode not in ("quick", "standard"):
        raise McpToolError(f"unsupported mode: {mode} (use quick or standard; deep is not exposed via MCP)")
    fail_on = str(args.get("fail_on", "never"))
    config = Path(str(args.get("config", "openultrasast.toml")))
    outcome = _run_scan(path, config, mode, fail_on)
    return {
        "scan_id": outcome.scan_id,
        "run_dir": str(outcome.run_dir),
        "mode": mode,
        "finding_count": outcome.finding_count,
        "exit_code": outcome.exit_code,
    }


def _status(args: dict[str, Any]) -> dict[str, Any]:
    manifest = _read_json(Path(_require(args, "run_dir")) / "manifest.json")
    return {
        "scan_id": manifest.get("scan_id"),
        "target": manifest.get("target"),
        "finding_count": len(manifest.get("findings", [])),
        "score": (manifest.get("score") or {}).get("project_score"),
        "gate_passed": (manifest.get("score") or {}).get("gate", {}).get("passed"),
        "degradations": manifest.get("degradations", []),
        "fusion": manifest.get("fusion", []),
    }


def _findings(args: dict[str, Any]) -> dict[str, Any]:
    payload = _read_json(Path(_require(args, "run_dir")) / "findings.json")
    items = [
        {
            "finding_id": finding["finding_id"],
            "path": finding["path"],
            "line": finding.get("line"),
            "severity": finding["severity"],
            "title": finding["title"],
        }
        for finding in payload.get("findings", [])
    ]
    return {"findings": items, "count": len(items)}


def _load_finding(run_dir: Path, finding_id: str) -> dict[str, Any]:
    for finding in _read_json(run_dir / "findings.json").get("findings", []):
        if finding["finding_id"] == finding_id:
            return cast(dict[str, Any], finding)
    raise McpToolError(f"finding not found: {finding_id}")


def _get_finding(args: dict[str, Any]) -> dict[str, Any]:
    run_dir = Path(_require(args, "run_dir"))
    return _load_finding(run_dir, str(_require(args, "finding_id")))


def _load_verification(run_dir: Path, finding_id: str) -> dict[str, Any] | None:
    path = run_dir / "verification.json"
    if not path.exists():
        return None
    for result in _read_json(path).get("verifications", []):
        if result["finding_id"] == finding_id:
            return cast(dict[str, Any], result)
    return None


def _evidence(args: dict[str, Any]) -> dict[str, Any]:
    run_dir = Path(_require(args, "run_dir"))
    finding_id = str(_require(args, "finding_id"))
    finding = _load_finding(run_dir, finding_id)
    return {
        "finding_id": finding_id,
        "evidence_level": finding.get("evidence_level"),
        "reachability_status": finding.get("reachability_status"),
        "reachability_evidence": finding.get("reachability_evidence", []),
        "reachability_conditions": finding.get("reachability_conditions", []),
        "verification": _load_verification(run_dir, finding_id),
    }


def _artifacts(args: dict[str, Any]) -> dict[str, Any]:
    manifest = _read_json(Path(_require(args, "run_dir")) / "manifest.json")
    return {"artifacts": manifest.get("artifacts", {})}


def _benchmark(args: dict[str, Any]) -> dict[str, Any]:
    from .benchmark import create_benchmark_run, evaluate_benchmark, load_benchmark_manifest, load_findings, resolve_benchmark_source
    from .cli import _run_scan

    manifest_path = Path(_require(args, "manifest"))
    if not manifest_path.is_file():
        raise McpToolError(f"benchmark manifest is not a file: {manifest_path}")
    mode = str(args.get("mode", "quick"))
    manifest = load_benchmark_manifest(manifest_path)
    target = resolve_benchmark_source(manifest_path, manifest)
    run = create_benchmark_run(target, manifest)
    outcome = _run_scan(target, Path(str(args.get("config", "openultrasast.toml"))), mode, "never")
    result = evaluate_benchmark(
        run=run, mode=mode, findings=load_findings(outcome.run_dir / "findings.json"), scan_id=outcome.scan_id, scan_run_dir=outcome.run_dir
    )
    metrics = result.metrics
    return {
        "benchmark_run_id": run.benchmark_run_id,
        "expected": metrics.expected_findings_total,
        "matched": metrics.matched_findings_total,
        "missed": metrics.missed_findings_total,
        "false_positives": metrics.false_positive_findings_total,
        "recall": metrics.recall,
    }


def _explain(args: dict[str, Any]) -> dict[str, Any]:
    run_dir = Path(_require(args, "run_dir"))
    finding_id = str(_require(args, "finding_id"))
    finding = _load_finding(run_dir, finding_id)
    verification = _load_verification(run_dir, finding_id)
    fusion_path = run_dir / "fusion.json"
    fusion = None
    if fusion_path.exists():
        fusion = next((decision for decision in _read_json_list(fusion_path) if decision["finding_id"] == finding_id), None)
    return {
        "finding_id": finding_id,
        "title": finding["title"],
        "severity": finding["severity"],
        "rationale": finding.get("rationale"),
        "reachability_status": finding.get("reachability_status"),
        "verification_status": verification["status"] if verification else "not_run",
        "pro_case": verification["pro_case"] if verification else None,
        "counter_case": verification["counter_case"] if verification else None,
        "fusion_disposition": fusion["disposition"] if fusion else None,
    }


def _read_json_list(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else []


def _propose_patch(args: dict[str, Any]) -> dict[str, Any]:
    _require(args, "run_dir")
    _require(args, "finding_id")
    # The patch oracle (sandboxed fix authoring + validation) is a later phase and is
    # intentionally not exposed over MCP yet. Degrade visibly rather than silently.
    return {
        "status": "not_implemented",
        "reason": "the patch oracle is a later phase; patch proposal is not exposed via MCP yet",
    }


def _export_report(args: dict[str, Any]) -> dict[str, Any]:
    run_dir = Path(_require(args, "run_dir"))
    fmt = str(args.get("format", "markdown"))
    filename = {"markdown": "report.md", "sarif": "report.sarif"}.get(fmt)
    if filename is None:
        raise McpToolError(f"unsupported report format: {fmt} (use markdown or sarif)")
    path = run_dir / filename
    if not path.exists():
        raise McpToolError(f"report artifact not found: {path}")
    return {"format": fmt, "path": str(path), "content": path.read_text()}


def _build_tools() -> list[Tool]:
    run_dir_schema = {"run_dir": {"type": "string", "description": "scan run directory (from scan.run_dir)"}}
    finding_schema = {**run_dir_schema, "finding_id": {"type": "string"}}
    return [
        Tool(
            "openultrasast.scan",
            "Run a bounded scan on a local path (quick or standard mode). Never executes arbitrary shell.",
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "mode": {"type": "string", "enum": ["quick", "standard"]},
                    "fail_on": {"type": "string", "enum": ["never", "findings", "verified"]},
                    "config": {"type": "string"},
                },
                "required": ["path"],
            },
            _scan,
        ),
        Tool("openultrasast.status", "Summarize a scan's status from its manifest.", _obj(run_dir_schema, ["run_dir"]), _status),
        Tool("openultrasast.findings", "List the findings of a completed scan.", _obj(run_dir_schema, ["run_dir"]), _findings),
        Tool("openultrasast.get_finding", "Return one finding by id.", _obj(finding_schema, ["run_dir", "finding_id"]), _get_finding),
        Tool(
            "openultrasast.evidence",
            "Return reachability and verification evidence for a finding.",
            _obj(finding_schema, ["run_dir", "finding_id"]),
            _evidence,
        ),
        Tool("openultrasast.artifacts", "List a scan's artifact paths.", _obj(run_dir_schema, ["run_dir"]), _artifacts),
        Tool(
            "openultrasast.benchmark",
            "Run a benchmark manifest and return recall/precision metrics.",
            {
                "type": "object",
                "properties": {"manifest": {"type": "string"}, "mode": {"type": "string"}, "config": {"type": "string"}},
                "required": ["manifest"],
            },
            _benchmark,
        ),
        Tool(
            "openultrasast.explain",
            "Explain a finding (rationale, reachability, verification, fusion).",
            _obj(finding_schema, ["run_dir", "finding_id"]),
            _explain,
        ),
        Tool(
            "openultrasast.propose_patch",
            "Propose a patch for a finding (patch oracle; not yet implemented).",
            _obj(finding_schema, ["run_dir", "finding_id"]),
            _propose_patch,
        ),
        Tool(
            "openultrasast.export_report",
            "Export a scan report as markdown or sarif.",
            {
                "type": "object",
                "properties": {"run_dir": {"type": "string"}, "format": {"type": "string", "enum": ["markdown", "sarif"]}},
                "required": ["run_dir"],
            },
            _export_report,
        ),
    ]


def _obj(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required}


class McpServer:
    """Minimal MCP server: pure request dispatch over a narrow, fixed tool surface."""

    def __init__(self) -> None:
        self._tools = {tool.name: tool for tool in _build_tools()}

    @property
    def tool_names(self) -> list[str]:
        return sorted(self._tools)

    def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Dispatch one JSON-RPC request; returns the response, or None for notifications."""
        method = request.get("method")
        request_id = request.get("id")
        if request_id is None:  # a notification (e.g. notifications/initialized) — no response
            return None
        try:
            result = self._dispatch(method, request.get("params") or {})
        except McpToolError as exc:
            return _error(request_id, -32602, str(exc))
        except Exception as exc:  # noqa: BLE001 — surface as a JSON-RPC error, never crash the loop
            return _error(request_id, -32603, f"{type(exc).__name__}: {exc}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _dispatch(self, method: str | None, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": _server_version()},
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [tool.descriptor() for tool in self._tools.values()]}
        if method == "tools/call":
            return self._call_tool(params)
        raise McpToolError(f"unknown method: {method}")

    def _call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        tool = self._tools.get(str(name))
        if tool is None:
            raise McpToolError(f"unknown tool: {name}")
        arguments = params.get("arguments") or {}
        try:
            result = tool.handler(arguments)
        except McpToolError as exc:
            return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
        return {"content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}], "isError": False}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def serve(stdin: IO[str] | None = None, stdout: IO[str] | None = None) -> int:
    """Run the MCP stdio loop (newline-delimited JSON-RPC) until EOF."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    server = McpServer()
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        response = server.handle(request)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
    return 0


__all__ = ["McpServer", "McpToolError", "Tool", "serve"]
