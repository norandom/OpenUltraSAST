"""Bounded tool-using hunter over map hotspots. Findings are suspicion only."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .complexity.map import Hotspot
from .findings import StaticFinding
from .hunter_tools import PathEscapesRepo, clamp_repo_path, find_refs, grep_repo, read_file
from .provider.openrouter import OpenRouterChatClient, OpenRouterError

_DEFAULT_MAX_CHARS = 4000
_DEFAULT_MAX_MATCHES = 50
DEFAULT_MAX_STEPS = 4
CLIENT_ENV = "OPENULTRASAST_HUNTER_CLIENT"
_FINDING_ID_PREFIX = "tool-hunter:"
_HUNTER_TOOL_NAMES = frozenset({"read_file", "grep_repo", "find_refs"})
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_SCRIPTED_FLAGS = frozenset({"scripted", "script"})
_DUMP_FLAGS = frozenset({"dump", "dump-only"})
_UNSAFE_FLAGS = frozenset({"unsafe", "unsafe-snippet"})
_OPENROUTER_FLAGS = frozenset({"openrouter", "live"})
_UNSAFE_SNIPPET = 'client = docker.DockerClient(base_url="unix://var/run/docker.sock")\n'
_SCRIPTED_FINDINGS = [
    {
        "path": "app.py",
        "line": 3,
        "title": "Dynamic execution of attacker-controlled data",
        "rationale": "eval/execute follows request input across the hotspot.",
        "evidence_level": "static_corroboration",
    }
]

HUNTER_TOOLS: list[dict[str, object]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file inside the scanned repository root.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relative to the repository root."},
                    "max_chars": {"type": "integer"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep_repo",
            "description": "Search repository source text with a Python regular expression.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "max_matches": {"type": "integer"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_refs",
            "description": "List references to a symbol inside the scanned repository.",
            "parameters": {
                "type": "object",
                "properties": {"symbol": {"type": "string"}},
                "required": ["symbol"],
            },
        },
    },
]

_SYSTEM_PROMPT = (
    "You are a tool-using security hunter. Tools: read_file, grep_repo, find_refs. "
    "Stay inside the scanned repository. Use a tool before concluding. "
    "After using tools, reply with a JSON array of objects with path, line, title, and rationale. "
    "These findings are suspicions, not static corroboration."
)


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, object]


@dataclass(frozen=True)
class ChatResponse:
    content: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()


class ChatClient(Protocol):
    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, object]],
        tools: list[dict[str, object]],
        timeout_seconds: int = 60,
    ) -> ChatResponse:
        raise NotImplementedError


class ScriptedChatClient:
    """Deterministic ChatClient for tests and OPENULTRASAST_HUNTER_CLIENT injection."""

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


class OpenRouterHunterClient:
    """Adapt OpenRouterChatClient to the tool-hunter ChatClient protocol."""

    def __init__(self, client: OpenRouterChatClient) -> None:
        self._client = client

    @classmethod
    def from_env(cls) -> OpenRouterHunterClient:
        return cls(OpenRouterChatClient.from_env())

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, object]],
        tools: list[dict[str, object]],
        timeout_seconds: int = 60,
    ) -> ChatResponse:
        message = self._client.complete_chat(model=model, messages=messages, tools=tools, timeout_seconds=timeout_seconds)
        return chat_response_from_message(message)


def scripted_hunter_client(mode: str = "scripted") -> ScriptedChatClient:
    grep_turn = ChatResponse(
        tool_calls=(ToolCall(id="call_grep", name="grep_repo", arguments={"pattern": "eval|execute|query", "max_matches": 10}),)
    )
    if mode in _DUMP_FLAGS:
        return ScriptedChatClient([ChatResponse(content=json.dumps(_SCRIPTED_FINDINGS))])
    if mode in _UNSAFE_FLAGS:
        payload = [{**_SCRIPTED_FINDINGS[0], "snippet": _UNSAFE_SNIPPET}]
        return ScriptedChatClient([grep_turn, ChatResponse(content=json.dumps(payload))])
    return ScriptedChatClient([grep_turn, ChatResponse(content=json.dumps(_SCRIPTED_FINDINGS))])


def resolve_hunter_client() -> ChatClient | None:
    """Return a hunter client from env, or OpenRouter when an API key is present."""
    flag = os.environ.get(CLIENT_ENV, "").strip().lower()
    if flag in _SCRIPTED_FLAGS:
        return scripted_hunter_client("scripted")
    if flag in _DUMP_FLAGS:
        return scripted_hunter_client("dump-only")
    if flag in _UNSAFE_FLAGS:
        return scripted_hunter_client("unsafe-snippet")
    if flag in _OPENROUTER_FLAGS or (not flag and os.environ.get("OPENROUTER_API_KEY")):
        try:
            return OpenRouterHunterClient.from_env()
        except OpenRouterError:
            return None
    return None


def chat_response_from_message(message: Mapping[str, object]) -> ChatResponse:
    content = message.get("content")
    text = content if isinstance(content, str) else None
    raw_calls = message.get("tool_calls") or ()
    calls: list[ToolCall] = []
    if isinstance(raw_calls, Sequence) and not isinstance(raw_calls, str | bytes):
        for index, item in enumerate(raw_calls):
            parsed = _tool_call_from_openrouter(item, index)
            if parsed is not None:
                calls.append(parsed)
    return ChatResponse(content=text, tool_calls=tuple(calls))


def _tool_call_from_openrouter(item: object, index: int) -> ToolCall | None:
    if not isinstance(item, Mapping):
        return None
    function = item.get("function")
    if not isinstance(function, Mapping):
        return None
    name = function.get("name")
    if not isinstance(name, str) or not name:
        return None
    call_id = item.get("id")
    identifier = call_id if isinstance(call_id, str) and call_id else f"call_{index}"
    arguments = function.get("arguments", {})
    if isinstance(arguments, str):
        try:
            loaded = json.loads(arguments)
        except json.JSONDecodeError:
            loaded = {}
        parsed_args = loaded if isinstance(loaded, dict) else {}
    elif isinstance(arguments, Mapping):
        parsed_args = dict(arguments)
    else:
        parsed_args = {}
    return ToolCall(id=identifier, name=name, arguments=parsed_args)


def run_tool_hunter(
    root: Path,
    hotspots: list[Hotspot],
    *,
    client: ChatClient,
    model: str,
    max_steps: int,
) -> list[StaticFinding]:
    if max_steps <= 0:
        return []
    messages: list[dict[str, object]] = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": _hotspot_prompt(hotspots)},
    ]
    used_tools = False
    for _step in range(max_steps):
        response = client.complete(model=model, messages=messages, tools=HUNTER_TOOLS)
        tool_calls = tuple(response.tool_calls or ())
        if tool_calls:
            messages.append(_assistant_tool_message(response.content, tool_calls))
            for call in tool_calls:
                if call.name in _HUNTER_TOOL_NAMES:
                    used_tools = True
                messages.append(_tool_result_message(root, call))
            continue
        content = response.content or ""
        if not content.strip() or not used_tools:
            # A findings dump is not evidence unless the loop invoked a repo tool.
            return []
        return _findings_from_content(root, hotspots, content)
    return []


def _hotspot_prompt(hotspots: Sequence[Hotspot]) -> str:
    payload = [
        {
            "path": hotspot.path,
            "function_name": hotspot.function_name,
            "score": hotspot.score,
            "band": hotspot.band,
            "rationale": hotspot.rationale,
        }
        for hotspot in hotspots
    ]
    return (
        "Inspect these complexity-map hotspots with the repository tools. "
        "Return JSON findings only after using a tool.\n"
        f"{json.dumps(payload, sort_keys=True)}"
    )


def _assistant_tool_message(content: str | None, tool_calls: Sequence[ToolCall]) -> dict[str, object]:
    return {
        "role": "assistant",
        "content": content,
        "tool_calls": [
            {
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.name,
                    "arguments": json.dumps(call.arguments, sort_keys=True) if not isinstance(call.arguments, str) else call.arguments,
                },
            }
            for call in tool_calls
        ],
    }


def _tool_result_message(root: Path, call: ToolCall) -> dict[str, object]:
    return {
        "role": "tool",
        "tool_call_id": call.id,
        "name": call.name,
        "content": _run_tool(root, call),
    }


def _run_tool(root: Path, call: ToolCall) -> str:
    try:
        payload = _dispatch_tool(root, call.name, _arguments(call.arguments))
    except Exception as exc:  # noqa: BLE001 — tool failures stay in-band so the scan continues
        payload = {"error": f"{type(exc).__name__}: {exc}"}
    return json.dumps(payload, sort_keys=True)


def _dispatch_tool(root: Path, name: str, arguments: Mapping[str, object]) -> object:
    if name == "read_file":
        path = _require_str(arguments, "path")
        max_chars = _optional_int(arguments, "max_chars", _DEFAULT_MAX_CHARS)
        return {"path": path, "content": read_file(root, path, max_chars=max_chars)}
    if name == "grep_repo":
        pattern = _require_str(arguments, "pattern")
        max_matches = _optional_int(arguments, "max_matches", _DEFAULT_MAX_MATCHES)
        return grep_repo(root, pattern, max_matches=max_matches)
    if name == "find_refs":
        symbol = _require_str(arguments, "symbol")
        return find_refs(root, symbol, None)
    raise ValueError(f"unknown tool: {name}")


def _arguments(raw: object) -> dict[str, object]:
    if isinstance(raw, str):
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        raise ValueError("tool arguments must be a JSON object")
    if isinstance(raw, Mapping):
        return dict(raw)
    raise ValueError("tool arguments must be an object")


def _require_str(arguments: Mapping[str, object], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} is required")
    return value


def _optional_int(arguments: Mapping[str, object], key: str, default: int) -> int:
    value = arguments.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value


def _findings_from_content(root: Path, hotspots: Sequence[Hotspot], content: str) -> list[StaticFinding]:
    payload = _load_json(content)
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        items = payload["findings"]
    else:
        return []
    scores = {hotspot.path: hotspot.score for hotspot in hotspots}
    findings: list[StaticFinding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        finding = _finding_from_item(root, item, scores)
        if finding is not None:
            findings.append(finding)
    return sorted(findings, key=lambda item: item.finding_id)


def _load_json(content: str) -> object | None:
    stripped = content.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", stripped, flags=re.DOTALL)
    if fenced is not None:
        stripped = fenced.group(1).strip()
    try:
        parsed: object = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    return parsed


def _finding_from_item(root: Path, item: Mapping[str, object], scores: Mapping[str, float]) -> StaticFinding | None:
    raw_path = item.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        return None
    try:
        relative = _clamp_relative_path(root, raw_path)
    except PathEscapesRepo:
        return None
    line = item.get("line")
    line_no = line if isinstance(line, int) and not isinstance(line, bool) else None
    title = item.get("title")
    rationale = item.get("rationale")
    function_name = item.get("function_name")
    severity = item.get("severity")
    snippet = item.get("snippet")
    proposed_snippet = snippet if isinstance(snippet, str) and snippet else None
    return StaticFinding(
        finding_id=f"{_FINDING_ID_PREFIX}{relative}:{line_no if line_no is not None else 0}",
        path=relative,
        title=title if isinstance(title, str) and title else "tool hunter suspicion",
        severity=severity if isinstance(severity, str) and severity in _SEVERITIES else "medium",
        confidence="low",
        evidence_level="suspicion",
        rationale=rationale if isinstance(rationale, str) and rationale else "Reported by the tool-using hunter.",
        line=line_no,
        function_name=function_name if isinstance(function_name, str) and function_name else None,
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=["tool-hunter"],
        ranking_priority=float(scores.get(relative, 0.0)),
        proposed_snippet=proposed_snippet,
    )


def _clamp_relative_path(root: Path, user_path: str) -> str:
    resolved_root = root.resolve()
    return clamp_repo_path(resolved_root, user_path).relative_to(resolved_root).as_posix()
