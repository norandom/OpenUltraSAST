"""Canary snippets and the second judge (learning-harness, Req 7.2, 7.5).

A canary is how a family says "the vulnerability fired": a snippet plants a marker only the
vulnerability can reveal, and the token appearing in the sandbox output is the oracle. A row in an
in-memory database that only an unconstrained query returns, a file under the scratch mount that only
a traversal reaches, an object that only an unsafe load reconstructs. The token is derived from the
claim, so one family's oracle can never answer for another and one claim's canary can never answer for
the next.

Nothing reaches `proven` on a machine's say-so alone: a second, independent judgement reads the snippet
and what the sandbox printed and either confirms or drops the claim back to corroboration. Templates
and oracle code live in the package, outside every directory a round may write.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from ..config import SandboxConfig
from ..findings import StaticFinding
from ..regress.candidate import DEFAULT_IMAGES, RegressionRunner
from ..regress.verdict import TRIGGERABLE
from ..sandbox.runner import WORKSPACE_MOUNT, SandboxRunner
from ..tool_hunter import ChatClient
from .verifiers import Verification, VerifierKind, token_oracle

_TOKEN_PREFIX = "ousast-canary-"
_JUDGE_SYSTEM = (
    "You check one security claim against what a sandbox actually printed. "
    'Answer with JSON only: {"confirms": true|false, "reason": "<one sentence>"}. '
    "Confirm only when the printed output can be explained by the claimed vulnerability and by nothing else."
)


def canary_token(family: str, path: str, function: str) -> str:
    """A token unique to this claim, so an oracle can only be satisfied by its own canary."""
    digest = hashlib.sha256(f"{family}|{path}|{function}".encode()).hexdigest()[:12]
    return f"{_TOKEN_PREFIX}{digest}"


def render_canary(family: str, *, language: str, path: str, function: str) -> tuple[str, str] | None:
    """The snippet that plants this family's canary and the token that proves it fired, or None."""
    template = _TEMPLATES.get((family, language))
    if template is None:
        return None
    token = canary_token(family, path, function)
    module = path.replace("\\", "/")
    snippet = template.format(token=token, workspace=WORKSPACE_MOUNT, module=module, function=function)
    return snippet, token


@dataclass(frozen=True)
class CanaryVerifier:
    """Runs a family's canary in the sandbox and lets only its own token count as proof."""

    runner: SandboxRunner
    limits: SandboxConfig
    images: dict[str, str] | None = None
    kind: VerifierKind = "canary"

    def verify(self, claim: StaticFinding, *, root: Path, language: str) -> Verification:
        family = next((tag.split(":", 1)[1] for tag in claim.tags if tag.startswith("family:")), "")
        rendered = render_canary(family, language=language, path=claim.path, function=claim.function_name or "")
        if rendered is None:
            return Verification(rung="suspicion", reason="no_template")
        snippet, token = rendered
        images = self.images or dict(DEFAULT_IMAGES)
        verdict = RegressionRunner(self.runner).run_recipe(
            language, snippet, images.get(language, "ousast-missing-image"), self.limits, repo_root=root, oracle=token_oracle(token)
        )
        if verdict.verdict == TRIGGERABLE:
            return Verification(rung="proven", reason="oracle_fired", oracle_output=token)
        return Verification(rung="suspicion", reason="oracle_quiet" if verdict.reason == "oracle_quiet" else verdict.reason)


def confirm_proven(
    verification: Verification, claim: StaticFinding, *, client: ChatClient | None, model: str, snippet: str
) -> Verification:
    """Req 7.5: a claim is published as proven only when a second, independent judgement agrees."""
    if verification.rung != "proven":
        return verification
    if client is None or not model:
        return Verification(rung="static_corroboration", reason="judge_unavailable", oracle_output=verification.oracle_output)
    question = (
        f"Claim: {claim.title}. {claim.rationale[:400]}\n"
        f"Location: {claim.path} line {claim.line}, function {claim.function_name}.\n\n"
        f"Snippet that was run:\n{snippet}\n\nWhat the sandbox printed:\n{verification.oracle_output}\n\n"
        "Does that output demonstrate the claim? Answer as JSON."
    )
    messages: list[dict[str, object]] = [{"role": "system", "content": _JUDGE_SYSTEM}, {"role": "user", "content": question}]
    try:
        response = client.complete(model=model, messages=messages, tools=[], json_object=True)  # type: ignore[call-arg]
    except TypeError:
        response = client.complete(model=model, messages=messages, tools=[])
    except Exception:  # noqa: BLE001 — a judge that cannot answer must not promote a claim
        return Verification(rung="static_corroboration", reason="judge_unavailable", oracle_output=verification.oracle_output)
    if _confirms(response.content):
        return verification
    return Verification(rung="static_corroboration", reason="judge_declined", oracle_output=verification.oracle_output)


def _confirms(content: str | None) -> bool:
    if not isinstance(content, str) or "{" not in content:
        return False
    try:
        payload = json.loads(content[content.index("{") : content.rindex("}") + 1])
    except (ValueError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict) and payload.get("confirms") is True


# Templates are data, not prose: each plants a marker only its own vulnerability can reveal, imports the
# candidate from the read-only source mount, and prints the token on that path alone. A snippet that
# cannot reach the function prints nothing, which is a suspicion, not a proof.
_PYTHON_INJECTION = """# canary: an unconstrained query returns a row the caller never asked for
import sqlite3, sys
sys.path.insert(0, {workspace!r})
CANARY = {token!r}
connection = sqlite3.connect(":memory:")
connection.execute("create table secrets (name text)")
connection.execute("insert into secrets values (?)", (CANARY,))
connection.commit()
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("candidate", {workspace!r} + "/" + {module!r})
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    handler = getattr(module, {function!r}, None)
    payload = "x' OR '1'='1"
    result = handler(payload) if callable(handler) else None
    if CANARY in str(result):
        print("CANARY", CANARY)
except Exception as error:
    print("canary could not reach the function:", type(error).__name__)
"""

_PYTHON_PATH = """# canary: a traversal reads a file the handler was never meant to open
import sys
sys.path.insert(0, {workspace!r})
CANARY = {token!r}
with open("/scratch/canary.txt", "w", encoding="utf-8") as handle:
    handle.write(CANARY)
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("candidate", {workspace!r} + "/" + {module!r})
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    handler = getattr(module, {function!r}, None)
    result = handler("../../scratch/canary.txt") if callable(handler) else None
    if CANARY in str(result):
        print("CANARY", CANARY)
except Exception as error:
    print("canary could not reach the function:", type(error).__name__)
"""

_PYTHON_DESERIALIZATION = """# canary: an unsafe load reconstructs an object that announces itself
import pickle, sys
sys.path.insert(0, {workspace!r})
CANARY = {token!r}

class Marker:
    def __reduce__(self):
        return (print, ("CANARY", CANARY))

blob = pickle.dumps(Marker())
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("candidate", {workspace!r} + "/" + {module!r})
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    handler = getattr(module, {function!r}, None)
    if callable(handler):
        handler(blob)
except Exception as error:
    print("canary could not reach the function:", type(error).__name__)
"""

_TEMPLATES: dict[tuple[str, str], str] = {
    ("injection", "python"): _PYTHON_INJECTION,
    ("path", "python"): _PYTHON_PATH,
    ("deserialization", "python"): _PYTHON_DESERIALIZATION,
}


__all__ = ["CanaryVerifier", "canary_token", "confirm_proven", "render_canary"]
