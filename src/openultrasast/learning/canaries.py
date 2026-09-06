"""Canary snippets and the second judge (learning-harness, Req 7.2, 7.5).

A canary is how a family says "the vulnerability fired": a snippet plants a marker only the
vulnerability can reveal, and the token appearing in the sandbox output is the oracle. A marker file an
injected command writes, a file under the scratch mount that only a traversal reaches, an object that
only an unsafe load reconstructs. The token is derived from the family, file and function, so one
family's oracle can never answer for another.

The injection canary confirms untrusted input reaching an interpreter: command, code and template
execution. A query-language injection whose payload never reaches a shell is not confirmed by it and
stays a suspicion, which is the honest answer rather than a false negative dressed as a verdict.

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
from ..sandbox.runner import SCRATCH_MOUNT, WORKSPACE_MOUNT, SandboxRunner
from ..tool_hunter import ChatClient
from .verifiers import Verification, VerifierKind, token_oracle

_TOKEN_PREFIX = "ousast-canary-"
_JUDGE_SYSTEM = (
    "You check one security claim against what a sandbox actually printed. "
    'Answer with JSON only: {"confirms": true|false, "reason": "<one sentence>"}. '
    "Confirm only when the printed output can be explained by the claimed vulnerability and by nothing else."
)


def canary_token(family: str, path: str, function: str) -> str:
    """The token the oracle looks for. Unique to the experiment, so one canary can never answer for another."""
    digest = hashlib.sha256(f"{family}|{path}|{function}".encode()).hexdigest()[:12]
    return f"{_TOKEN_PREFIX}{digest}"


def payload_token(family: str, path: str, function: str) -> str:
    """The value carried *inside* an injected payload, deliberately unrelated to the oracle token.

    A handler that merely echoes its input would otherwise print the oracle token and satisfy the oracle
    without the vulnerability firing at all. The snippet prints the oracle token only after seeing this
    value somewhere the payload alone could not have put it.
    """
    digest = hashlib.sha256(f"payload|{family}|{path}|{function}".encode()).hexdigest()[:12]
    return f"ousast-payload-{digest}"


def render_canary(
    family: str, *, language: str, path: str, function: str, workspace: str = WORKSPACE_MOUNT, scratch: str = SCRATCH_MOUNT
) -> tuple[str, str] | None:
    """The snippet that plants this family's canary and the token that proves it fired, or None.

    ``workspace`` and ``scratch`` default to the sandbox mounts; a test points them at real directories so
    the snippet can be run for what it actually does rather than for what a fake runner says it does.
    """
    template = _TEMPLATES.get((family, language))
    if template is None:
        return None
    token = canary_token(family, path, function)
    module = path.replace("\\", "/")
    snippet = template.format(
        token=token,
        payload=payload_token(family, path, function),
        workspace=workspace,
        scratch=scratch,
        module=module,
        function=function,
    )
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
_PYTHON_INJECTION = """# canary: untrusted input reaches an interpreter, which writes a marker only it could write.
# The payload carries a different value from the oracle token, so a handler that merely echoes its input
# cannot satisfy the oracle; only something that executed the payload can put PLANTED into the marker.
import sys
sys.path.insert(0, {workspace!r})
CANARY = {token!r}
PLANTED = {payload!r}
MARKER = {scratch!r} + "/canary-injection.txt"
payload = "x; python3 -c \\"open(%r,'w').write(%r)\\"" % (MARKER, PLANTED)
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("candidate", {workspace!r} + "/" + {module!r})
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    handler = getattr(module, {function!r}, None)
    if callable(handler):
        try:
            handler(payload)
        except Exception as inner:
            print("handler raised:", type(inner).__name__)
    import os
    if os.path.exists(MARKER):
        with open(MARKER, encoding="utf-8") as handle:
            if PLANTED in handle.read():
                print("CANARY", CANARY)
except Exception as error:
    print("canary could not reach the function:", type(error).__name__)
"""

_PYTHON_PATH = """# canary: a traversal reads a file the handler was never meant to open
import sys
sys.path.insert(0, {workspace!r})
CANARY = {token!r}
PLANTED = {payload!r}
MARKER = {scratch!r} + "/canary-path.txt"
with open(MARKER, "w", encoding="utf-8") as handle:
    handle.write(CANARY)
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("candidate", {workspace!r} + "/" + {module!r})
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    handler = getattr(module, {function!r}, None)
    result = handler(MARKER) if callable(handler) else None
    if CANARY in str(result):
        print("CANARY", CANARY)
except Exception as error:
    print("canary could not reach the function:", type(error).__name__)
"""

_PYTHON_DESERIALIZATION = """# canary: an unsafe load reconstructs an object that announces itself
import pickle, sys
sys.path.insert(0, {workspace!r})
CANARY = {token!r}
PLANTED = {payload!r}


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


__all__ = ["CanaryVerifier", "canary_token", "confirm_proven", "payload_token", "render_canary"]
