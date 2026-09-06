"""learning-harness task 2.7: canary templates and the second judge (offline)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.config import SandboxConfig
from openultrasast.findings import StaticFinding
from openultrasast.learning.families import load_families
from openultrasast.regress.safety import check_snippet_safety
from openultrasast.sandbox import SandboxResult
from openultrasast.sandbox.runner import FakeSandboxRunner
from openultrasast.tool_hunter import ChatResponse, ScriptedChatClient

CANARY_FAMILIES = ("injection", "path", "deserialization")


def _claim(family: str, function: str = "lookup", line: int = 3) -> StaticFinding:
    return StaticFinding(
        finding_id=f"detector:app.py:{line}",
        path="app.py",
        title="t",
        severity="high",
        confidence="low",
        evidence_level="suspicion",
        rationale="r",
        line=line,
        function_name=function,
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=[f"family:{family}"],
        ranking_priority=0.0,
    )


def test_every_canary_template_renders_and_passes_the_snippet_safety_check() -> None:
    from openultrasast.learning.canaries import render_canary

    for family in CANARY_FAMILIES:
        snippet, token = render_canary(family, language="python", path="app.py", function="lookup")
        assert token and token in snippet
        check_snippet_safety(snippet)  # raises when the template would be refused before it ever runs
        assert "/workspace" in snippet  # the candidate is imported from the read-only source mount
    assert render_canary("memory", language="python", path="app.py", function="f") is None
    assert render_canary("injection", language="rust", path="a.rs", function="f") is None


def test_a_canary_token_is_unique_to_the_experiment_it_names() -> None:
    from openultrasast.learning.canaries import render_canary

    first = render_canary("injection", language="python", path="app.py", function="lookup")
    second = render_canary("injection", language="python", path="app.py", function="other")
    third = render_canary("path", language="python", path="app.py", function="lookup")
    assert first and second and third
    assert first[1] != second[1] != third[1] and first[1] != third[1]
    # the same family, file and function is the same experiment, so it is deliberately the same token
    assert render_canary("injection", language="python", path="app.py", function="lookup")[1] == first[1]  # type: ignore[index]


def test_the_canary_verifier_proves_only_when_the_oracle_fires(tmp_path: Path) -> None:
    from openultrasast.learning.canaries import CanaryVerifier

    (tmp_path / "app.py").write_text("def lookup(value):\n    return value\n")
    fired = CanaryVerifier(runner=_runner(lambda token: SandboxResult(0, f"CANARY {token}", "", False)), limits=SandboxConfig())
    proven = fired.verify(_claim("injection"), root=tmp_path, language="python")
    assert proven.rung == "proven" and proven.reason == "oracle_fired"
    quiet = CanaryVerifier(runner=_runner(lambda _t: SandboxResult(1, "boom", "Traceback", False)), limits=SandboxConfig())
    unproven = quiet.verify(_claim("injection"), root=tmp_path, language="python")
    assert unproven.rung == "suspicion" and unproven.reason == "oracle_quiet"  # a crash is not this family's evidence


def test_a_family_or_language_with_no_template_stays_at_suspicion(tmp_path: Path) -> None:
    from openultrasast.learning.canaries import CanaryVerifier

    (tmp_path / "app.py").write_text("def lookup(value):\n    return value\n")
    verifier = CanaryVerifier(runner=_runner(lambda token: SandboxResult(0, token, "", False)), limits=SandboxConfig())
    assert verifier.verify(_claim("memory"), root=tmp_path, language="python").reason == "no_template"
    assert verifier.verify(_claim("injection"), root=tmp_path, language="rust").reason == "no_template"


def test_the_registry_uses_the_canary_verifier_when_one_is_supplied(tmp_path: Path) -> None:
    from openultrasast.learning.canaries import CanaryVerifier
    from openultrasast.learning.verifiers import NoVerifier, verifier_for

    taxonomy = load_families()
    canary = CanaryVerifier(runner=_runner(lambda token: SandboxResult(0, token, "", False)), limits=SandboxConfig())
    assert verifier_for(taxonomy.by_id("injection"), canary=canary) is canary
    assert isinstance(verifier_for(taxonomy.by_id("access_control"), canary=canary), type(verifier_for(taxonomy.by_id("access_control"))))
    assert isinstance(verifier_for(taxonomy.by_id("memory"), canary=canary), NoVerifier)


def test_nothing_is_published_as_proven_until_a_second_judge_confirms() -> None:
    from openultrasast.learning.canaries import confirm_proven
    from openultrasast.learning.verifiers import Verification

    proven = Verification(rung="proven", reason="oracle_fired", oracle_output="CANARY abc")
    agrees = ScriptedChatClient([ChatResponse(content=json.dumps({"confirms": True, "reason": "the row came back"}))])
    kept = confirm_proven(proven, _claim("injection"), client=agrees, model="judge", snippet="print('x')")
    assert kept.rung == "proven"
    declines = ScriptedChatClient([ChatResponse(content=json.dumps({"confirms": False, "reason": "unrelated output"}))])
    dropped = confirm_proven(proven, _claim("injection"), client=declines, model="judge", snippet="print('x')")
    assert dropped.rung == "static_corroboration" and dropped.reason == "judge_declined"
    assert confirm_proven(proven, _claim("injection"), client=None, model="", snippet="x").rung == "static_corroboration"
    lower = Verification(rung="suspicion", reason="oracle_quiet")
    assert confirm_proven(lower, _claim("injection"), client=agrees, model="judge", snippet="x") is lower  # nothing to confirm


def test_the_judge_sees_the_snippet_and_the_oracle_output_and_never_the_label() -> None:
    from openultrasast.learning.canaries import confirm_proven
    from openultrasast.learning.verifiers import Verification

    client = ScriptedChatClient([ChatResponse(content=json.dumps({"confirms": True, "reason": "ok"}))])
    confirm_proven(
        Verification(rung="proven", reason="oracle_fired", oracle_output="CANARY abc"),
        _claim("injection"),
        client=client,
        model="judge",
        snippet="print('CANARY abc')",
    )
    prompt = json.dumps(client.calls[0]["messages"])
    assert "CANARY abc" in prompt and "print('CANARY abc')" in prompt
    assert client.calls[0].get("json_object") is True and client.calls[0]["tools"] == []
    assert "family:injection" not in prompt  # the judge is told the claim, not the answer key


def test_templates_and_oracle_code_live_outside_every_proposer_write_root(tmp_path: Path) -> None:
    from openultrasast.learning import canaries
    from openultrasast.learning.detectors import write_default_configs

    write_roots = set(write_default_configs(tmp_path, load_families(), prompt="p", version="0").values())
    module = Path(canaries.__file__).resolve()
    assert not any(module.is_relative_to(root.resolve()) for root in write_roots)
    assert "site-packages" in str(module) or "src/openultrasast" in str(module)


def _runner(reply: object) -> FakeSandboxRunner:
    """A sandbox that answers from whatever canary token the snippet actually planted."""

    class _Runner(FakeSandboxRunner):  # type: ignore[misc]
        def run(self, spec: object) -> SandboxResult:
            body = "\n".join(str(value) for value in (getattr(spec, "scratch_files", {}) or {}).values())
            marker = next((word.strip("'\"") for word in body.split() if "ousast-canary-" in word), "ousast-canary-none")
            return reply(marker)  # type: ignore[operator]

    return _Runner()


VULNERABLE = {
    "injection": "import os\n\n\ndef lookup(value):\n    os.system(value)\n    return 'done'\n",
    "path": "def lookup(value):\n    with open(value, encoding='utf-8') as handle:\n        return handle.read()\n",
    "deserialization": "import pickle\n\n\ndef lookup(value):\n    return pickle.loads(value)\n",
}
FIXED = {
    "injection": (
        "import shlex, subprocess\n\n\ndef lookup(value):\n"
        "    subprocess.run(['echo', shlex.quote(value)], check=False)\n    return 'done'\n"
    ),
    "path": (
        "from pathlib import Path\n\n\ndef lookup(value):\n"
        "    name = Path(value).name\n    return (Path('/tmp') / name).read_text(encoding='utf-8') if False else ''\n"
    ),
    "deserialization": "import json\n\n\ndef lookup(value):\n    return json.loads(value.decode('utf-8', 'ignore') or '{}')\n",
}


@pytest.mark.parametrize("family", CANARY_FAMILIES)
def test_each_canary_fires_on_a_real_bug_and_stays_quiet_on_its_fixed_twin(tmp_path: Path, family: str) -> None:
    """The oracle must be a property of the code, not of the harness: run the snippet for real, both sides.

    The injection fixture's fixed twin deliberately echoes its input, which is why the payload carries a
    value unrelated to the oracle token: an echoing handler must not be able to satisfy the oracle.
    """
    import subprocess
    import sys

    from openultrasast.learning.canaries import render_canary

    for side, sources in (("vuln", VULNERABLE), ("fixed", FIXED)):
        workspace = tmp_path / side / "workspace"
        scratch = tmp_path / side / "scratch"
        workspace.mkdir(parents=True)
        scratch.mkdir(parents=True)
        (workspace / "app.py").write_text(sources[family])
        rendered = render_canary(
            family, language="python", path="app.py", function="lookup", workspace=str(workspace), scratch=str(scratch)
        )
        assert rendered is not None
        snippet, token = rendered
        script = scratch / "case.py"
        script.write_text(snippet)
        completed = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=60, check=False)
        fired = token in completed.stdout or token in completed.stderr
        assert fired is (side == "vuln"), f"{family} {side}: {completed.stdout!r} {completed.stderr!r}"
