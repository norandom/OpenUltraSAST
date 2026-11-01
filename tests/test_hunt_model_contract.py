"""Hunt-owned execution crosses the dependency-free core model boundary."""

from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path

import pytest
from test_core_model import _case, _digest

from openultrasast.core import model
from openultrasast.hunt.model_contract import (
    ExecutorModelOutput,
    execute_model_contract,
    model_executor_input,
)


def _output(result: model.ModelResult) -> ExecutorModelOutput:
    identity = result.identity
    return ExecutorModelOutput(
        request_digest=result.request_digest,
        packet_digest=result.packet_digest,
        provider=identity.provider,
        model=identity.model,
        program_digest=identity.program_digest,
        prompt_digest=identity.prompt_digest,
        configuration_digest=identity.configuration_digest,
        adapter_revision=identity.adapter_revision,
        status=result.status.value,
        normalized_fields=() if result.response is None else result.response.normalized_fields,
        inline_redacted_text=None if result.response is None else result.response.inline_redacted_text,
        artifact=None if result.response is None else result.response.artifact,
        redaction_policy_digest=None if result.response is None else result.response.redaction_policy_digest,
        family_decision=result.family_decision,
        decision_mapping_digest=result.decision_mapping_digest,
        failure_reason=result.failure_reason,
    )


@pytest.mark.parametrize("failed", [False, True])
def test_fake_executor_success_and_failure_cross_canonical_boundary(failed: bool) -> None:
    case = _case(failed=failed)
    seen = []

    def executor(value):
        seen.append(value)
        return _output(case.result)

    result = execute_model_contract(case.request, executor, case.resolver)

    assert seen == [model_executor_input(case.request)]
    assert result == case.result
    model.validate_model_result(case.request, result, case.resolver)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("request_digest", _digest("wrong-request"), "request"),
        ("packet_digest", _digest("wrong-packet"), "packet"),
        ("program_digest", _digest("wrong-program"), "program"),
        ("decision_mapping_digest", _digest("wrong-mapping"), "mapping"),
    ],
)
def test_executor_cannot_substitute_declared_result_identity(field: str, value: str, message: str) -> None:
    case = _case()
    output = replace(_output(case.result), **{field: value})

    with pytest.raises(model.ModelContractError, match=message):
        execute_model_contract(case.request, lambda _: output, case.resolver)


def test_failure_shape_and_success_decision_are_core_validated() -> None:
    case = _case()
    failure = replace(
        _output(case.result),
        status="failed",
        family_decision=None,
        decision_mapping_digest=None,
        failure_reason=None,
    )
    with pytest.raises(model.ModelContractError, match="failure_reason"):
        execute_model_contract(case.request, lambda _: failure, case.resolver)

    forbidden = replace(_output(case.result), family_decision="not-declared")
    with pytest.raises(model.ModelContractError, match="allowed"):
        execute_model_contract(case.request, lambda _: forbidden, case.resolver)


def test_hunt_adapter_owns_no_provider_or_dspy_execution() -> None:
    import openultrasast.hunt.model_contract as adapter

    with open(adapter.__file__, encoding="utf-8") as source_file:
        source = source_file.read()
    assert "import dspy" not in source
    assert "litellm" not in source
    assert "openai" not in source


def test_core_import_census_has_no_model_runtime_dependency() -> None:
    core = Path(__file__).parents[1] / "src" / "openultrasast" / "core"
    forbidden = {"dspy", "litellm", "openai"}
    found = []
    for path in sorted(core.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name.split(".", 1)[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = {node.module.split(".", 1)[0]}
            else:
                continue
            if names & forbidden:
                found.append((path.name, node.lineno, tuple(sorted(names & forbidden))))
    assert found == []
