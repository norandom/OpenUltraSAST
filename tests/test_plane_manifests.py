"""Manifest schemas of the service plane: ax's kinds load, a Run loads, and every violation names its field."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from openultrasast.plane.manifests import (
    ManifestError,
    Model,
    Run,
    Task,
    Workspace,
    check_run_tasks,
    load_manifests,
    parse_manifest,
)

TASK_YAML = """
apiVersion: ax.io/v1alpha1
kind: Task
metadata:
  name: verify
  namespace: sast
spec:
  image: openultrasast:dev
  command: ["verify", "--pass", "a"]
  env:
    - name: OUSAST_PASS
      value: "a"
  resources:
    requests: {cpu: "500m", memory: "1Gi"}
    limits: {cpu: "2", memory: "4Gi"}
  workspaces:
    - name: case-pin
      path: /workspace
      goal: the repository under test at its vulnerable pin
  debug: true
"""

WORKSPACE_YAML = """
apiVersion: ax.io/v1alpha1
kind: Workspace
metadata:
  name: flask-abc123
spec:
  git:
    - name: repo
      repo: https://github.com/pallets/flask.git
      branch: main
      commit: abc123
  files:
    - path: candidates.json
      content: '{"sinks": []}'
  mcp:
    registries: [https://registry.example/mcp]
    servers: [{name: fs}]
  skills:
    registries: [https://registry.example/skills]
    path: /skills
"""

MODEL_YAML = """
apiVersion: ax.io/v1alpha1
kind: Model
metadata:
  name: deepseek-flash
  annotations:
    openultrasast.io/provider-extension: "true"
spec:
  provider: deepseek
  model: deepseek-chat
  secretKey:
    name: deepseek-api
    key: token
  parameters:
    price_prompt_usd_per_m: 0.27
    price_completion_usd_per_m: 1.1
"""

RUN_YAML = """
apiVersion: openultrasast.io/v1alpha1
kind: Run
metadata:
  name: validation-46
spec:
  artifacts: ~/ousast-results/plane
  tasks:
    - name: repo-facts
      task: repo-facts
      outputs: [facts.json]
      serialize: engine
    - name: verify-a
      task: verify
      dependsOn: [repo-facts]
      inputs: {facts: repo-facts/facts.json}
      outputs: [units.jsonl]
      budget: {usd: 1.5, calls: 400}
    - name: verify-b
      task: verify
      dependsOn: [repo-facts]
      inputs: {facts: repo-facts/facts.json}
      outputs: [units.jsonl]
      budget: {usd: 1.5}
    - name: agree
      task: agree
      dependsOn: [verify-a, verify-b]
      inputs: {a: verify-a/units.jsonl, b: verify-b/units.jsonl}
      outputs: [agreed.json, disputed.json]
"""

TASK_STUB = """
apiVersion: ax.io/v1alpha1
kind: Task
metadata: {name: %s}
spec: {command: [%s]}
"""


def doc(text: str) -> dict[str, Any]:
    loaded = yaml.safe_load(text)
    assert isinstance(loaded, dict)
    return loaded


def rejected(document: object, field: str) -> str:
    """Parse and assert a ManifestError whose message names ``field``; return the message."""
    with pytest.raises(ManifestError) as info:
        parse_manifest(document)
    message = str(info.value)
    assert field in message, message
    return message


# --- valid manifests -----------------------------------------------------------------------------------------------


def test_task_loads_every_ax_field() -> None:
    task = parse_manifest(doc(TASK_YAML))
    assert isinstance(task, Task)
    assert task.metadata.name == "verify"
    assert task.metadata.namespace == "sast"
    assert task.image == "openultrasast:dev"
    assert task.command == ("verify", "--pass", "a")
    assert task.env[0].name == "OUSAST_PASS" and task.env[0].value == "a"
    assert task.resources is not None and task.resources.requests is not None and task.resources.limits is not None
    assert task.resources.requests.cpu == "500m" and task.resources.limits.memory == "4Gi"
    assert task.workspaces[0].path == "/workspace" and task.workspaces[0].goal is not None
    assert task.debug is True


def test_task_minimal_defaults() -> None:
    task = parse_manifest(doc(TASK_STUB % ("repo-facts", "repo-facts")))
    assert isinstance(task, Task)
    assert task.image is None and task.env == () and task.resources is None and task.workspaces == () and task.debug is False


def test_workspace_loads() -> None:
    workspace = parse_manifest(doc(WORKSPACE_YAML))
    assert isinstance(workspace, Workspace)
    assert workspace.git[0].repo.endswith("flask.git") and workspace.git[0].commit == "abc123"
    assert workspace.files[0].path == "candidates.json"
    assert workspace.mcp is not None and len(workspace.mcp.registries) == 1 and len(workspace.mcp.servers) == 1
    assert workspace.skills is not None and workspace.skills.path == "/skills"


def test_model_loads_with_declared_extension() -> None:
    model = parse_manifest(doc(MODEL_YAML))
    assert isinstance(model, Model)
    assert model.provider == "deepseek" and model.model == "deepseek-chat"
    assert model.secret_key is not None and model.secret_key.key == "token"
    assert model.parameters["price_prompt_usd_per_m"] == 0.27


@pytest.mark.parametrize("provider", ["google", "anthropic"])
def test_model_ax_providers_need_no_annotation(provider: str) -> None:
    document = doc(MODEL_YAML)
    del document["metadata"]["annotations"]
    document["spec"]["provider"] = provider
    model = parse_manifest(document)
    assert isinstance(model, Model) and model.provider == provider


def test_run_loads_graph() -> None:
    run = parse_manifest(doc(RUN_YAML))
    assert isinstance(run, Run)
    assert run.artifacts == "~/ousast-results/plane"
    assert [t.name for t in run.tasks] == ["repo-facts", "verify-a", "verify-b", "agree"]
    verify_a = run.task("verify-a")
    assert verify_a.task == "verify" and verify_a.depends_on == ("repo-facts",)
    assert verify_a.inputs == {"facts": "repo-facts/facts.json"}
    assert verify_a.budget is not None and verify_a.budget.usd == 1.5 and verify_a.budget.calls == 400
    assert run.task("verify-b").budget is not None and run.task("verify-b").budget.calls is None
    assert run.task("repo-facts").serialize == "engine" and run.task("repo-facts").budget is None
    assert run.task("agree").producers == ("verify-a", "verify-b")


def test_load_manifests_reads_multi_document_files(tmp_path: Path) -> None:
    (tmp_path / "kinds.yaml").write_text("---".join([TASK_YAML, WORKSPACE_YAML, MODEL_YAML]) + "\n---\n", encoding="utf-8")
    (tmp_path / "tasks.yaml").write_text(
        "---".join([TASK_STUB % ("repo-facts", "repo-facts"), TASK_STUB % ("agree", "agree")]), encoding="utf-8"
    )
    (tmp_path / "run.yaml").write_text(RUN_YAML, encoding="utf-8")
    manifests = load_manifests([tmp_path / "kinds.yaml", str(tmp_path / "tasks.yaml"), tmp_path / "run.yaml"])
    assert set(manifests.tasks) == {"verify", "repo-facts", "agree"}
    assert set(manifests.workspaces) == {"flask-abc123"}
    assert set(manifests.models) == {"deepseek-flash"}
    assert set(manifests.runs) == {"validation-46"}


# --- rejections: unknown fields, apiVersion, kind ---------------------------------------------------------------------


def test_unknown_top_level_field_is_named() -> None:
    document = doc(TASK_YAML)
    document["status"] = {}
    assert rejected(document, "status is not a field").startswith("Task/verify: ")


def test_unknown_spec_field_is_named() -> None:
    document = doc(TASK_YAML)
    document["spec"]["foo"] = 1
    assert rejected(document, "spec.foo is not a field") == "Task/verify: spec.foo is not a field"


def test_unknown_nested_fields_are_named_with_index() -> None:
    task = doc(TASK_YAML)
    task["spec"]["env"][0]["valueFrom"] = {}
    rejected(task, "spec.env[0].valueFrom is not a field")
    task = doc(TASK_YAML)
    task["spec"]["resources"]["requests"]["gpu"] = "1"
    rejected(task, "spec.resources.requests.gpu is not a field")
    workspace = doc(WORKSPACE_YAML)
    workspace["spec"]["git"][0]["depth"] = 1
    rejected(workspace, "Workspace/flask-abc123: spec.git[0].depth is not a field")
    model = doc(MODEL_YAML)
    model["spec"]["secretKey"]["namespace"] = "x"
    rejected(model, "Model/deepseek-flash: spec.secretKey.namespace is not a field")
    run = doc(RUN_YAML)
    run["spec"]["tasks"][1]["image"] = "x"
    rejected(run, "Run/validation-46: spec.tasks[1].image is not a field")
    run = doc(RUN_YAML)
    run["spec"]["tasks"][1]["budget"]["tokens"] = 1
    rejected(run, "spec.tasks[1].budget.tokens is not a field")


def test_unknown_metadata_field_is_named() -> None:
    document = doc(TASK_YAML)
    document["metadata"]["labels"] = {"a": "b"}
    rejected(document, "metadata.labels is not a field")


def test_wrong_api_version_is_named() -> None:
    task = doc(TASK_YAML)
    task["apiVersion"] = "ax.io/v1"
    assert rejected(task, "apiVersion").startswith("Task/verify: apiVersion 'ax.io/v1' must be 'ax.io/v1alpha1'")
    run = doc(RUN_YAML)
    run["apiVersion"] = "ax.io/v1alpha1"
    rejected(run, "Run/validation-46: apiVersion 'ax.io/v1alpha1' must be 'openultrasast.io/v1alpha1'")


def test_unknown_kind_and_non_mapping_are_rejected() -> None:
    document = doc(TASK_YAML)
    document["kind"] = "Pod"
    with pytest.raises(ManifestError, match="kind 'Pod' is not one of Task, Workspace, Model, Run"):
        parse_manifest(document)
    with pytest.raises(ManifestError, match="must be a mapping"):
        parse_manifest(["not", "a", "manifest"])


def test_missing_name_is_named() -> None:
    document = doc(TASK_YAML)
    del document["metadata"]["name"]
    assert rejected(document, "metadata.name is required") == "Task/?: metadata.name is required"


def test_task_type_errors_are_named() -> None:
    task = doc(TASK_YAML)
    task["spec"]["command"] = "verify"
    rejected(task, "spec.command must be a list")
    task = doc(TASK_YAML)
    task["spec"]["command"] = ["verify", 3]
    rejected(task, "spec.command[1] must be a non-empty string")
    task = doc(TASK_YAML)
    del task["spec"]["command"]
    rejected(task, "spec.command is required")
    task = doc(TASK_YAML)
    task["spec"]["debug"] = "yes"
    rejected(task, "spec.debug must be true or false")
    task = doc(TASK_YAML)
    del task["spec"]["workspaces"][0]["path"]
    rejected(task, "spec.workspaces[0].path is required")


# --- rejections: Model provider --------------------------------------------------------------------------------------


def test_deepseek_without_extension_annotation_is_rejected() -> None:
    document = doc(MODEL_YAML)
    del document["metadata"]["annotations"]
    message = rejected(document, "spec.provider")
    assert message.startswith("Model/deepseek-flash: spec.provider")
    assert 'metadata.annotations["openultrasast.io/provider-extension"] = "true"' in message
    document = doc(MODEL_YAML)
    document["metadata"]["annotations"]["openultrasast.io/provider-extension"] = "yes"
    rejected(document, "spec.provider")


def test_unknown_provider_is_rejected_even_with_annotation() -> None:
    document = doc(MODEL_YAML)
    document["spec"]["provider"] = "openai"
    assert rejected(document, 'spec.provider "openai" is not one of anthropic, deepseek, google')


def test_model_requires_model_name() -> None:
    document = doc(MODEL_YAML)
    del document["spec"]["model"]
    rejected(document, "spec.model is required")


# --- rejections: Run graph --------------------------------------------------------------------------------------------


def test_run_cycle_is_named() -> None:
    document = doc(RUN_YAML)
    document["spec"]["tasks"][0]["dependsOn"] = ["agree"]
    message = rejected(document, "dependsOn closes a cycle")
    assert message.startswith("Run/validation-46: spec.tasks[0].dependsOn closes a cycle: repo-facts -> ")
    assert message.endswith("-> repo-facts")


def test_run_self_dependency_is_a_cycle() -> None:
    document = doc(RUN_YAML)
    document["spec"]["tasks"][3]["dependsOn"] = ["agree"]
    rejected(document, "spec.tasks[3].dependsOn closes a cycle: agree -> agree")


def test_run_cycle_through_inputs_is_named() -> None:
    document = doc(RUN_YAML)
    document["spec"]["tasks"][0]["inputs"] = {"back": "verify-a/units.jsonl"}
    rejected(document, "spec.tasks[0].dependsOn closes a cycle: repo-facts -> verify-a -> repo-facts")


def test_run_input_naming_unknown_task_is_named() -> None:
    document = doc(RUN_YAML)
    document["spec"]["tasks"][1]["inputs"]["facts"] = "classify/facts.json"
    rejected(document, 'spec.tasks[1].inputs.facts "classify/facts.json" names no task in the Run')


def test_run_input_must_be_task_slash_artifact() -> None:
    document = doc(RUN_YAML)
    document["spec"]["tasks"][1]["inputs"]["facts"] = "facts.json"
    rejected(document, 'spec.tasks[1].inputs.facts "facts.json" must be "<task>/<artifact>"')


def test_run_depends_on_unknown_task_is_named() -> None:
    document = doc(RUN_YAML)
    document["spec"]["tasks"][3]["dependsOn"] = ["verify-a", "verify-c"]
    rejected(document, 'spec.tasks[3].dependsOn[1] "verify-c" names no task in the Run')


def test_run_duplicate_task_name_is_named() -> None:
    document = doc(RUN_YAML)
    document["spec"]["tasks"][2]["name"] = "verify-a"
    rejected(document, 'spec.tasks[2].name "verify-a" is defined twice')


def test_run_budget_types_are_named() -> None:
    document = doc(RUN_YAML)
    document["spec"]["tasks"][1]["budget"]["usd"] = "1.5"
    rejected(document, "spec.tasks[1].budget.usd must be a non-negative number")
    document = doc(RUN_YAML)
    document["spec"]["tasks"][1]["budget"]["calls"] = 2.5
    rejected(document, "spec.tasks[1].budget.calls must be a non-negative integer")
    document = doc(RUN_YAML)
    document["spec"]["tasks"][1]["budget"]["calls"] = -1
    rejected(document, "spec.tasks[1].budget.calls must be a non-negative integer")


def test_run_without_tasks_is_rejected() -> None:
    document = doc(RUN_YAML)
    document["spec"]["tasks"] = []
    rejected(document, "spec.tasks is required")


def test_run_task_naming_no_loaded_task_is_named(tmp_path: Path) -> None:
    run = parse_manifest(doc(RUN_YAML))
    assert isinstance(run, Run)
    verify = parse_manifest(doc(TASK_YAML))
    assert isinstance(verify, Task)
    with pytest.raises(ManifestError, match=r'Run/validation-46: spec.tasks\[0\].task "repo-facts" names no loaded Task'):
        check_run_tasks(run, {"verify": verify})
    (tmp_path / "all.yaml").write_text("---".join([TASK_YAML, TASK_STUB % ("repo-facts", "repo-facts"), RUN_YAML]), encoding="utf-8")
    with pytest.raises(ManifestError, match=r'spec.tasks\[3\].task "agree" names no loaded Task'):
        load_manifests([tmp_path / "all.yaml"])


# --- loader errors ---------------------------------------------------------------------------------------------------


def test_load_manifests_rejects_duplicate_names_and_bad_files(tmp_path: Path) -> None:
    (tmp_path / "dup.yaml").write_text("---".join([TASK_YAML, TASK_YAML]), encoding="utf-8")
    with pytest.raises(ManifestError, match="Task/verify: metadata.name is defined twice"):
        load_manifests([tmp_path / "dup.yaml"])
    (tmp_path / "bad.yaml").write_text("kind: Task\nspec: [unclosed\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="not valid YAML"):
        load_manifests([tmp_path / "bad.yaml"])
    with pytest.raises(ManifestError, match="cannot be read"):
        load_manifests([tmp_path / "missing.yaml"])


def test_manifests_are_frozen() -> None:
    task = parse_manifest(doc(TASK_YAML))
    with pytest.raises(AttributeError):
        task.metadata = copy.copy(task.metadata)  # type: ignore[misc]
