"""Manifests of the model-level service plane.

``Task``, ``Workspace`` and ``Model`` follow google/ax (``apiVersion: ax.io/v1alpha1``) and carry only the
fields ax documents, under ax's own names (``metadata.atespace``, not ``namespace``). ``metadata.annotations``
is this project's extension: ax's ObjectMeta has no such field and its API server rejects unknown fields, so the
reconciler strips annotations before anything reaches ``ax apply``. They declare the provider extension and carry
the Model binding and the Workspace commit pins (``openultrasast.io/git-commits: "<git name>=<sha>,..."``), which
reach the task as env. ``Run`` (``apiVersion: openultrasast.io/v1alpha1``) is this project's kind for the task
graph, artifacts and budgets; it holds nothing a task needs to execute. Every schema violation raises
:class:`ManifestError`, whose message names the kind, the ``metadata.name`` and the offending field path
(``Task/verify: spec.foo is not a field``), before anything runs.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "AX_API_VERSION",
    "AX_PROVIDERS",
    "EGRESS_HOSTS_ANNOTATION",
    "EXTENSION_PROVIDERS",
    "GIT_COMMITS_ANNOTATION",
    "PROVIDER_EXTENSION_ANNOTATION",
    "RUN_API_VERSION",
    "Budget",
    "EnvVar",
    "FileEntry",
    "GitSource",
    "ManifestError",
    "Manifests",
    "McpSpec",
    "Metadata",
    "Model",
    "ResourceSpec",
    "Resources",
    "Run",
    "RunTask",
    "SecretKey",
    "SkillsSpec",
    "Task",
    "Workspace",
    "WorkspaceBinding",
    "check_run_tasks",
    "load_manifests",
    "parse_manifest",
]

AX_API_VERSION = "ax.io/v1alpha1"
RUN_API_VERSION = "openultrasast.io/v1alpha1"
PROVIDER_EXTENSION_ANNOTATION = "openultrasast.io/provider-extension"
GIT_COMMITS_ANNOTATION = "openultrasast.io/git-commits"
EGRESS_HOSTS_ANNOTATION = "openultrasast.io/egress-hosts"  # the Model API hosts a bound task may reach
_DNS_NAME = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
AX_PROVIDERS = frozenset({"google", "anthropic"})
EXTENSION_PROVIDERS = frozenset({"deepseek"})

_API_VERSIONS = {"Task": AX_API_VERSION, "Workspace": AX_API_VERSION, "Model": AX_API_VERSION, "Run": RUN_API_VERSION}


class ManifestError(ValueError):
    """A manifest violates its schema; the message names kind, ``metadata.name`` and the field."""


# --- dataclasses -----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Metadata:
    name: str
    atespace: str | None = None
    annotations: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class EnvVar:
    name: str
    value: str


@dataclass(frozen=True)
class ResourceSpec:
    cpu: str | None = None
    memory: str | None = None


@dataclass(frozen=True)
class Resources:
    requests: ResourceSpec | None = None
    limits: ResourceSpec | None = None


@dataclass(frozen=True)
class WorkspaceBinding:
    name: str
    path: str
    goal: str | None = None


@dataclass(frozen=True)
class Task:
    metadata: Metadata
    command: tuple[str, ...]
    image: str | None = None
    env: tuple[EnvVar, ...] = ()
    resources: Resources | None = None
    workspaces: tuple[WorkspaceBinding, ...] = ()
    debug: bool = False


@dataclass(frozen=True)
class GitSource:
    """ax's ``GitRepo``: exactly ``name``, ``repo``, ``branch``, ``dir``, ``depth`` (a commit pin is an annotation)."""

    name: str
    repo: str
    branch: str | None = None
    dir: str | None = None
    depth: int | None = None


@dataclass(frozen=True)
class FileEntry:
    path: str
    content: str


@dataclass(frozen=True)
class McpSpec:
    registries: tuple[Any, ...] = ()
    servers: tuple[Any, ...] = ()


@dataclass(frozen=True)
class SkillsSpec:
    registries: tuple[Any, ...] = ()
    path: str | None = None


@dataclass(frozen=True)
class Workspace:
    metadata: Metadata
    git: tuple[GitSource, ...] = ()
    files: tuple[FileEntry, ...] = ()
    mcp: McpSpec | None = None
    skills: SkillsSpec | None = None

    @property
    def pins(self) -> dict[str, str]:
        """Git entry name -> 40-hex commit, from ``metadata.annotations["openultrasast.io/git-commits"]``."""
        return _split_pins(self.metadata.annotations.get(GIT_COMMITS_ANNOTATION, ""))


@dataclass(frozen=True)
class SecretKey:
    name: str
    key: str


@dataclass(frozen=True)
class Model:
    metadata: Metadata
    provider: str
    model: str
    secret_key: SecretKey | None = None
    parameters: Mapping[str, Any] = field(default_factory=dict)

    @property
    def egress_hosts(self) -> tuple[str, ...]:
        """DNS names from ``metadata.annotations["openultrasast.io/egress-hosts"]`` (comma-separated)."""
        return _split_hosts(self.metadata.annotations.get(EGRESS_HOSTS_ANNOTATION, ""))


def _split_hosts(text: str) -> tuple[str, ...]:
    return tuple(h.strip() for h in text.split(",") if h.strip())


@dataclass(frozen=True)
class Budget:
    usd: float | None = None
    calls: int | None = None


@dataclass(frozen=True)
class RunTask:
    name: str
    task: str
    depends_on: tuple[str, ...] = ()
    inputs: Mapping[str, str] = field(default_factory=dict)
    outputs: tuple[str, ...] = ()
    budget: Budget | None = None
    serialize: str | None = None

    @property
    def producers(self) -> tuple[str, ...]:
        """Tasks this task waits for: ``dependsOn`` plus the producer of every input, in order, unique."""
        seen: dict[str, None] = dict.fromkeys(self.depends_on)
        for ref in self.inputs.values():
            seen.setdefault(ref.split("/", 1)[0])
        return tuple(seen)


@dataclass(frozen=True)
class Run:
    metadata: Metadata
    tasks: tuple[RunTask, ...]
    artifacts: str | None = None

    def task(self, name: str) -> RunTask:
        for entry in self.tasks:
            if entry.name == name:
                return entry
        raise KeyError(name)


@dataclass(frozen=True)
class Manifests:
    """Loaded manifests by kind, each keyed by ``metadata.name``."""

    tasks: dict[str, Task] = field(default_factory=dict)
    workspaces: dict[str, Workspace] = field(default_factory=dict)
    models: dict[str, Model] = field(default_factory=dict)
    runs: dict[str, Run] = field(default_factory=dict)


# --- field access with named failures ----------------------------------------------------------------------------


def _join(path: str, key: str) -> str:
    return key if not path else f"{path}.{key}"


class _Check:
    """Field access on one document; every failure names ``Kind/name: path rule``."""

    def __init__(self, kind: str, name: str) -> None:
        self.prefix = f"{kind}/{name}: "

    def fail(self, path: str, rule: str) -> ManifestError:
        return ManifestError(f"{self.prefix}{path} {rule}")

    def mapping(self, value: object, path: str, allowed: Iterable[str]) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise self.fail(path or "document", "must be a mapping")
        allowed_set = frozenset(allowed)
        for key in value:
            if key not in allowed_set:
                raise self.fail(_join(path, str(key)), "is not a field")
        return value

    def optional_mapping(self, parent: Mapping[str, Any], path: str, key: str, allowed: Iterable[str]) -> dict[str, Any] | None:
        value = parent.get(key)
        return None if value is None else self.mapping(value, _join(path, key), allowed)

    def string(self, parent: Mapping[str, Any], path: str, key: str) -> str:
        value = parent.get(key)
        if value is None:
            raise self.fail(_join(path, key), "is required")
        if not isinstance(value, str) or not value:
            raise self.fail(_join(path, key), "must be a non-empty string")
        return value

    def optional_string(self, parent: Mapping[str, Any], path: str, key: str) -> str | None:
        return None if parent.get(key) is None else self.string(parent, path, key)

    def sequence(self, parent: Mapping[str, Any], path: str, key: str) -> list[Any]:
        value = parent.get(key)
        if value is None:
            return []
        if not isinstance(value, list):
            raise self.fail(_join(path, key), "must be a list")
        return value

    def strings(self, parent: Mapping[str, Any], path: str, key: str) -> tuple[str, ...]:
        items = self.sequence(parent, path, key)
        for index, item in enumerate(items):
            if not isinstance(item, str) or not item:
                raise self.fail(f"{_join(path, key)}[{index}]", "must be a non-empty string")
        return tuple(items)

    def mappings(self, parent: Mapping[str, Any], path: str, key: str, allowed: Iterable[str]) -> list[tuple[str, dict[str, Any]]]:
        allowed_set = frozenset(allowed)
        base = _join(path, key)
        return [
            (f"{base}[{i}]", self.mapping(item, f"{base}[{i}]", allowed_set)) for i, item in enumerate(self.sequence(parent, path, key))
        ]

    def string_map(self, parent: Mapping[str, Any], path: str, key: str) -> dict[str, str]:
        value = parent.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise self.fail(_join(path, key), "must be a mapping")
        for item_key, item in value.items():
            if not isinstance(item_key, str) or not isinstance(item, str) or not item:
                raise self.fail(_join(_join(path, key), str(item_key)), "must map a string to a non-empty string")
        return value

    def optional_int(self, parent: Mapping[str, Any], path: str, key: str) -> int | None:
        value = parent.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise self.fail(_join(path, key), "must be a non-negative integer")
        return value

    def boolean(self, parent: Mapping[str, Any], path: str, key: str) -> bool:
        value = parent.get(key, False)
        if not isinstance(value, bool):
            raise self.fail(_join(path, key), "must be true or false")
        return value


# --- per-kind parsers ----------------------------------------------------------------------------------------------


def _parse_metadata(check: _Check, value: object) -> Metadata:
    meta = check.mapping(value, "metadata", ("name", "atespace", "annotations"))
    return Metadata(
        name=check.string(meta, "metadata", "name"),
        atespace=check.optional_string(meta, "metadata", "atespace"),
        annotations=check.string_map(meta, "metadata", "annotations"),
    )


def _parse_resource_spec(check: _Check, spec: Mapping[str, Any], path: str, key: str) -> ResourceSpec | None:
    entry = check.optional_mapping(spec, path, key, ("cpu", "memory"))
    if entry is None:
        return None
    sub = _join(path, key)
    return ResourceSpec(cpu=check.optional_string(entry, sub, "cpu"), memory=check.optional_string(entry, sub, "memory"))


def _parse_task(check: _Check, metadata: Metadata, spec: Mapping[str, Any]) -> Task:
    command = check.strings(spec, "spec", "command")
    if not command:
        raise check.fail("spec.command", "is required")
    resources = check.optional_mapping(spec, "spec", "resources", ("requests", "limits"))
    return Task(
        metadata=metadata,
        command=command,
        image=check.optional_string(spec, "spec", "image"),
        env=tuple(
            EnvVar(check.string(e, p, "name"), check.string(e, p, "value"))
            for p, e in check.mappings(spec, "spec", "env", ("name", "value"))
        ),
        resources=None
        if resources is None
        else Resources(
            requests=_parse_resource_spec(check, resources, "spec.resources", "requests"),
            limits=_parse_resource_spec(check, resources, "spec.resources", "limits"),
        ),
        workspaces=tuple(
            WorkspaceBinding(check.string(w, p, "name"), check.string(w, p, "path"), check.optional_string(w, p, "goal"))
            for p, w in check.mappings(spec, "spec", "workspaces", ("name", "path", "goal"))
        ),
        debug=check.boolean(spec, "spec", "debug"),
    )


_SHA = re.compile(r"[0-9a-f]{40}")


def _pin_items(value: str) -> list[str]:
    return [item for item in (part.strip() for part in value.split(",")) if item]


def _split_pins(value: str) -> dict[str, str]:
    """``name=sha,name=sha`` -> ``{name: sha}`` (validated at parse time by :func:`_check_pins`)."""
    pairs = (item.partition("=") for item in _pin_items(value))
    return {name.strip(): sha.strip() for name, _, sha in pairs}


def _check_pins(check: _Check, metadata: Metadata, git: tuple[GitSource, ...]) -> None:
    path = f'metadata.annotations["{GIT_COMMITS_ANNOTATION}"]'
    names = {g.name for g in git}
    for item in _pin_items(metadata.annotations.get(GIT_COMMITS_ANNOTATION, "")):
        name, eq, sha = (part.strip() for part in item.partition("="))
        if not eq or not name:
            raise check.fail(path, f'item "{item}" must be "<git name>=<40-hex commit>"')
        if name not in names:
            raise check.fail(path, f'"{name}" names no spec.git entry')
        if not _SHA.fullmatch(sha):
            raise check.fail(path, f'"{name}={sha}" is not a 40-hex commit')


def _parse_git(check: _Check, spec: Mapping[str, Any]) -> tuple[GitSource, ...]:
    for index, entry in enumerate(check.sequence(spec, "spec", "git")):
        if isinstance(entry, dict) and "commit" in entry:
            raise check.fail(
                f"spec.git[{index}].commit",
                f'is not an ax field; pin the commit in metadata.annotations["{GIT_COMMITS_ANNOTATION}"] as "<git name>=<sha>"',
            )
    return tuple(
        GitSource(
            check.string(g, p, "name"),
            check.string(g, p, "repo"),
            check.optional_string(g, p, "branch"),
            check.optional_string(g, p, "dir"),
            check.optional_int(g, p, "depth"),
        )
        for p, g in check.mappings(spec, "spec", "git", ("name", "repo", "branch", "dir", "depth"))
    )


def _parse_workspace(check: _Check, metadata: Metadata, spec: Mapping[str, Any]) -> Workspace:
    mcp = check.optional_mapping(spec, "spec", "mcp", ("registries", "servers"))
    skills = check.optional_mapping(spec, "spec", "skills", ("registries", "path"))
    git = _parse_git(check, spec)
    _check_pins(check, metadata, git)
    return Workspace(
        metadata=metadata,
        git=git,
        files=tuple(
            FileEntry(check.string(f, p, "path"), check.string(f, p, "content"))
            for p, f in check.mappings(spec, "spec", "files", ("path", "content"))
        ),
        mcp=None
        if mcp is None
        else McpSpec(tuple(check.sequence(mcp, "spec.mcp", "registries")), tuple(check.sequence(mcp, "spec.mcp", "servers"))),
        skills=None
        if skills is None
        else SkillsSpec(tuple(check.sequence(skills, "spec.skills", "registries")), check.optional_string(skills, "spec.skills", "path")),
    )


def _parse_model(check: _Check, metadata: Metadata, spec: Mapping[str, Any]) -> Model:
    provider = check.string(spec, "spec", "provider")
    if provider in EXTENSION_PROVIDERS:
        if metadata.annotations.get(PROVIDER_EXTENSION_ANNOTATION) != "true":
            raise check.fail(
                "spec.provider",
                f'"{provider}" is not an ax provider; requires metadata.annotations["{PROVIDER_EXTENSION_ANNOTATION}"] = "true"',
            )
    elif provider not in AX_PROVIDERS:
        raise check.fail("spec.provider", f'"{provider}" is not one of {", ".join(sorted(AX_PROVIDERS | EXTENSION_PROVIDERS))}')
    for host in _split_hosts(metadata.annotations.get(EGRESS_HOSTS_ANNOTATION, "")):
        if not _DNS_NAME.match(host) or host.replace(".", "").isdigit():
            path = f'metadata.annotations["{EGRESS_HOSTS_ANNOTATION}"]'
            raise check.fail(path, f"{host!r} is not a lowercase DNS name (no wildcard, IP address, port or scheme)")
    secret = check.optional_mapping(spec, "spec", "secretKey", ("name", "key"))
    parameters = spec.get("parameters") or {}
    if not isinstance(parameters, dict):
        raise check.fail("spec.parameters", "must be a mapping")
    return Model(
        metadata=metadata,
        provider=provider,
        model=check.string(spec, "spec", "model"),
        secret_key=None
        if secret is None
        else SecretKey(check.string(secret, "spec.secretKey", "name"), check.string(secret, "spec.secretKey", "key")),
        parameters=parameters,
    )


def _parse_budget(check: _Check, entry: Mapping[str, Any], path: str) -> Budget | None:
    budget = check.optional_mapping(entry, path, "budget", ("usd", "calls"))
    if budget is None:
        return None
    usd, calls = budget.get("usd"), budget.get("calls")
    if usd is not None and (isinstance(usd, bool) or not isinstance(usd, int | float) or usd < 0):
        raise check.fail(f"{path}.budget.usd", "must be a non-negative number")
    if calls is not None and (isinstance(calls, bool) or not isinstance(calls, int) or calls < 0):
        raise check.fail(f"{path}.budget.calls", "must be a non-negative integer")
    return Budget(usd=None if usd is None else float(usd), calls=calls)


def _parse_run(check: _Check, metadata: Metadata, spec: Mapping[str, Any]) -> Run:
    entries = check.mappings(spec, "spec", "tasks", ("name", "task", "dependsOn", "inputs", "outputs", "budget", "serialize"))
    if not entries:
        raise check.fail("spec.tasks", "is required")
    tasks: list[RunTask] = []
    for path, entry in entries:
        inputs = check.string_map(entry, path, "inputs")
        for input_name, ref in inputs.items():
            producer, _, artifact = ref.partition("/")
            if not producer or not artifact:
                raise check.fail(f"{path}.inputs.{input_name}", f'"{ref}" must be "<task>/<artifact>"')
        tasks.append(
            RunTask(
                name=check.string(entry, path, "name"),
                task=check.string(entry, path, "task"),
                depends_on=check.strings(entry, path, "dependsOn"),
                inputs=inputs,
                outputs=check.strings(entry, path, "outputs"),
                budget=_parse_budget(check, entry, path),
                serialize=check.optional_string(entry, path, "serialize"),
            )
        )
    run = Run(metadata=metadata, tasks=tuple(tasks), artifacts=check.optional_string(spec, "spec", "artifacts"))
    _check_run_graph(check, run)
    return run


def _check_run_graph(check: _Check, run: Run) -> None:
    names: dict[str, int] = {}
    for index, entry in enumerate(run.tasks):
        if entry.name in names:
            raise check.fail(f"spec.tasks[{index}].name", f'"{entry.name}" is defined twice')
        names[entry.name] = index
    for index, entry in enumerate(run.tasks):
        for dep_index, dep in enumerate(entry.depends_on):
            if dep not in names:
                raise check.fail(f"spec.tasks[{index}].dependsOn[{dep_index}]", f'"{dep}" names no task in the Run')
        for input_name, ref in entry.inputs.items():
            if ref.split("/", 1)[0] not in names:
                raise check.fail(f"spec.tasks[{index}].inputs.{input_name}", f'"{ref}" names no task in the Run')
    cycle = _find_cycle(run)
    if cycle is not None:
        raise check.fail(f"spec.tasks[{names[cycle[0]]}].dependsOn", "closes a cycle: " + " -> ".join(cycle))


def _find_cycle(run: Run) -> list[str] | None:
    """Return one dependency cycle as ``[a, b, ..., a]`` over ``dependsOn`` and input producers, or None."""
    state: dict[str, int] = {}  # 1 = on the current path, 2 = finished
    path: list[str] = []

    def visit(name: str) -> list[str] | None:
        state[name] = 1
        path.append(name)
        for dep in run.task(name).producers:
            mark = state.get(dep)
            if mark == 1:
                return path[path.index(dep) :] + [dep]
            if mark is None:
                found = visit(dep)
                if found is not None:
                    return found
        path.pop()
        state[name] = 2
        return None

    for entry in run.tasks:
        if entry.name not in state:
            found = visit(entry.name)
            if found is not None:
                return found
    return None


def check_run_tasks(run: Run, tasks: Mapping[str, Task]) -> None:
    """Reject a Run whose entries name a Task that is not among ``tasks``."""
    check = _Check("Run", run.metadata.name)
    for index, entry in enumerate(run.tasks):
        if entry.task not in tasks:
            raise check.fail(f"spec.tasks[{index}].task", f'"{entry.task}" names no loaded Task')


_PARSERS: dict[str, Any] = {"Task": _parse_task, "Workspace": _parse_workspace, "Model": _parse_model, "Run": _parse_run}
_SPEC_FIELDS = {
    "Task": ("image", "command", "env", "resources", "workspaces", "debug"),
    "Workspace": ("git", "files", "mcp", "skills"),
    "Model": ("provider", "model", "secretKey", "parameters"),
    "Run": ("tasks", "artifacts"),
}


def parse_manifest(document: object, *, source: str = "<document>") -> Task | Workspace | Model | Run:
    """Validate one decoded YAML document and return its manifest; raise :class:`ManifestError` naming the field."""
    if not isinstance(document, dict):
        raise ManifestError(f"{source}: a manifest must be a mapping")
    kind = document.get("kind")
    if not isinstance(kind, str) or kind not in _PARSERS:
        raise ManifestError(f"{source}: kind {kind!r} is not one of Task, Workspace, Model, Run")
    raw_meta = document.get("metadata")
    raw_name = raw_meta.get("name") if isinstance(raw_meta, dict) else None
    check = _Check(kind, raw_name if isinstance(raw_name, str) and raw_name else "?")
    check.mapping(document, "", ("apiVersion", "kind", "metadata", "spec"))
    api_version = document.get("apiVersion")
    if api_version != _API_VERSIONS[kind]:
        raise check.fail("apiVersion", f"{api_version!r} must be {_API_VERSIONS[kind]!r}")
    metadata = _parse_metadata(check, raw_meta)
    spec = check.mapping(document.get("spec"), "spec", _SPEC_FIELDS[kind])
    manifest: Task | Workspace | Model | Run = _PARSERS[kind](check, metadata, spec)
    return manifest


def _documents(path: Path) -> list[Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"{path}: cannot be read: {exc}") from exc
    try:
        return list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise ManifestError(f"{path}: not valid YAML: {exc}") from exc


def load_manifests(paths: Iterable[str | Path]) -> Manifests:
    """Read one or more YAML files (multi-document allowed), validate each manifest and index them by kind and name.

    Every Run is checked against the Tasks loaded in the same call; a name defined twice within a kind is rejected.
    """
    manifests = Manifests()
    buckets: dict[type, dict[str, Any]] = {
        Task: manifests.tasks,
        Workspace: manifests.workspaces,
        Model: manifests.models,
        Run: manifests.runs,
    }
    for raw_path in paths:
        path = Path(raw_path)
        for index, document in enumerate(_documents(path)):
            if document is None:
                continue
            manifest = parse_manifest(document, source=f"{path}[{index}]")
            bucket = buckets[type(manifest)]
            name = manifest.metadata.name
            if name in bucket:
                raise ManifestError(f"{type(manifest).__name__}/{name}: metadata.name is defined twice ({path})")
            bucket[name] = manifest
    for run in manifests.runs.values():
        check_run_tasks(run, manifests.tasks)
    return manifests
