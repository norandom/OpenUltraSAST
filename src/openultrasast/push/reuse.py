"""Compatible replay reuse; the existing ranker and detector remain decision owners."""

from __future__ import annotations

import math
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from openultrasast.cpg.artifact import GraphArtifact, digest_value
from openultrasast.cpg.backend import CpgResult, JoernBackend
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.model.regions import ScanRegion
from openultrasast.push.cache import ArtifactCache, SemanticKeys
from openultrasast.push.contracts import SnapshotManifest


class ReusingBackend:
    def __init__(self, backend: JoernBackend, cache: ArtifactCache, semantics: SemanticKeys, *, declarations: str, exclusions: str) -> None:
        self.backend = backend
        self.cache = cache
        self.semantics = semantics
        self.declarations = declarations
        self.exclusions = exclusions
        self.last_failure = ""
        self.graph_hits = 0
        self.query_hits = 0

    def build(self, root: Path, *, language: str, exclude: Sequence[str], execution_budget: ExecutionBudget) -> CpgResult | None:
        identity = None
        artifact = None
        result = None
        try:
            identity = self.backend.graph_identity(
                root,
                language=language,
                declarations_digest=self.declarations,
                exclusions_digest=digest_value([self.exclusions, sorted(exclude)]),
                execution_budget=execution_budget,
            )
            key = digest_value({"layer": "graph-v1", "identity": identity.to_payload()})
            with self.cache.lookup(key, execution_budget) as entry:
                if entry is not None:
                    artifact = GraphArtifact.from_payload(entry.metadata)
                    result = self.backend.load_graph(entry.path, artifact, identity, execution_budget=execution_budget)
                    if result is not None:
                        self.graph_hits += 1
        except (OSError, ValueError, TimeoutError):
            artifact = None
        if result is None:
            artifact = None
            result = self.backend.build(root, language=language, exclude=exclude, execution_budget=execution_budget)
            self.last_failure = self.backend.last_failure
            if result is None:
                return None
            if identity is not None and time.monotonic() < execution_budget.deadline_monotonic:
                artifact = self.backend.describe_graph(result, root, identity, execution_budget=execution_budget)
                if artifact is not None:
                    self.cache.publish(key, result.cpg_path, artifact.to_payload(), execution_budget)
        if artifact is None:
            return result
        return self._answers(result, artifact, execution_budget)

    def _answers(self, result: CpgResult, artifact: GraphArtifact, budget: ExecutionBudget) -> CpgResult:
        def normalize(value: Any) -> Any:
            if isinstance(value, str):
                return value.replace(artifact.source_root + "/", "")
            if isinstance(value, list):
                return [normalize(item) for item in value]
            if isinstance(value, dict):
                return {key: normalize(item) for key, item in value.items()}
            return value

        def batch(kind: str, requests: Mapping[str, Mapping[str, object]]) -> dict[str, list[object]] | None:
            answers: dict[str, list[object]] = {}
            missing = {}
            keys = {}
            for rid, request in requests.items():
                if time.monotonic() >= budget.deadline_monotonic:
                    break
                key = self.semantics.query(
                    graph=digest_value({"identity": artifact.identity.to_payload(), "bytes": artifact.graph_digest}),
                    kind=kind,
                    request=request,
                    context={"paths": artifact.source_paths, "declarations": artifact.identity.declarations_digest},
                )
                keys[rid] = key
                cached = self.cache.get_json(key, kind="query", budget=budget)
                if isinstance(cached, dict) and isinstance(cached.get("rows"), list) and self._census(cached.get("census"), artifact):
                    answers[rid] = cached["rows"]
                    answers["__census__"] = cached["census"]
                    self.query_hits += 1
                else:
                    missing[rid] = request
            if missing and time.monotonic() < budget.deadline_monotonic:
                raw: Any = result.run_batch(kind, missing) if result.run_batch else None
                if raw is None and result.run_batch is None:
                    raw = {rid: result.run(kind, params) for rid, params in missing.items()}
                if isinstance(raw, dict):
                    normalized = normalize(raw)
                    census = normalized.get("__census__")
                    valid = self._census(census, artifact)
                    if not valid:
                        return answers or None
                    answers["__census__"] = census
                    for rid in missing:
                        rows = normalized.get(rid)
                        if isinstance(rows, list):
                            answers[rid] = rows
                            self.cache.put_json(keys[rid], {"rows": rows, "census": census}, kind="query", budget=budget, complete=valid)
            return answers or None

        def run(kind: str, params: Mapping[str, object]) -> object | None:
            if kind == "census":
                value: object = normalize(result.run(kind, params))
                return value
            rows = batch(kind, {"one": params})
            return rows.get("one") if rows is not None else None

        return replace(result, run=run, run_batch=batch)

    @staticmethod
    def _census(value: object, artifact: GraphArtifact) -> bool:
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            return False
        row = value[0]
        names = row.get("file_names")
        try:
            return (
                isinstance(names, list)
                and all(isinstance(name, str) for name in names)
                and set(artifact.source_paths) <= set(names)
                and int(str(row.get("methods", 0))) > 0
                and int(str(row.get("files", 0))) >= len(artifact.source_paths)
                and int(str(row.get("shards", 1))) == 1
            )
        except (ValueError, TypeError):
            return False


def discovery(
    root: Path,
    manifest: SnapshotManifest,
    *,
    cache: ArtifactCache | None,
    identity: str,
    budget: ExecutionBudget,
    discover: Callable[[Path], tuple[tuple[ScanRegion, ...], tuple[bytes, ...]]],
) -> tuple[tuple[ScanRegion, ...], tuple[bytes, ...], bool]:
    """Persist pure discovery only after the adapter proves the complete snapshot readable."""
    key = digest_value(
        {
            "layer": "discovery-v1",
            "files": [item.to_payload() for item in manifest.files],
            "object_format": manifest.object_format,
            "identity": identity,
        }
    )
    raw = cache.get_json(key, kind="discovery", budget=budget) if cache and manifest.complete else None
    if isinstance(raw, dict):
        try:
            regions = []
            for item in raw["regions"]:
                values = dict(item)
                values["families"] = tuple(values["families"])
                region = ScanRegion(**values)
                if (
                    not all(isinstance(v, str) for v in (region.path, region.language, region.source, *region.families))
                    or region.function is not None
                    and not isinstance(region.function, str)
                    or type(region.shipped) is not bool
                    or type(region.rank) not in (int, float)
                    or not math.isfinite(region.rank)
                ):
                    raise ValueError("invalid_discovery_region")
                if os.fsencode(region.path) not in {item.path_bytes for item in manifest.files}:
                    raise ValueError("discovery_path_outside_snapshot")
                regions.append(region)
            declarations = tuple(bytes.fromhex(item) for item in raw["declarations"])
            if not set(declarations) <= {item.path_bytes for item in manifest.files}:
                raise ValueError("invalid_declarations")
            return tuple(regions), declarations, True
        except (KeyError, ValueError, TypeError):
            pass
    found, declarations = discover(root)
    if cache and manifest.complete:
        cache.put_json(
            key,
            {"regions": [asdict(region) for region in found], "declarations": [item.hex() for item in declarations]},
            kind="discovery",
            budget=budget,
            complete=True,
        )
    return found, declarations, False


def declaration_identity(manifest: SnapshotManifest, paths: tuple[bytes, ...]) -> str:
    declared = set(paths)
    return digest_value([item.to_payload() for item in manifest.files if item.path_bytes in declared])
