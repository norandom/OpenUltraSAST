"""Metadata-only source authority for isolated label-blind execution."""

from __future__ import annotations

from dataclasses import dataclass

from benchmarks.valid.isolated_execution_contract import (
    IsolatedExecutionError,
    LabelBlindCaseInputV1,
    _bind_digest,
    _digest,
    _positive,
)
from benchmarks.valid.ordinary_change_contract import (
    OrdinaryPushV1,
    OrdinarySelectionV1,
    ordinary_selection_bytes,
)
from benchmarks.valid.population_label_blind_contract import (
    LabelBlindPopulationManifestV3,
    label_blind_population_manifest_bytes,
)
from benchmarks.valid.population_material_contract import (
    PublicPopulationMaterialManifestV1,
    _manifest_value,
    _validate_manifest_counts,
)
from benchmarks.valid.replacement_artifact_contract import ArtifactAccessClass
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue
from openultrasast.core.evaluation_plan import derive_evaluation_input_set_digest

EXECUTION_SOURCE_SCHEMA = "openultrasast.valid-detection-benchmark.execution-source-projection.v1"


@dataclass(frozen=True, order=True)
class ExecutionSourceRecordV1:
    input_identity_digest: str
    change_input_digest: str
    source_digest: str
    byte_length: int
    provenance_digest: str
    access_class: ArtifactAccessClass

    def __post_init__(self) -> None:
        if type(self) is not ExecutionSourceRecordV1:
            raise IsolatedExecutionError("execution source must use exact ExecutionSourceRecordV1")
        for item, field in (
            (self.input_identity_digest, "source input identity"),
            (self.change_input_digest, "source change input"),
            (self.source_digest, "source content"),
            (self.provenance_digest, "source provenance"),
        ):
            _digest(item, field)
        _positive(self.byte_length, "source byte length", 1 << 34)
        if type(self.access_class) is not ArtifactAccessClass or self.access_class not in {
            ArtifactAccessClass.PUBLIC,
            ArtifactAccessClass.PRIVATE,
        }:
            raise IsolatedExecutionError("execution source access must be public or private")


def _source_value(source: ExecutionSourceRecordV1) -> dict[str, JsonValue]:
    source.__post_init__()
    return {
        "input_identity_digest": source.input_identity_digest,
        "change_input_digest": source.change_input_digest,
        "source_digest": source.source_digest,
        "byte_length": source.byte_length,
        "provenance_digest": source.provenance_digest,
        "access_class": source.access_class.value,
    }


@dataclass(frozen=True)
class ExecutionSourceProjectionV1:
    label_blind_manifest_digest: str
    public_material_manifest_digest: str
    material_artifact_set_digest: str
    ordinary_selection_digest: str
    input_set_digest: str
    sources: tuple[ExecutionSourceRecordV1, ...]
    projection_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ExecutionSourceProjectionV1:
            raise IsolatedExecutionError("source projection must use exact ExecutionSourceProjectionV1")
        for item, field in (
            (self.label_blind_manifest_digest, "label-blind manifest"),
            (self.public_material_manifest_digest, "public material manifest"),
            (self.material_artifact_set_digest, "reviewed material artifact set"),
            (self.ordinary_selection_digest, "ordinary selection"),
            (self.input_set_digest, "source input set"),
        ):
            _digest(item, field)
        _validate_source_rows(self.sources, self.input_set_digest)
        expected = canonical.content_digest(_projection_value(self, include_digest=False))
        _bind_digest(self, "projection_digest", expected)


def _validate_source_rows(sources: tuple[ExecutionSourceRecordV1, ...], input_set_digest: str) -> None:
    if type(sources) is not tuple or not sources:
        raise IsolatedExecutionError("source projection must contain a nonempty exact tuple")
    if any(type(row) is not ExecutionSourceRecordV1 for row in sources):
        raise IsolatedExecutionError("source projection contains a non-exact source record")
    for row in sources:
        row.__post_init__()
    identities = tuple(row.input_identity_digest for row in sources)
    if identities != tuple(sorted(set(identities))):
        raise IsolatedExecutionError("source projection identities must be unique and canonical")
    if derive_evaluation_input_set_digest(identities) != input_set_digest:
        raise IsolatedExecutionError("source projection does not match its input-set identity")


def _projection_value(
    projection: ExecutionSourceProjectionV1,
    *,
    include_digest: bool,
) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": EXECUTION_SOURCE_SCHEMA,
        "label_blind_manifest_digest": projection.label_blind_manifest_digest,
        "public_material_manifest_digest": projection.public_material_manifest_digest,
        "material_artifact_set_digest": projection.material_artifact_set_digest,
        "ordinary_selection_digest": projection.ordinary_selection_digest,
        "input_set_digest": projection.input_set_digest,
        "sources": tuple(_source_value(row) for row in projection.sources),
    }
    if include_digest:
        value["projection_digest"] = projection.projection_digest
    return value


def execution_source_projection_bytes(projection: ExecutionSourceProjectionV1) -> bytes:
    if type(projection) is not ExecutionSourceProjectionV1:
        raise IsolatedExecutionError("source projection must use exact ExecutionSourceProjectionV1")
    projection.__post_init__()
    return canonical.canonical_bytes(_projection_value(projection, include_digest=True))


def _public_manifest_bytes(manifest: PublicPopulationMaterialManifestV1) -> bytes:
    if type(manifest) is not PublicPopulationMaterialManifestV1:
        raise IsolatedExecutionError("source authority must use exact PublicPopulationMaterialManifestV1")
    if manifest.public_sources != tuple(sorted(set(manifest.public_sources))):
        raise IsolatedExecutionError("public source metadata is not canonical")
    if manifest.private_refs != tuple(sorted(set(manifest.private_refs))):
        raise IsolatedExecutionError("private source metadata is not canonical")
    if manifest.positive_change_digests != tuple(sorted(set(manifest.positive_change_digests))):
        raise IsolatedExecutionError("positive source identities are not canonical")
    try:
        _validate_manifest_counts(manifest)
        value = _manifest_value(manifest, include_digest=False)
        if canonical.content_digest(value) != manifest.manifest_digest:
            raise IsolatedExecutionError("public material manifest digest does not match")
        return canonical.canonical_bytes(_manifest_value(manifest, include_digest=True))
    except (TypeError, ValueError) as error:
        raise IsolatedExecutionError("public material manifest metadata is invalid") from error


def _positive_sources(
    manifest: PublicPopulationMaterialManifestV1,
) -> dict[str, ExecutionSourceRecordV1]:
    result = {
        row.change_digest: ExecutionSourceRecordV1(
            row.change_digest,
            row.change_digest,
            row.source_digest,
            row.byte_length,
            row.object_digest,
            ArtifactAccessClass.PUBLIC,
        )
        for row in manifest.public_sources
    }
    result.update(
        {
            row.change_digest: ExecutionSourceRecordV1(
                row.change_digest,
                row.change_digest,
                row.source_digest,
                row.byte_length,
                manifest.private_object_digest,
                ArtifactAccessClass.PRIVATE,
            )
            for row in manifest.private_refs
        }
    )
    if tuple(sorted(result)) != manifest.positive_change_digests:
        raise IsolatedExecutionError("public material metadata does not cover the exact positive set")
    return result


def _ordinary_source(push: OrdinaryPushV1) -> ExecutionSourceRecordV1:
    return ExecutionSourceRecordV1(
        push.push_digest,
        push.change_content_digest,
        push.change_content_digest,
        push.change_byte_length,
        push.history_source_digest,
        ArtifactAccessClass.PRIVATE,
    )


def _source_records(
    manifest: LabelBlindPopulationManifestV3,
    public_manifest: PublicPopulationMaterialManifestV1,
    selection: OrdinarySelectionV1,
) -> tuple[ExecutionSourceRecordV1, ...]:
    result = _positive_sources(public_manifest)
    if tuple(sorted(result)) != selection.positive_change_digests:
        raise IsolatedExecutionError("ordinary selection does not match the exact positive source set")
    for push in selection.pushes:
        if push.push_digest in result:
            raise IsolatedExecutionError("one input identity maps to more than one source")
        result[push.push_digest] = _ordinary_source(push)
    if tuple(sorted(result)) != manifest.input_digests:
        raise IsolatedExecutionError("source metadata does not reconstruct the reviewed input identities")
    return tuple(result[item] for item in manifest.input_digests)


def build_execution_source_projection(
    manifest: LabelBlindPopulationManifestV3,
    public_material_manifest: PublicPopulationMaterialManifestV1,
    selection: OrdinarySelectionV1,
) -> ExecutionSourceProjectionV1:
    """Derive adapter source authority without accepting or opening material bytes."""
    try:
        if not label_blind_population_manifest_bytes(manifest):
            raise IsolatedExecutionError("label-blind manifest bytes must be nonempty")
        if not _public_manifest_bytes(public_material_manifest):
            raise IsolatedExecutionError("public material manifest bytes must be nonempty")
        if type(selection) is not OrdinarySelectionV1 or not ordinary_selection_bytes(selection):
            raise IsolatedExecutionError("ordinary selection authority is invalid or empty")
    except (TypeError, ValueError) as error:
        raise IsolatedExecutionError("execution source authority metadata is invalid") from error
    _validate_authority_bindings(manifest, public_material_manifest, selection)
    sources = _source_records(manifest, public_material_manifest, selection)
    return ExecutionSourceProjectionV1(
        manifest.manifest_digest,
        public_material_manifest.manifest_digest,
        manifest.material_artifact_set_digest,
        selection.selection_digest,
        manifest.input_set_digest,
        sources,
        "",
    )


def _validate_authority_bindings(
    manifest: LabelBlindPopulationManifestV3,
    public_manifest: PublicPopulationMaterialManifestV1,
    selection: OrdinarySelectionV1,
) -> None:
    if (public_manifest.population_digest, public_manifest.freeze_digest) != (
        manifest.population_digest,
        manifest.freeze_digest,
    ):
        raise IsolatedExecutionError("public material manifest does not bind the reviewed population")
    if public_manifest.manifest_digest != manifest.public_material_manifest_digest:
        raise IsolatedExecutionError("public material manifest does not match the reviewed identity")
    if selection.selection_digest != manifest.ordinary_selection_digest:
        raise IsolatedExecutionError("ordinary selection does not match the reviewed identity")
    if derive_evaluation_input_set_digest(manifest.input_digests) != manifest.input_set_digest:
        raise IsolatedExecutionError("reviewed input identities do not match their input-set identity")


def validate_execution_cases(
    cases: tuple[LabelBlindCaseInputV1, ...],
    projection: ExecutionSourceProjectionV1,
) -> tuple[LabelBlindCaseInputV1, ...]:
    if type(cases) is not tuple or not cases:
        raise IsolatedExecutionError("case inputs must be a nonempty tuple")
    if any(type(row) is not LabelBlindCaseInputV1 for row in cases):
        raise IsolatedExecutionError("case inputs must use exact LabelBlindCaseInputV1 values")
    projection.__post_init__()
    identities = tuple(row.input_identity_digest for row in cases)
    expected = tuple(row.input_identity_digest for row in projection.sources)
    if identities != expected:
        raise IsolatedExecutionError("case inputs must exactly equal the source projection identities")
    for case, source in zip(cases, projection.sources, strict=True):
        case.__post_init__()
        _validate_case_source(case, source)
    return cases


def _validate_case_source(case: LabelBlindCaseInputV1, source: ExecutionSourceRecordV1) -> None:
    reference = case.code_reference
    if case.change_input_digest != source.change_input_digest:
        raise IsolatedExecutionError("case change does not match the source authority")
    if reference.content_digest != source.source_digest:
        raise IsolatedExecutionError("case source digest does not match the source authority")
    if reference.byte_length != source.byte_length:
        raise IsolatedExecutionError("case source length does not match the source authority")
    if reference.provenance_digest != source.provenance_digest:
        raise IsolatedExecutionError("case provenance does not match the source authority")
    if reference.access_class is not source.access_class:
        raise IsolatedExecutionError("case access does not match the source authority")


__all__ = [
    "EXECUTION_SOURCE_SCHEMA",
    "ExecutionSourceProjectionV1",
    "ExecutionSourceRecordV1",
    "build_execution_source_projection",
    "execution_source_projection_bytes",
    "validate_execution_cases",
]
