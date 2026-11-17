"""Boundary tests for typed public source objects and metadata-only manifests."""

from __future__ import annotations

import base64
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_population_materials import (  # noqa: E402
    _digest,
    _freeze,
    _inputs,
    _Validator,
)

from benchmarks.valid import population_materials as materials  # noqa: E402
from benchmarks.valid.population_freeze_contract import (  # noqa: E402
    PopulationFreezeV3,
    _freeze_value,
    _population_value,
)
from openultrasast.core.canonical import bytes_digest, canonical_bytes, content_digest  # noqa: E402


def _partition_with_source(source: bytes) -> materials.PopulationMaterialPartitionV1:
    changes = tuple(_digest(f"typed-source-{index}") for index in range(3))
    freeze = _freeze(changes)
    inputs = list(_inputs(changes))
    inputs[0] = replace(inputs[0], source_content=source)
    return materials.build_population_material_partition(
        freeze,
        inputs,
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )


def _freeze_with_exclusions(changes: tuple[str, ...], exclusions: tuple[tuple[str, int], ...]) -> PopulationFreezeV3:
    base = _freeze(changes)
    draft = replace(base, exclusion_counts=exclusions, population_digest="", freeze_digest="")
    with_population = replace(draft, population_digest=content_digest(_population_value(draft)))
    return replace(
        with_population,
        freeze_digest=content_digest(_freeze_value(with_population, include_digest=False)),
    )


@pytest.mark.parametrize(
    "source",
    (
        b'x = 1\nopen("\\\\ProgramData\\\\service\\\\token.txt")\n',
        b"x = 1\r\n\\secret.txt",
        b"# \\secret.txt",
        b"// \\secret.txt",
        b"- \\secret.txt",
        rb"\u0061",
        rb"\uD83D\uDE00",
        rb'print("\u0061")',
        b"password=literal-used-by-a-security-test",
        b"https://example.test/path/in/source",
        b"private-label-0",
        b"invalid-utf8-\xff",
    ),
)
def test_arbitrary_approved_source_bytes_are_public_typed_objects(source: bytes) -> None:
    partition = _partition_with_source(source)
    manifest_bytes = materials.public_manifest_bytes(partition)
    manifest = json.loads(manifest_bytes)
    reference = next(item for item in partition.manifest.public_sources if item.change_digest == _digest("typed-source-0"))

    assert source not in manifest_bytes
    assert base64.b64encode(source) not in manifest_bytes
    assert "content_base64" not in manifest["public_sources"][0]
    assert materials.resolve_public_source(partition, reference) == source
    assert bytes_digest(materials.public_source_object_bytes(partition, reference)) == reference.object_digest


def test_manifest_is_metadata_only_and_has_no_path_or_payload_fields() -> None:
    partition = _partition_with_source(b"/home/operator/private.py\nC:\\Users\\operator\\source.py")
    manifest = json.loads(materials.public_manifest_bytes(partition))
    serialized = materials.public_manifest_bytes(partition)

    assert b"/home/" not in serialized
    assert b"C:\\\\Users" not in serialized
    assert b"content_base64" not in serialized
    assert b"path" not in serialized.lower()
    assert set(manifest["public_sources"][0]) == {
        "byte_length",
        "change_digest",
        "license_class",
        "license_expression",
        "object_digest",
        "source_digest",
    }

    unsafe_metadata = replace(partition.manifest, exclusion_counts=(("/home/operator/result", 0),))
    with pytest.raises(materials.PopulationMaterialError, match="full lowercase SHA-256"):
        materials.public_manifest_bytes(replace(partition, manifest=unsafe_metadata))


@pytest.mark.parametrize("reason", ("api_key_supersecret123", "repository_owner_project"))
def test_public_manifest_projects_open_freeze_reasons_to_safe_digests(reason: str) -> None:
    changes = tuple(_digest(f"reason-{index}") for index in range(3))
    freeze = _freeze_with_exclusions(changes, ((reason, 2),))
    partition = materials.build_population_material_partition(
        freeze,
        _inputs(changes),
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    manifest_bytes = materials.public_manifest_bytes(partition)
    manifest = json.loads(manifest_bytes)

    assert reason.encode() not in manifest_bytes
    assert manifest["exclusion_counts"] == [[content_digest({"exclusion_reason": reason}), 2]]


def test_multi_reason_projection_sorts_by_projected_digest() -> None:
    changes = tuple(_digest(f"multi-reason-{index}") for index in range(3))
    freeze = _freeze_with_exclusions(changes, (("r0", 1), ("r1", 2)))
    partition = materials.build_population_material_partition(
        freeze,
        _inputs(changes),
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    first = json.loads(materials.public_manifest_bytes(partition))["exclusion_counts"]
    second = json.loads(materials.public_manifest_bytes(partition))["exclusion_counts"]

    assert first == second == sorted(first)


def test_rehashed_duplicate_exclusion_digest_with_conflicting_counts_is_rejected() -> None:
    partition = _partition_with_source(b"duplicate-reason")
    reason_digest = content_digest({"exclusion_reason": "review_excluded"})
    exclusions = ((reason_digest, 1), (reason_digest, 2))
    draft = replace(partition.manifest, exclusion_counts=exclusions, manifest_digest="")
    manifest = replace(draft, manifest_digest=content_digest(materials._manifest_value(draft, include_digest=False)))

    with pytest.raises(materials.PopulationMaterialError, match="unique"):
        materials.public_manifest_bytes(replace(partition, manifest=manifest))


def test_exported_manifest_serialization_rejects_rehashed_dangling_public_ref() -> None:
    partition = _partition_with_source(b"bound-source")
    reference = partition.manifest.public_sources[0]
    tampered_ref = replace(reference, source_digest="0" * 64)
    draft = replace(partition.manifest, public_sources=(tampered_ref,), manifest_digest="")
    manifest = replace(draft, manifest_digest=content_digest(materials._manifest_value(draft, include_digest=False)))

    with pytest.raises(materials.PopulationMaterialError, match="references do not match"):
        materials.public_manifest_bytes(replace(partition, manifest=manifest))


def test_public_object_reference_and_bytes_are_exactly_bound() -> None:
    partition = _partition_with_source(b"source-object")
    reference = partition.manifest.public_sources[0]
    object_bytes = materials.public_source_object_bytes(partition, reference)
    value = json.loads(object_bytes)

    assert value["byte_length"] == len(b"source-object")
    assert value["source_digest"] == bytes_digest(b"source-object")
    assert base64.b64decode(value["content_base64"]) == b"source-object"

    for tampered in (
        replace(reference, source_digest="0" * 64),
        replace(reference, byte_length=reference.byte_length + 1),
        replace(reference, object_digest="0" * 64),
    ):
        with pytest.raises(materials.PopulationMaterialError):
            materials.public_source_object_bytes(partition, tampered)


def test_public_object_set_is_canonical_and_conflicts_on_any_changed_object() -> None:
    partition = _partition_with_source(b"canonical-source")
    artifacts = materials.material_artifact_bytes(partition)
    assert artifacts == materials.material_artifact_bytes(partition)

    public_value = json.loads(artifacts[1])
    public_value["content_base64"] = base64.b64encode(b"changed-source").decode()
    tampered = canonical_bytes(public_value)
    with pytest.raises(materials.PopulationMaterialConflict, match="different bytes"):
        materials.accept_population_material_partition(
            partition,
            existing=(artifacts[0], tampered, *artifacts[2:]),
        )


def test_nonpublic_license_and_distribution_decisions_remain_private() -> None:
    changes = tuple(_digest(f"private-decision-{index}") for index in range(3))
    freeze = _freeze(changes)
    inputs = list(_inputs(changes))
    inputs[0] = replace(inputs[0], public_distribution_approved=False)
    partition = materials.build_population_material_partition(
        freeze,
        inputs,
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    manifest = json.loads(materials.public_manifest_bytes(partition))

    assert manifest["public_count"] == 0
    assert manifest["private_count"] == 3
    assert materials.public_source_object_bytes_set(partition) == ()


@pytest.mark.parametrize(
    ("license_class", "license_expression"),
    (
        (materials.LicenseClass.NON_PERMISSIVE, "BUSL-1.1"),
        (materials.LicenseClass.UNCERTAIN, "NOASSERTION"),
    ),
)
def test_single_all_private_partition_has_no_zero_count_permissive_license(
    license_class: materials.LicenseClass,
    license_expression: str,
) -> None:
    change = _digest(f"all-private-{license_class.value}")
    freeze = _freeze((change,))
    item = materials.PopulationMaterialInputV1(
        change,
        license_class,
        license_expression,
        b"private source",
        b"label",
        b"judgment",
        True,
    )

    partition = materials.build_population_material_partition(
        freeze,
        (item,),
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    manifest = json.loads(materials.public_manifest_bytes(partition))

    assert manifest["public_count"] == 0
    assert manifest["private_count"] == 1
    assert manifest["license_partitions"] == [[license_class.value, 1]]
    assert len(manifest["private_refs"]) == 1
    assert materials.public_source_object_bytes_set(partition) == ()


def test_rehashed_boolean_public_count_is_rejected() -> None:
    partition = _partition_with_source(b"boolean-public-count")
    draft = replace(partition.manifest, public_count=True, manifest_digest="")
    manifest = replace(draft, manifest_digest=content_digest(materials._manifest_value(draft, include_digest=False)))

    with pytest.raises(materials.PopulationMaterialError, match="counts must be nonnegative integers"):
        materials.public_manifest_bytes(replace(partition, manifest=manifest))


def test_rehashed_false_public_count_is_rejected() -> None:
    change = _digest("false-public-count")
    freeze = _freeze((change,))
    item = materials.PopulationMaterialInputV1(
        change,
        materials.LicenseClass.NON_PERMISSIVE,
        "BUSL-1.1",
        b"private source",
        b"label",
        b"judgment",
        True,
    )
    partition = materials.build_population_material_partition(
        freeze,
        (item,),
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    draft = replace(partition.manifest, public_count=False, manifest_digest="")
    manifest = replace(draft, manifest_digest=content_digest(materials._manifest_value(draft, include_digest=False)))

    with pytest.raises(materials.PopulationMaterialError, match="counts must be nonnegative integers"):
        materials.public_manifest_bytes(replace(partition, manifest=manifest))


def test_rehashed_boolean_private_count_is_rejected() -> None:
    change = _digest("boolean-private-count")
    freeze = _freeze((change,))
    item = materials.PopulationMaterialInputV1(
        change,
        materials.LicenseClass.UNCERTAIN,
        "NOASSERTION",
        b"private source",
        b"label",
        b"judgment",
        True,
    )
    partition = materials.build_population_material_partition(
        freeze,
        (item,),
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    draft = replace(partition.manifest, private_count=True, manifest_digest="")
    manifest = replace(draft, manifest_digest=content_digest(materials._manifest_value(draft, include_digest=False)))

    with pytest.raises(materials.PopulationMaterialError, match="counts must be nonnegative integers"):
        materials.public_manifest_bytes(replace(partition, manifest=manifest))


def test_rehashed_false_private_count_is_rejected() -> None:
    change = _digest("false-private-count")
    freeze = _freeze((change,))
    item = materials.PopulationMaterialInputV1(
        change,
        materials.LicenseClass.PERMISSIVE,
        "MIT",
        b"public source",
        b"label",
        b"judgment",
        True,
    )
    partition = materials.build_population_material_partition(
        freeze,
        (item,),
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    draft = replace(partition.manifest, private_count=False, manifest_digest="")
    manifest = replace(draft, manifest_digest=content_digest(materials._manifest_value(draft, include_digest=False)))

    with pytest.raises(materials.PopulationMaterialError, match="counts must be nonnegative integers"):
        materials.public_manifest_bytes(replace(partition, manifest=manifest))
