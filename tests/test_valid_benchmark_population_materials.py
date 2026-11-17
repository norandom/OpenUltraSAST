"""Public/private/sealed partition tests for the replacement population."""

from __future__ import annotations

import base64
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import population_materials as materials  # noqa: E402
from benchmarks.valid.ecosystem_review import CanonicalEcosystem  # noqa: E402
from benchmarks.valid.population_freeze_contract import (  # noqa: E402
    PopulationClass,
    PopulationClassificationReason,
    PopulationFreezeV3,
    PopulationScopeCountV1,
    _freeze_value,
    _population_value,
    population_freeze_bytes,
)
from openultrasast.core.canonical import bytes_digest, canonical_bytes, content_digest  # noqa: E402


def _digest(label: str) -> str:
    return content_digest({"fixture": label})


def _percent_encoded(value: bytes) -> bytes:
    return b"".join(f"%{byte:02X}".encode("ascii") for byte in value)


def _freeze(changes: tuple[str, ...]) -> PopulationFreezeV3:
    changes = tuple(sorted(changes))
    scope_census = (PopulationScopeCountV1("injection", CanonicalEcosystem.PYTHON, len(changes)),)
    ecosystem_reviews = tuple(sorted(_digest(f"ecosystem-{index}") for index in range(len(changes))))
    ground_truth_reviews = tuple(sorted(_digest(f"truth-{index}") for index in range(len(changes))))
    draft = PopulationFreezeV3(
        PopulationClass.INSUFFICIENT,
        (
            PopulationClassificationReason.BELOW_MINIMUM_POSITIVES,
            PopulationClassificationReason.MISSING_ECOSYSTEM,
            PopulationClassificationReason.MISSING_SECOND_FAMILY,
        ),
        len(changes),
        (CanonicalEcosystem.PYTHON,),
        ("injection",),
        scope_census,
        (),
        changes,
        content_digest(
            {
                "accepted_changes": changes,
                "scope_census": tuple((item.vulnerability_family, item.ecosystem.value, item.count) for item in scope_census),
            }
        ),
        ecosystem_reviews,
        ground_truth_reviews,
        content_digest(
            {
                "ecosystem_reviews": ecosystem_reviews,
                "ground_truth_reviews": ground_truth_reviews,
            }
        ),
        _digest("ordinary-selection"),
        _digest("reservation-census"),
        (("excluded", 0),),
        _digest("provenance"),
        _digest("ecosystem-policy"),
        _digest("truth-policy"),
        _digest("freeze-policy"),
        "",
        "",
    )
    with_population = replace(draft, population_digest=content_digest(_population_value(draft)))
    return replace(with_population, freeze_digest=content_digest(_freeze_value(with_population, include_digest=False)))


class _Validator:
    def __init__(self, expected: PopulationFreezeV3) -> None:
        self.expected = expected
        self.calls = 0

    def validate(self, freeze: PopulationFreezeV3) -> bytes:
        self.calls += 1
        if freeze != self.expected:
            raise materials.PopulationMaterialError("freeze does not replay from exact authorities")
        return population_freeze_bytes(freeze)


def _inputs(changes: tuple[str, ...]) -> tuple[materials.PopulationMaterialInputV1, ...]:
    classes = (
        materials.LicenseClass.PERMISSIVE,
        materials.LicenseClass.NON_PERMISSIVE,
        materials.LicenseClass.UNCERTAIN,
    )
    return tuple(
        materials.PopulationMaterialInputV1(
            change,
            classes[index],
            ("Apache-2.0", "BUSL-1.1", "NOASSERTION")[index],
            (f"safe source {index}\n").encode(),
            (f"private-label-{index}").encode(),
            (f"review-judgment-{index}").encode(),
            index == 0,
        )
        for index, change in enumerate(changes)
    )


def _partition() -> tuple[materials.PopulationMaterialPartitionV1, _Validator]:
    changes = tuple(_digest(f"change-{index}") for index in range(3))
    freeze = _freeze(tuple(sorted(changes)))
    validator = _Validator(freeze)
    partition = materials.build_population_material_partition(
        freeze,
        _inputs(changes),
        freeze_validator=validator,
        partition_policy_digest=_digest("partition-policy"),
    )
    return partition, validator


def test_partitions_permissive_public_and_opaque_private_material_deterministically() -> None:
    first, validator = _partition()
    second, _ = _partition()

    assert validator.calls == 1
    assert materials.public_manifest_bytes(first) == materials.public_manifest_bytes(second)
    manifest = json.loads(materials.public_manifest_bytes(first))
    assert manifest["public_count"] == 1
    assert manifest["private_count"] == 2
    assert manifest["public_sources"][0]["license_class"] == "permissive"
    assert tuple(row["license_class"] for row in manifest["private_refs"]) == (
        "non_permissive",
        "uncertain",
    )
    public_ref = first.manifest.public_sources[0]
    assert "content_base64" not in manifest["public_sources"][0]
    assert manifest["public_sources"][0]["object_digest"] == public_ref.object_digest
    assert materials.resolve_public_source(first, public_ref) == b"safe source 0\n"
    assert materials.public_source_object_bytes(first, public_ref) == materials.public_source_object_bytes(second, public_ref)


def test_public_manifest_excludes_private_labels_judgments_paths_and_credentials() -> None:
    partition, _ = _partition()
    content = materials.public_manifest_bytes(partition)

    for forbidden in (
        b"private-label",
        b"review-judgment",
        b"BUSL-1.1",
        b"NOASSERTION",
        b"/home/",
        b"C:\\\\",
        b"AKIA0000000000000000",
    ):
        assert forbidden not in content
        assert base64.b64encode(forbidden) not in content

    for sealed in (b"private-label-0", b"review-judgment-0"):
        assert sealed.hex().encode() not in content
        assert _percent_encoded(sealed) not in content


def test_public_license_policy_is_closed_and_public_bytes_are_digest_bound() -> None:
    change = _digest("closed-license")
    freeze = _freeze((change,))
    unlisted = materials.PopulationMaterialInputV1(
        change, materials.LicenseClass.PERMISSIVE, "private-label", b"source", b"label", b"judgment", True
    )
    private = materials.build_population_material_partition(
        freeze,
        (unlisted,),
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("partition-policy"),
    )
    assert json.loads(materials.public_manifest_bytes(private))["public_count"] == 0

    partition, _ = _partition()
    source = partition.manifest.public_sources[0]
    tampered_source = replace(source, source_digest="0" * 64)
    tampered_manifest = replace(partition.manifest, public_sources=(tampered_source,))
    with pytest.raises(materials.PopulationMaterialError):
        materials.public_manifest_bytes(replace(partition, manifest=tampered_manifest))

    with pytest.raises(materials.PopulationMaterialError):
        materials.resolve_public_source(partition, replace(source, byte_length=source.byte_length + 1))

    with pytest.raises(materials.PopulationMaterialError):
        materials.resolve_private_material(
            partition,
            source,  # type: ignore[arg-type]
            materials.material_access_authority(
                partition,
                materials.MaterialActorRole.CUSTODIAN,
                (materials.MaterialPermission.PRIVATE_SOURCE,),
                _digest("access-policy"),
                expected_access_policy_digest=_digest("access-policy"),
            ),
            expected_access_policy_digest=_digest("access-policy"),
        )


def test_only_exact_custodian_authority_resolves_private_and_sealed_objects() -> None:
    partition, _ = _partition()
    manifest = json.loads(materials.public_manifest_bytes(partition))
    private_ref = partition.manifest.private_refs[0]
    custodian = materials.material_access_authority(
        partition,
        materials.MaterialActorRole.CUSTODIAN,
        (materials.MaterialPermission.PRIVATE_SOURCE, materials.MaterialPermission.SEALED_LABELS),
        _digest("access-policy"),
        expected_access_policy_digest=_digest("access-policy"),
    )

    assert materials.resolve_private_material(
        partition,
        private_ref,
        custodian,
        expected_access_policy_digest=_digest("access-policy"),
    ).startswith(b"safe source")
    assert materials.resolve_sealed_labels(
        partition,
        custodian,
        expected_access_policy_digest=_digest("access-policy"),
    ) == materials.sealed_label_object_bytes(partition)
    assert manifest["private_object_digest"] == bytes_digest(materials.private_object_bytes(partition))

    for role in (
        materials.MaterialActorRole.DETECTOR,
        materials.MaterialActorRole.PRESENTER,
        materials.MaterialActorRole.OPERATOR,
    ):
        authority = materials.material_access_authority(
            partition,
            role,
            (),
            _digest("access-policy"),
            expected_access_policy_digest=_digest("access-policy"),
        )
        with pytest.raises(materials.PopulationMaterialError, match="not authorized"):
            materials.resolve_private_material(
                partition,
                private_ref,
                authority,
                expected_access_policy_digest=_digest("access-policy"),
            )
        with pytest.raises(materials.PopulationMaterialError, match="not authorized"):
            materials.resolve_sealed_labels(
                partition,
                authority,
                expected_access_policy_digest=_digest("access-policy"),
            )


def test_opaque_reference_and_authority_tampering_are_refused() -> None:
    partition, _ = _partition()
    authority = materials.material_access_authority(
        partition,
        materials.MaterialActorRole.CUSTODIAN,
        (materials.MaterialPermission.PRIVATE_SOURCE,),
        _digest("access-policy"),
        expected_access_policy_digest=_digest("access-policy"),
    )
    reference = partition.manifest.private_refs[0]

    with pytest.raises(materials.PopulationMaterialError):
        materials.resolve_private_material(
            partition,
            replace(reference, source_digest="0" * 64),
            authority,
            expected_access_policy_digest=_digest("access-policy"),
        )
    with pytest.raises(materials.PopulationMaterialError):
        materials.resolve_private_material(
            partition,
            reference,
            replace(authority, population_digest="1" * 64),
            expected_access_policy_digest=_digest("access-policy"),
        )


def _tampered_authorities(
    authority: materials.MaterialAccessAuthorityV1,
) -> tuple[materials.MaterialAccessAuthorityV1, ...]:
    return (
        replace(authority, freeze_digest="0" * 64),
        replace(authority, manifest_digest="0" * 64),
        replace(authority, partition_policy_digest="0" * 64),
        replace(authority, private_object_digest="0" * 64),
        replace(authority, sealed_label_digest="0" * 64),
    )


def test_custodian_authority_is_bound_to_the_exact_partition_and_every_object() -> None:
    first, _ = _partition()
    changes = first.manifest.positive_change_digests
    freeze = _freeze(changes)
    changed_inputs = list(_inputs(changes))
    changed_inputs[0] = replace(changed_inputs[0], label_content=b"different-sealed-label")
    changed_inputs[1] = replace(changed_inputs[1], source_content=b"different-private-source")
    second = materials.build_population_material_partition(
        freeze,
        changed_inputs,
        freeze_validator=_Validator(freeze),
        partition_policy_digest=_digest("different-partition-policy"),
    )
    authority = materials.material_access_authority(
        first,
        materials.MaterialActorRole.CUSTODIAN,
        (materials.MaterialPermission.PRIVATE_SOURCE, materials.MaterialPermission.SEALED_LABELS),
        _digest("access-policy"),
        expected_access_policy_digest=_digest("access-policy"),
    )

    assert authority.freeze_digest == first.manifest.freeze_digest
    assert authority.manifest_digest == first.manifest.manifest_digest
    assert authority.partition_policy_digest == first.manifest.partition_policy_digest
    assert authority.private_object_digest == first.manifest.private_object_digest
    assert authority.sealed_label_digest == first.manifest.sealed_label_digest
    with pytest.raises(materials.PopulationMaterialError, match="not authorized"):
        materials.resolve_private_material(
            second,
            second.manifest.private_refs[0],
            authority,
            expected_access_policy_digest=_digest("access-policy"),
        )
    with pytest.raises(materials.PopulationMaterialError, match="not authorized"):
        materials.resolve_sealed_labels(
            second,
            authority,
            expected_access_policy_digest=_digest("access-policy"),
        )

    for tampered in _tampered_authorities(authority):
        with pytest.raises(materials.PopulationMaterialError):
            materials.resolve_sealed_labels(
                first,
                tampered,
                expected_access_policy_digest=_digest("access-policy"),
            )


def test_access_policy_expectation_is_independent_and_required_at_every_boundary() -> None:
    partition, _ = _partition()
    reference = partition.manifest.private_refs[0]
    expected = _digest("access-policy")
    wrong = _digest("wrong-access-policy")

    with pytest.raises(materials.PopulationMaterialError, match="access policy"):
        materials.material_access_authority(
            partition,
            materials.MaterialActorRole.CUSTODIAN,
            (materials.MaterialPermission.PRIVATE_SOURCE,),
            wrong,
            expected_access_policy_digest=expected,
        )
    wrong_authority = materials.material_access_authority(
        partition,
        materials.MaterialActorRole.CUSTODIAN,
        (materials.MaterialPermission.PRIVATE_SOURCE, materials.MaterialPermission.SEALED_LABELS),
        wrong,
        expected_access_policy_digest=wrong,
    )
    with pytest.raises(materials.PopulationMaterialError, match="not authorized"):
        materials.resolve_private_material(
            partition,
            reference,
            wrong_authority,
            expected_access_policy_digest=expected,
        )
    with pytest.raises(TypeError):
        materials.resolve_private_material(partition, reference, wrong_authority)  # type: ignore[call-arg]
    with pytest.raises(materials.PopulationMaterialError, match="not authorized"):
        materials.resolve_sealed_labels(
            partition,
            wrong_authority,
            expected_access_policy_digest=expected,
        )
    with pytest.raises(TypeError):
        materials.resolve_sealed_labels(partition, wrong_authority)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        materials.material_access_authority(  # type: ignore[call-arg]
            partition,
            materials.MaterialActorRole.CUSTODIAN,
            (materials.MaterialPermission.PRIVATE_SOURCE,),
            expected,
        )


def test_material_set_must_match_exact_freeze_and_all_bytes_are_nonempty() -> None:
    changes = (_digest("one"), _digest("two"))
    freeze = _freeze(changes)
    item = materials.PopulationMaterialInputV1(changes[0], materials.LicenseClass.PERMISSIVE, "MIT", b"source", b"label", b"judgment", True)

    with pytest.raises(materials.PopulationMaterialError, match="exact positive set"):
        materials.build_population_material_partition(
            freeze,
            (item,),
            freeze_validator=_Validator(freeze),
            partition_policy_digest=_digest("partition-policy"),
        )
    with pytest.raises(materials.PopulationMaterialError, match="nonempty"):
        materials.build_population_material_partition(
            _freeze((changes[0],)),
            (replace(item, label_content=b""),),
            freeze_validator=_Validator(_freeze((changes[0],))),
            partition_policy_digest=_digest("partition-policy"),
        )


def test_exact_freeze_replay_is_required_and_tampered_freeze_is_refused() -> None:
    partition, validator = _partition()
    freeze = _freeze(partition.manifest.positive_change_digests)

    assert validator.calls == 1
    with pytest.raises(materials.PopulationMaterialError, match="freeze"):
        materials.build_population_material_partition(
            replace(freeze, reservation_census_digest=_digest("stale-census")),
            _inputs(partition.manifest.positive_change_digests),
            freeze_validator=_Validator(freeze),
            partition_policy_digest=_digest("partition-policy"),
        )


def test_same_identity_different_bytes_conflicts_and_summary_is_redacted() -> None:
    partition, _ = _partition()
    accepted = materials.accept_population_material_partition(partition)
    existing = materials.material_artifact_bytes(partition)

    assert materials.accept_population_material_partition(partition, existing=existing) == accepted
    assert len(existing) == 4
    with pytest.raises(materials.PopulationMaterialConflict, match="different bytes"):
        materials.accept_population_material_partition(partition, existing=(*existing[:-1], existing[-1] + b"\n"))

    public_object = json.loads(existing[1])
    public_object["schema_version"] = "wrong"
    changed_schema = canonical_bytes(public_object)
    with pytest.raises(materials.PopulationMaterialConflict, match="different bytes"):
        materials.accept_population_material_partition(partition, existing=(existing[0], changed_schema, *existing[2:]))

    summary = materials.operator_material_summary(partition)
    assert json.loads(summary)["status"] == "partitioned"
    assert b"private-label" not in summary
    assert b"review-judgment" not in summary
    assert b"safe source" not in summary
    assert b"content_base64" not in summary
