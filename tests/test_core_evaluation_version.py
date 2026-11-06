"""Evaluation-admission V3 version and partial-authority boundary."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from dataclasses import replace
from functools import partial, wraps

import pytest

from openultrasast.core import admission, canonical
from openultrasast.core.admission_report import ADMISSION_REPLAY_SCHEMA, AdmissionReportV2
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationContractVersion,
    EvaluationV3Contract,
    EvaluationVersionError,
    NonAuthorizingV3,
    PartialArtifactKindV3,
    PartialEvaluationArtifactV3,
    require_exact_v3_contract,
    require_v3_child_schema,
    route_evaluation_schema,
)


def _partial(kind: PartialArtifactKindV3 = PartialArtifactKindV3.FEASIBILITY) -> PartialEvaluationArtifactV3:
    return PartialEvaluationArtifactV3(
        evaluation_schema=EVALUATION_ADMISSION_V3_SCHEMA,
        kind=kind,
        artifact_digest=canonical.content_digest(kind.value),
    )


def test_exact_v3_root_identity_is_the_only_v3_route() -> None:
    assert EVALUATION_ADMISSION_V3_SCHEMA == "openultrasast.detection-core.evaluation-admission.v3"
    assert route_evaluation_schema(EVALUATION_ADMISSION_V3_SCHEMA) is EvaluationContractVersion.V3

    with pytest.raises(EvaluationVersionError, match="V2.*new V3 baseline"):
        route_evaluation_schema(ADMISSION_REPLAY_SCHEMA)
    with pytest.raises(EvaluationVersionError, match="unknown evaluation schema"):
        route_evaluation_schema("openultrasast.detection-core.evaluation-admission.v4")
    with pytest.raises(EvaluationVersionError, match="schema must be exact text"):
        route_evaluation_schema(None)  # type: ignore[arg-type]


def test_v2_facade_names_and_routes_remain_separate_and_unchanged() -> None:
    assert admission.ADMISSION_REPLAY_SCHEMA == "openultrasast.detection-core.admission-replay.v2"
    assert admission.ADMISSION_REPORT_SCHEMA == "openultrasast.detection-core.admission-report.v2"
    assert admission.AdmissionReplay.__module__ == "openultrasast.core._admission_replay"
    assert admission.AdmissionReportV2.__module__ == "openultrasast.core.admission_report"
    assert "EVALUATION_ADMISSION_V3_SCHEMA" not in admission.__all__


def test_exact_contract_and_child_guards_refuse_subclasses_and_mixed_versions() -> None:
    partial = _partial()
    require_exact_v3_contract(partial, PartialEvaluationArtifactV3, field="partial")
    require_v3_child_schema(EVALUATION_ADMISSION_V3_SCHEMA, field="partial")

    class DerivedPartial(PartialEvaluationArtifactV3):
        pass

    with pytest.raises(EvaluationVersionError, match="exact PartialEvaluationArtifactV3"):
        DerivedPartial(
            EVALUATION_ADMISSION_V3_SCHEMA,
            PartialArtifactKindV3.FEASIBILITY,
            canonical.content_digest("derived"),
        )
    with pytest.raises(EvaluationVersionError, match="mixed or incompatible"):
        require_v3_child_schema(ADMISSION_REPLAY_SCHEMA, field="report")
    with pytest.raises(EvaluationVersionError, match="mixed or incompatible"):
        require_v3_child_schema("openultrasast.detection-core.evaluation-admission.v4", field="report")


def test_every_partial_kind_is_exactly_non_authorizing() -> None:
    for kind in PartialArtifactKindV3:
        partial = _partial(kind)
        assert isinstance(partial, NonAuthorizingV3)
        assert partial.kind is kind
        assert not hasattr(partial, "authorize")
        assert not hasattr(partial, "authorization")
        assert not hasattr(partial, "consumer_authority")

    with pytest.raises(TypeError, match="non-authorizing V3 artifacts cannot declare"):

        class InvalidPartial(NonAuthorizingV3):
            def authorize(self) -> None:
                pass


def test_partial_contract_rejects_wrong_version_kind_digest_and_rehash() -> None:
    partial = _partial()
    with pytest.raises(EvaluationVersionError, match="mixed or incompatible"):
        replace(partial, evaluation_schema=ADMISSION_REPLAY_SCHEMA)
    with pytest.raises(EvaluationVersionError, match="closed PartialArtifactKindV3"):
        replace(partial, kind="feasibility")  # type: ignore[arg-type]
    with pytest.raises(EvaluationVersionError, match="lowercase SHA-256"):
        replace(partial, artifact_digest="not-a-digest")


def test_exact_contract_guard_rejects_v2_arbitrary_and_marker_spoof_types() -> None:
    v2_report = object.__new__(AdmissionReportV2)
    with pytest.raises(EvaluationVersionError, match="registered V3 contract"):
        require_exact_v3_contract(v2_report, AdmissionReportV2, field="report")

    class Arbitrary:
        pass

    with pytest.raises(EvaluationVersionError, match="registered V3 contract"):
        require_exact_v3_contract(Arbitrary(), Arbitrary, field="arbitrary")

    class SpoofedMarker:
        __evaluation_v3_contract__ = True

    with pytest.raises(EvaluationVersionError, match="registered V3 contract"):
        require_exact_v3_contract(SpoofedMarker(), SpoofedMarker, field="spoof")

    class EqualitySpoofMeta(type):
        def __hash__(cls) -> int:
            return hash(PartialEvaluationArtifactV3)

        def __eq__(cls, other: object) -> bool:
            return other is PartialEvaluationArtifactV3

    class EqualitySpoof(metaclass=EqualitySpoofMeta):
        pass

    with pytest.raises(EvaluationVersionError, match="registered V3 contract"):
        require_exact_v3_contract(EqualitySpoof(), EqualitySpoof, field="equality spoof")

    with pytest.raises(EvaluationVersionError, match="runtime type"):
        require_exact_v3_contract(_partial(), "PartialEvaluationArtifactV3", field="partial")  # type: ignore[arg-type]
    with pytest.raises(EvaluationVersionError, match="nonempty exact text"):
        require_exact_v3_contract(_partial(), PartialEvaluationArtifactV3, field="")


def test_later_evaluation_modules_have_an_intentional_closed_registration_path() -> None:
    class RepresentativePlanContract(EvaluationV3Contract):
        __module__ = "openultrasast.core.evaluation_plan"
        __evaluation_v3_contract_schema__ = EVALUATION_ADMISSION_V3_SCHEMA

    value = RepresentativePlanContract()
    assert require_exact_v3_contract(value, RepresentativePlanContract, field="plan") is value

    class UnmarkedPlanContract(EvaluationV3Contract):
        __module__ = "openultrasast.core.evaluation_plan"

    with pytest.raises(EvaluationVersionError, match="registered V3 contract"):
        require_exact_v3_contract(UnmarkedPlanContract(), UnmarkedPlanContract, field="unmarked plan")

    class WrongOwnerContract(EvaluationV3Contract):
        __evaluation_v3_contract_schema__ = EVALUATION_ADMISSION_V3_SCHEMA

    with pytest.raises(EvaluationVersionError, match="registered V3 contract"):
        require_exact_v3_contract(WrongOwnerContract(), WrongOwnerContract, field="wrong owner")


def test_non_authorizing_marker_rejects_inherited_authority_capabilities() -> None:
    class AuthorizingBase:
        def authorize(self) -> None:
            pass

    with pytest.raises(TypeError, match="non-authorizing V3 artifacts cannot declare"):

        class InheritedAuthorize(NonAuthorizingV3, AuthorizingBase):
            pass

    class AuthorizationPropertyBase:
        @property
        def authorization(self) -> str:
            return "forbidden"

    with pytest.raises(TypeError, match="non-authorizing V3 artifacts cannot declare"):

        class InheritedProperty(AuthorizationPropertyBase, NonAuthorizingV3):
            pass

    class CallableBase:
        def __call__(self) -> None:
            pass

    with pytest.raises(TypeError, match="non-authorizing V3 artifacts cannot declare"):

        class InheritedCallable(CallableBase, NonAuthorizingV3):
            pass


def test_non_authorizing_marker_rejects_inherited_fields_descriptors_and_aliases() -> None:
    from dataclasses import dataclass

    @dataclass
    class AuthorizationFieldBase:
        consumer_authority: str

    with pytest.raises(TypeError, match="consumer_authority"):

        class InheritedField(NonAuthorizingV3, AuthorizationFieldBase):
            pass

    class AuthorityDescriptor:
        def __get__(self, instance: object, owner: type[object]) -> object:
            return self

    class DescriptorBase:
        authorization = AuthorityDescriptor()

    with pytest.raises(TypeError, match="authorization"):

        class InheritedDescriptor(NonAuthorizingV3, DescriptorBase):
            pass

    def authorize() -> None:
        pass

    with pytest.raises(TypeError, match="authority_alias"):

        class AliasedCapability(NonAuthorizingV3):
            authority_alias = staticmethod(authorize)


def test_registration_rejects_non_string_schema_equality_spoof() -> None:
    class EqualSchema:
        def __eq__(self, other: object) -> bool:
            return other == EVALUATION_ADMISSION_V3_SCHEMA

    class SchemaEqualitySpoof(EvaluationV3Contract):
        __module__ = "openultrasast.core.evaluation_plan"
        __evaluation_v3_contract_schema__ = EqualSchema()

    with pytest.raises(EvaluationVersionError, match="registered V3 contract"):
        require_exact_v3_contract(SchemaEqualitySpoof(), SchemaEqualitySpoof, field="schema spoof")


def test_non_authorizing_marker_rejects_partial_and_wrapped_authority_aliases() -> None:
    def authorize_consumer() -> None:
        pass

    with pytest.raises(TypeError, match="partial_alias"):

        class PartialAlias(NonAuthorizingV3):
            partial_alias = partial(authorize_consumer)

    def harmless_wrapper() -> None:
        pass

    wrapped_authority = wraps(authorize_consumer)(harmless_wrapper)
    with pytest.raises(TypeError, match="wrapped_alias"):

        class WrappedAlias(NonAuthorizingV3):
            wrapped_alias = staticmethod(wrapped_authority)


def test_non_authorizing_marker_rejects_post_class_authority_injection() -> None:
    def authorize_consumer() -> None:
        pass

    with pytest.raises(TypeError, match="authorize"):
        NonAuthorizingV3.authorize = authorize_consumer  # type: ignore[attr-defined]
    with pytest.raises(TypeError, match="consumer_authority"):
        PartialEvaluationArtifactV3.consumer_authority = property(lambda self: "forbidden")  # type: ignore[attr-defined]
    with pytest.raises(TypeError, match="partial_alias"):
        PartialEvaluationArtifactV3.partial_alias = partial(authorize_consumer)  # type: ignore[attr-defined]

    class HarmlessPartial(NonAuthorizingV3):
        pass

    HarmlessPartial.display_label = "partial"  # type: ignore[attr-defined]
    assert HarmlessPartial.display_label == "partial"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("assignment", "attribute"),
    (
        ("EvaluationV3Contract.authorize = authorize_consumer", "authorize"),
        ("EvaluationV3Contract.wrapped_alias = staticmethod(wrapped_authority)", "wrapped_alias"),
    ),
)
def test_authority_cannot_be_injected_through_a_shared_contract_base(assignment: str, attribute: str) -> None:
    program = textwrap.dedent(
        f"""
        from functools import wraps
        from openultrasast.core.evaluation_version import EvaluationV3Contract, PartialEvaluationArtifactV3

        def authorize_consumer():
            pass

        def harmless_wrapper():
            pass

        wrapped_authority = wraps(authorize_consumer)(harmless_wrapper)
        try:
            {assignment}
        except TypeError:
            pass
        else:
            raise AssertionError("shared-base authority assignment was accepted")
        assert not hasattr(PartialEvaluationArtifactV3, {attribute!r})
        EvaluationV3Contract.display_label = "evaluation-v3"
        assert PartialEvaluationArtifactV3.display_label == "evaluation-v3"
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", program],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
