"""Task 11.3 conversion adapter: closed refusal surface (first slice).

The full end-to-end conversion suite drives the committed 8.1-8.5 chain over
the group-10 population; this slice pins the adapter's closed refusal surface
and stage wiring before that lifecycle runs.
"""

from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_core_fixtures import stored_artifact  # noqa: E402
from test_valid_benchmark_admission_execution import _case  # noqa: E402
from test_valid_benchmark_admission_replay import _core_context  # noqa: E402
from test_valid_benchmark_admission_spend import _SpendEnv  # noqa: E402
from test_valid_benchmark_orchestrator import _attestation, _digest  # noqa: E402

from benchmarks.valid.admission_case_adapter import (  # noqa: E402
    bind_case_adapter_replay_stage,
    derive_case_adapter_replay,
)
from benchmarks.valid.admission_case_graph import (  # noqa: E402
    AdmissionAdapterError,
    AdmissionAdapterReason,
    AdmissionCaseAdapterRequestV1,
    validate_adapter_request,
)
from benchmarks.valid.admission_spend import AdmissionSpendReleaseV1  # noqa: E402


@lru_cache(maxsize=1)
def _environment():
    environment = _SpendEnv(_case())
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="adapter-conflicts")
    context, _custody_policy = _core_context()
    request = AdmissionCaseAdapterRequestV1(
        repository=environment.repository,
        custodian_access_policy_digest=_digest("adapter-access-policy"),
        execution=environment.product,
        plan=environment.case.plan,
        selection=environment.case.selection,
        population_digest=environment.case.freeze.population_digest,
        input_count=len(environment.case.manifest.input_digests),
        custody=environment.custody,
        resolver=resolver,
        context=context,
        readiness=(),
        case_content=lambda *_args, **_kwargs: None,
        proof_candidates=lambda *_args, **_kwargs: None,
        census_review=_attestation(_digest("census"), _digest("producer"), disclosure),
        plan_review=_attestation(_digest("plan"), _digest("producer"), disclosure),
        admission_review=lambda subject: _attestation(subject, _digest("producer"), disclosure),
        release_review=lambda subject: _attestation(subject, _digest("producer"), disclosure),
        bridged_store_identity="adapter-bridge",
        bridged_retention_policy_digest=_digest("adapter-retention"),
    )
    return request


def test_request_missing_readiness_is_refused_with_a_closed_reason() -> None:
    with pytest.raises(AdmissionAdapterError) as raised:
        validate_adapter_request(_environment())
    assert raised.value.reason is AdmissionAdapterReason.INVALID_REQUEST


def test_refused_spend_release_never_reaches_the_core_boundary() -> None:
    request = _environment()
    validate_adapter_request(_replace_readiness(request))
    refused = AdmissionSpendReleaseV1("labels_unreadable", "", False, 0, "", (), None, "")
    stage = bind_case_adapter_replay_stage(_replace_readiness(request))
    with pytest.raises(AdmissionAdapterError) as raised:
        derive_case_adapter_replay(_replace_readiness(request), refused)
    assert raised.value.reason is AdmissionAdapterReason.RELEASE_REFUSED
    assert callable(stage)


def _replace_readiness(request: AdmissionCaseAdapterRequestV1) -> AdmissionCaseAdapterRequestV1:
    from dataclasses import replace

    from test_core_readiness import _chain as _readiness_chain
    from test_valid_benchmark_admission_replay import _BridgeEnv  # noqa: F401  (readiness source)

    return replace(request, readiness=tuple(_readiness_chain()))
