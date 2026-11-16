"""Causal projection for immutable population lifecycle events."""

from __future__ import annotations

from collections.abc import Iterable

from benchmarks.valid.lifecycle import (
    LIFECYCLE_PROJECTION_SCHEMA,
    LifecycleConflict,
    LifecycleError,
    PopulationLifecycleEventV1,
    PopulationLifecycleKind,
    PopulationLifecycleProjectionV1,
    PopulationLifecycleState,
    decode_lifecycle_event,
)
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes
from openultrasast.core.canonical import JsonValue, content_digest


def _projection_value(projection: PopulationLifecycleProjectionV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": LIFECYCLE_PROJECTION_SCHEMA,
        "state": projection.state.value,
        "historical_withdrawal_digest": projection.historical_withdrawal_digest,
        "population_digest": projection.population_digest,
        "freeze_digest": projection.freeze_digest,
        "head_event_digest": projection.head_event_digest,
        "event_digests": projection.event_digests,
        "influence_event_digests": projection.influence_event_digests,
        "admission_eligible": projection.admission_eligible,
    }
    if include_digest:
        value["projection_digest"] = projection.projection_digest
    return value


def projection_bytes(projection: PopulationLifecycleProjectionV1) -> bytes:
    expected = content_digest(_projection_value(projection, include_digest=False))
    if projection.projection_digest != expected:
        raise LifecycleError("lifecycle projection digest does not match")
    eligible = projection.state is PopulationLifecycleState.REPLACEMENT_COMPLETE
    if projection.admission_eligible is not eligible:
        raise LifecycleError("lifecycle projection eligibility does not match state")
    return canonical_json_bytes(_projection_value(projection, include_digest=True))


def _events_by_digest(contents: Iterable[bytes]) -> dict[str, tuple[PopulationLifecycleEventV1, bytes]]:
    events: dict[str, tuple[PopulationLifecycleEventV1, bytes]] = {}
    for content in contents:
        event = decode_lifecycle_event(content)
        existing = events.get(event.event_digest)
        if existing is not None and existing[1] != content:
            raise LifecycleConflict("same lifecycle identity has different bytes")
        events[event.event_digest] = (event, content)
    if not events:
        raise LifecycleConflict("lifecycle requires one withdrawn root")
    return events


def _ordered_chain(events: dict[str, tuple[PopulationLifecycleEventV1, bytes]]) -> tuple[PopulationLifecycleEventV1, ...]:
    roots = [event for event, _ in events.values() if event.predecessor_digest is None]
    if len(roots) != 1 or roots[0].kind is not PopulationLifecycleKind.WITHDRAWN or roots[0].historical_withdrawal_digest is None:
        raise LifecycleConflict("lifecycle requires exactly one withdrawn root")
    successors: dict[str, PopulationLifecycleEventV1] = {}
    for event, _ in events.values():
        if event.predecessor_digest is None:
            continue
        if event.predecessor_digest not in events:
            raise LifecycleConflict("lifecycle predecessor is missing")
        if event.predecessor_digest in successors:
            raise LifecycleConflict("lifecycle predecessor has a fork")
        successors[event.predecessor_digest] = event
    ordered = [roots[0]]
    while ordered[-1].event_digest in successors:
        ordered.append(successors[ordered[-1].event_digest])
    if len(ordered) != len(events):
        raise LifecycleConflict("lifecycle events do not form one complete chain")
    return tuple(ordered)


def _transition(previous: PopulationLifecycleEventV1, event: PopulationLifecycleEventV1, root: str) -> None:
    if previous.kind in {PopulationLifecycleKind.RETIRED, PopulationLifecycleKind.DEVELOPMENT_OPENED}:
        raise LifecycleConflict("terminal lifecycle state cannot have a successor")
    if previous.kind is PopulationLifecycleKind.WITHDRAWN:
        if event.kind is not PopulationLifecycleKind.REPLACEMENT_BOUND:
            raise LifecycleConflict("withdrawal requires exact replacement binding")
        if event.historical_withdrawal_digest != root:
            raise LifecycleConflict("replacement does not bind exact historical withdrawal")
        return
    if previous.kind is not PopulationLifecycleKind.REPLACEMENT_BOUND:
        raise LifecycleConflict("unsupported lifecycle transition")
    if event.kind not in {PopulationLifecycleKind.RETIRED, PopulationLifecycleKind.DEVELOPMENT_OPENED}:
        raise LifecycleConflict("active replacement accepts only terminal transitions")
    if (event.population_digest, event.freeze_digest) != (previous.population_digest, previous.freeze_digest):
        raise LifecycleConflict("terminal event population or freeze identity conflicts")


def _state(head: PopulationLifecycleEventV1) -> PopulationLifecycleState:
    return {
        PopulationLifecycleKind.WITHDRAWN: PopulationLifecycleState.REPLACEMENT_PENDING,
        PopulationLifecycleKind.REPLACEMENT_BOUND: PopulationLifecycleState.REPLACEMENT_COMPLETE,
        PopulationLifecycleKind.RETIRED: PopulationLifecycleState.RETIRED,
        PopulationLifecycleKind.DEVELOPMENT_OPENED: PopulationLifecycleState.DEVELOPMENT_OPENED,
    }[head.kind]


def _projection(ordered: tuple[PopulationLifecycleEventV1, ...]) -> PopulationLifecycleProjectionV1:
    root = ordered[0]
    if root.historical_withdrawal_digest is None:
        raise LifecycleConflict("withdrawn root lacks historical withdrawal identity")
    for previous, event in zip(ordered, ordered[1:], strict=False):
        _transition(previous, event, root.historical_withdrawal_digest)
    head = ordered[-1]
    replacement = next((event for event in ordered if event.kind is PopulationLifecycleKind.REPLACEMENT_BOUND), None)
    state = _state(head)
    draft = PopulationLifecycleProjectionV1(
        state,
        root.historical_withdrawal_digest,
        replacement.population_digest if replacement else None,
        replacement.freeze_digest if replacement else None,
        head.event_digest,
        tuple(event.event_digest for event in ordered),
        tuple(sorted({digest for event in ordered for digest in event.influence_event_digests})),
        state is PopulationLifecycleState.REPLACEMENT_COMPLETE,
        "",
    )
    return PopulationLifecycleProjectionV1(
        **{**vars(draft), "projection_digest": content_digest(_projection_value(draft, include_digest=False))}
    )


class BaselineLifecycleAuthority:
    """Append reviewed events and rebuild one exact causal projection."""

    def __init__(self) -> None:
        self._contents_by_digest: dict[str, bytes] = {}

    def project(self, contents: Iterable[bytes]) -> PopulationLifecycleProjectionV1:
        return _projection(_ordered_chain(_events_by_digest(contents)))

    def append(self, content: bytes) -> PopulationLifecycleProjectionV1:
        event = decode_lifecycle_event(content)
        existing = self._contents_by_digest.get(event.event_digest)
        if existing is not None and existing != content:
            raise LifecycleConflict("same lifecycle identity has different bytes")
        candidate = {**self._contents_by_digest, event.event_digest: content}
        projection = self.project(candidate.values())
        self._contents_by_digest = candidate
        return projection

    def require_admission_eligible(
        self,
        population_digest: str,
        freeze_digest: str,
    ) -> PopulationLifecycleProjectionV1:
        if not self._contents_by_digest:
            raise LifecycleError("baseline is not admission eligible")
        projection = self.project(self._contents_by_digest.values())
        exact = (projection.population_digest, projection.freeze_digest) == (population_digest, freeze_digest)
        if not projection.admission_eligible or not exact:
            raise LifecycleError("baseline is not admission eligible for exact population and freeze")
        return projection


__all__ = ["BaselineLifecycleAuthority", "projection_bytes"]
