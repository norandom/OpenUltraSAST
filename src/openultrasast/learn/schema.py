"""The candidate feature record: a closed, typed allow-list (learned-decision-engine Req 1, 7.2; design section 1).

A candidate is ``(repo, pin, path, function, family)``. That key lives in the record's envelope, for joining labels
and grouping folds, and is never a feature. The features are the closed list :data:`FEATURES`: each has a name, the
instrument that produces it, a type (``bool``, ``int`` with a cap, ``float`` in [0, 1], or ``enum`` over a closed
vocabulary), a profile (``static``: what ``scan``/``pre-push`` compute locally without a model; ``plane``: adds
verify, agree and model roles) and whether it is a framework *prior* (Req 8.2). There is no free text, no
identifier and no raw count of a repository-specific token: rule ids enter only through the closed mechanism
buckets and the prior count, because a rule written after one case's miss would otherwise name that case.

**Missing is not negative (Req 1.2).** A record carries ``instruments: {name: {state, version}}`` with ``state`` in
:data:`STATES`:

- ``ran``: the instrument read its input for this candidate; its features hold values (``0`` is a real zero);
- ``none``: no coverage -- the instrument has no rule/model for the language, or it was not part of the run;
- ``failed``: the instrument broke or did not demonstrably read its input (never zero findings);
- ``not_applicable``: ``delta.*`` on a whole-repository scan, ``facts.*`` on a pair excerpt.

Every feature of an instrument whose state is not ``ran`` is ``null``. A feature of an instrument that ran is
``null`` only where the spec says ``nullable`` (a minimum over no findings, an answer to a pass never asked).
At training time a ``null`` becomes 0 plus one indicator ``missing.<instrument>`` per instrument.

**Excluded** (label information or identities, :data:`EXCLUDED_FIELDS`): ``site_match``, ``in_fix_range``, every
fixed-pin alert, declared sites and ``case.json``, costs, rule ids, paths, file and function names, commit ids and
repository names. :func:`validate_record` rejects them anywhere in a record's features, and the builders drop them on
read.

Versioning: :data:`SCHEMA_VERSION` (bumped on any spec change) and :func:`feature_set_digest` (sha256 of the
canonical :data:`FEATURES`), recorded in every record, so a model trained on one feature set never scores another.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any, Literal

SCHEMA_VERSION = 1
PROFILES = ("static", "plane")
STATES = ("ran", "none", "failed", "not_applicable")
UNITS = ("pin", "delta")
Profile = Literal["static", "plane"]
FeatureType = Literal["bool", "int", "float", "enum"]

# The instruments, in record order. `language` always runs (it is the file's extension).
INSTRUMENTS = (
    "language", "quick", "engine", "facts", "source", "entry_points", "roles", "delta", "verify", "agree", "model_sinks",
)  # fmt: skip

# The languages the engine or quick mode covers; anything else is `other` (a one-hot, never a name).
LANGUAGES = ("c", "cpp", "groovy", "java", "javascript", "php", "python", "typescript", "other")

# The closed mechanism vocabulary: the ids of `benchmarks/pairs/mechanisms.toml` (a test keeps them equal).
MECHANISMS = (
    "source_reaches_sink", "container_taint", "config_sink_weak_literal", "unchecked_length_copy", "unchecked_alloc_size",
    "null_deref_unguarded", "signed_size_operand", "fixed_buffer_capacity", "identity_from_request_body",
    "missing_auth_guard", "secret_in_client", "permissive_default", "path_join_user_input", "prototype_pollution", "redos",
    "uaf", "type_confusion", "validation_strength", "cross_artifact", "unconstrained_protected_read",
    "unconstrained_protected_write", "unguarded_privileged_action", "other",
)  # fmt: skip

# A quick rule's `tags` mapped into the mechanism vocabulary; an unmapped tag counts as `other`.
RULE_TAG_MECHANISM = {
    "injection": "source_reaches_sink",
    "syscall_entry": "source_reaches_sink",
    "deserialization": "source_reaches_sink",
    "network_entry": "source_reaches_sink",
    "filesystem_entry": "path_join_user_input",
    "memory_unsafe": "unchecked_length_copy",
    "crypto": "config_sink_weak_literal",
    "insecure_default": "permissive_default",
}

RUNGS = ("suspicion", "model_corroborated", "model_entailed", "execution_confirmed")
OPERATIONS = (
    "sql", "command", "code_eval", "deserialize", "file_path", "file_inclusion", "outbound_request", "redirect", "html_output",
    "other",
)  # fmt: skip
SOURCE_KINDS = ("request", "server", "raw_body", "argv_stdin", "inferred_role", "prior", "other")
ORIGINS = ("language", "inferred_wrapper", "model_role", "prior")
NOVELTY = ("new", "worsened", "unchanged", "unknown", "not_applicable")
FINALS = ("agreed", "disputed", "rejected")

# Fields that carry label information or an identity. None may be a feature; builders drop them on read.
EXCLUDED_FIELDS = frozenset(
    {
        "site_match", "in_fix_range", "fixed_ranges", "ranges", "sites", "declared_sites", "case", "case_json",
        "usd", "cost", "rule_id", "rule_ids", "path", "file", "function", "candidate", "repo", "repository", "pin",
        "commit", "base", "sha", "title", "witness", "site", "reported_at",
    }
)  # fmt: skip


class FeatureRecordError(ValueError):
    """A record names a feature outside the allow-list, a value outside its type, or a label/identity field."""


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    instrument: str
    type: FeatureType
    profile: Profile
    cap: int | None = None  # int: the value is clipped to [0, cap]
    vocabulary: tuple[str, ...] = ()  # enum: the closed set of values
    prior: bool = False  # a framework/library prior (Req 8.2): off by default for the engine
    nullable: bool = False  # may be null while its instrument ran (a minimum over nothing, a pass never asked)


def _specs() -> tuple[FeatureSpec, ...]:
    specs: list[FeatureSpec] = [FeatureSpec(f"lang.{name}", "language", "bool", "static") for name in LANGUAGES]
    specs += [
        FeatureSpec("qr.enabled_hits", "quick", "int", "static", cap=20),
        FeatureSpec("qr.shadow_hits", "quick", "int", "static", cap=20),
    ]
    specs += [FeatureSpec(f"qr.mechanism.{m}", "quick", "int", "static", cap=10) for m in MECHANISMS]
    specs += [
        FeatureSpec("qr.max_precision_estimate", "quick", "float", "static", nullable=True),
        FeatureSpec("qr.prior_hits", "quick", "int", "static", cap=10, prior=True),
        FeatureSpec("eng.findings", "engine", "int", "static", cap=10),
        FeatureSpec("eng.rung_max", "engine", "enum", "static", vocabulary=RUNGS, nullable=True),
        FeatureSpec("eng.witness_steps_min", "engine", "int", "static", cap=50, nullable=True),
        FeatureSpec("eng.sink_kind", "engine", "enum", "static", vocabulary=OPERATIONS, nullable=True),
        FeatureSpec("eng.source_kind", "engine", "enum", "static", vocabulary=SOURCE_KINDS, nullable=True),
        FeatureSpec("eng.sink_origin", "engine", "enum", "static", vocabulary=ORIGINS, nullable=True),
        FeatureSpec("eng.source_origin", "engine", "enum", "static", vocabulary=ORIGINS, nullable=True),
        FeatureSpec("eng.sanitizer_on_path", "engine", "bool", "static", nullable=True),
        FeatureSpec("eng.completion", "engine", "float", "static", nullable=True),
        FeatureSpec("eng.degraded", "engine", "bool", "static"),
        FeatureSpec("eng.unstable", "engine", "bool", "static", nullable=True),
        FeatureSpec("facts.callers", "facts", "int", "static", cap=40),
        FeatureSpec("facts.caller_files", "facts", "int", "static", cap=20),
        FeatureSpec("facts.is_global", "facts", "bool", "static"),
        FeatureSpec("facts.function_lines", "source", "int", "static", cap=500),
        FeatureSpec("facts.entry_distance", "entry_points", "int", "static", cap=6),
        FeatureSpec("roles.sink_confidence", "roles", "float", "static", nullable=True),
        FeatureSpec("roles.source_in_function", "roles", "bool", "static"),
        FeatureSpec("delta.novelty", "delta", "enum", "static", vocabulary=NOVELTY),
        FeatureSpec("delta.changed_lines", "delta", "int", "static", cap=200),
        FeatureSpec("delta.sanitizer_removed", "delta", "bool", "static"),
        FeatureSpec("verify.flag_a", "verify", "bool", "plane", nullable=True),
        FeatureSpec("verify.flag_b", "verify", "bool", "plane", nullable=True),
        FeatureSpec("verify.flag_c", "verify", "bool", "plane", nullable=True),
        FeatureSpec("verify.votes", "verify", "int", "plane", cap=3),
        FeatureSpec("verify.turns_mean", "verify", "float", "plane", nullable=True),
        FeatureSpec("verify.site_offset", "verify", "int", "plane", cap=200, nullable=True),
        FeatureSpec("agree.final", "agree", "enum", "plane", vocabulary=FINALS),
        FeatureSpec("ms.flagged", "model_sinks", "bool", "plane"),
        FeatureSpec("ms.operation", "model_sinks", "enum", "plane", vocabulary=OPERATIONS, nullable=True),
    ]
    return tuple(specs)


FEATURES: tuple[FeatureSpec, ...] = _specs()
BY_NAME: Mapping[str, FeatureSpec] = {spec.name: spec for spec in FEATURES}
# `float` features are fractions or means; `verify.turns_mean` is a mean of tool turns, the only unbounded float.
UNBOUNDED_FLOATS = frozenset({"verify.turns_mean"})


def features_for(profile: str) -> tuple[FeatureSpec, ...]:
    """The features a record of ``profile`` carries: ``static`` never sees an instrument absent in deployment."""
    if profile not in PROFILES:
        raise FeatureRecordError(f"unknown profile {profile!r} (one of {', '.join(PROFILES)})")
    return FEATURES if profile == "plane" else tuple(spec for spec in FEATURES if spec.profile == "static")


def instruments_for(profile: str) -> tuple[str, ...]:
    used = {spec.instrument for spec in features_for(profile)}
    return tuple(name for name in INSTRUMENTS if name in used)


def feature_set_digest() -> str:
    """sha256 of the canonical feature list: any change to a name, type, cap, vocabulary or profile changes it."""
    canonical = json.dumps([asdict(spec) for spec in FEATURES], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _check_value(spec: FeatureSpec, value: object) -> None:
    where = f"feature {spec.name}"
    if spec.type == "bool":
        if not isinstance(value, bool):
            raise FeatureRecordError(f"{where}: expected a bool, got {value!r}")
    elif spec.type == "int":
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= (spec.cap or 0):
            raise FeatureRecordError(f"{where}: expected an int in [0, {spec.cap}], got {value!r}")
    elif spec.type == "float":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise FeatureRecordError(f"{where}: expected a finite non-negative number, got {value!r}")
        if spec.name not in UNBOUNDED_FLOATS and value > 1:
            raise FeatureRecordError(f"{where}: expected a fraction in [0, 1], got {value!r}")
    elif not isinstance(value, str) or value not in spec.vocabulary:
        raise FeatureRecordError(f"{where}: {value!r} is outside the vocabulary {list(spec.vocabulary)}")


def validate_x(x: Mapping[str, object], instruments: Mapping[str, Mapping[str, object]], profile: str) -> None:
    """The features of one record against the allow-list and the instruments' states."""
    specs = {spec.name: spec for spec in features_for(profile)}
    unknown = sorted(set(x) - set(specs))
    if unknown:
        label = sorted(k for k in unknown if k.rsplit(".", 1)[-1] in EXCLUDED_FIELDS)
        why = f" (label or identity fields: {label})" if label else ""
        raise FeatureRecordError(f"features outside the {profile} allow-list: {unknown}{why}")
    missing = sorted(set(specs) - set(x))
    if missing:
        raise FeatureRecordError(f"features missing from the record: {missing}")
    wanted = set(instruments_for(profile))
    if set(instruments) != wanted:
        raise FeatureRecordError(f"instruments {sorted(instruments)} != the {profile} profile's {sorted(wanted)}")
    for name, info in instruments.items():
        if not isinstance(info, Mapping) or info.get("state") not in STATES:
            raise FeatureRecordError(f"instrument {name}: state must be one of {STATES}, got {info!r}")
    for name, spec in specs.items():
        value, state = x[name], instruments[spec.instrument]["state"]
        if state != "ran":
            if value is not None:
                raise FeatureRecordError(f"feature {name}: instrument {spec.instrument} is {state}, so the value must be null")
            continue
        if value is None:
            if not spec.nullable:
                raise FeatureRecordError(f"feature {name}: instrument {spec.instrument} ran, so null is not allowed here")
            continue
        _check_value(spec, value)


RECORD_FIELDS = ("candidate", "family", "language", "profile", "schema_version", "feature_set_digest", "unit", "x", "instruments")


def validate_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """A feature record, checked: envelope fields, versions, profile, and :func:`validate_x`. Returns it as a dict."""
    extra = sorted(set(record) - {*RECORD_FIELDS, "base"})
    if extra:
        raise FeatureRecordError(f"record fields outside the schema: {extra}")
    missing = [name for name in RECORD_FIELDS if name not in record]
    if missing:
        raise FeatureRecordError(f"record fields missing: {missing}")
    if record["schema_version"] != SCHEMA_VERSION or record["feature_set_digest"] != feature_set_digest():
        raise FeatureRecordError("record built for another schema version or feature set")
    if record["unit"] not in UNITS:
        raise FeatureRecordError(f"unit {record['unit']!r} is not one of {UNITS}")
    if not isinstance(record["x"], Mapping) or not isinstance(record["instruments"], Mapping):
        raise FeatureRecordError("x and instruments must be objects")
    validate_x(record["x"], record["instruments"], str(record["profile"]))
    return dict(record)


def names(specs: Iterable[FeatureSpec] = FEATURES) -> tuple[str, ...]:
    return tuple(spec.name for spec in specs)


__all__ = [
    "BY_NAME", "EXCLUDED_FIELDS", "FEATURES", "FINALS", "INSTRUMENTS", "LANGUAGES", "MECHANISMS", "NOVELTY", "OPERATIONS",
    "ORIGINS", "PROFILES", "RULE_TAG_MECHANISM", "RUNGS", "SCHEMA_VERSION", "SOURCE_KINDS", "STATES", "UNITS",
    "FeatureRecordError", "FeatureSpec", "feature_set_digest", "features_for", "instruments_for", "names",
    "validate_record", "validate_x",
]  # fmt: skip
