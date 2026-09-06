"""authorization-obligations task 2.3: the declared policy has a closed schema (offline)."""

from __future__ import annotations

from pathlib import Path

import pytest

GOOD = (
    'version = 1\nidentity_source = "request.user"\n\n'
    '[[resource]]\nname = "book"\nsensitivity = "high"\nidentity_field = "user_id"\n\n'
    '[[route]]\npath = "/health"\naccess = "public"\n\n[[route]]\npath = "/admin/*"\naccess = "role"\nroles = ["admin"]\n'
)


def test_valid_policy_loads_with_a_version_hash(tmp_path: Path) -> None:
    from openultrasast.semantic.obligations.policy import load_declared_policy

    path = tmp_path / "obligations.toml"
    path.write_text(GOOD)
    policy = load_declared_policy(path)
    assert policy is not None and policy.version == 1 and policy.identity_source == "request.user"
    assert policy.resources["book"].sensitivity == "high" and policy.resources["book"].identity_field == "user_id"
    assert (
        policy.route_access("/health") == "public"
        and policy.route_access("/admin/users") == "role"
        and policy.route_access("/books/1") is None
    )
    assert len(policy.version_hash) == 40 and policy.version_hash == load_declared_policy(path).version_hash  # type: ignore[union-attr]
    path.write_text(GOOD + "\n# comment\n")
    assert load_declared_policy(path).version_hash == policy.version_hash  # type: ignore[union-attr]  # normalized: comments do not change the version
    assert load_declared_policy(tmp_path / "missing.toml") is None


def test_unknown_fields_and_values_are_rejected_by_name(tmp_path: Path) -> None:
    from openultrasast.semantic.obligations.policy import PolicyError, load_declared_policy

    path = tmp_path / "obligations.toml"
    for bad, needle in (
        (GOOD.replace('access = "public"', 'access = "sometimes"'), "sometimes"),
        (GOOD + '\n[[resource]]\nname = "x"\nsensitivity = "high"\nmood = "strict"\n', "mood"),
        (GOOD.replace('sensitivity = "high"', 'sensitivity = "critical"'), "critical"),
        (GOOD + "\nallow_everything = true\n", "allow_everything"),
        (GOOD.replace('identity_source = "request.user"', 'identity_source = "whatever.works"'), "identity_source"),
        (GOOD + '\n[[route]]\npath = "/x"\naccess = "public"\ncolor = "blue"\n', "color"),
    ):
        path.write_text(bad)
        with pytest.raises(PolicyError, match=needle):
            load_declared_policy(path)
