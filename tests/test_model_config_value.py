"""model-grounded-detection task 4.2 / Req 6.3: the configuration arm is constant abstraction, not taint.

A config_secrets bug has no flow and no guard. `CORS(app, origins="*")` is not dangerous because untrusted
input reaches it — nothing reaches it — but because the value it is *set to* is permissive. So the arbiter is
abstract-value evaluation of the argument against the closed permissive set, which is the third form the
design names alongside taint reachability and guard dominance.
"""

from __future__ import annotations

from pathlib import Path


def _spec():  # type: ignore[no-untyped-def]
    from openultrasast.model.specs import ConfigSpec

    return ConfigSpec(family="config_secrets", language="python",
                      settings=("CORS", "set_cookie", "app.run"),
                      permissive=("'*'", '"*"', "True", "0.0.0.0"))


def _cpg(rows):  # type: ignore[no-untyped-def]
    from openultrasast.cpg.backend import CpgResult

    return CpgResult(cpg_path=Path("cpg.bin"), run=lambda q, p: rows)


def test_a_permissive_literal_is_entailed() -> None:
    from openultrasast.model.config_value import verdict
    from openultrasast.model.ladder import Rung

    rows = [{"setting": 'CORS(app, origins="*")', "line": "3", "method": "create_app",
             "literalArgs": ['"*"'], "args": ["app", '"*"']}]
    answer = verdict(_cpg(rows), _spec(), function="create_app")
    assert answer is not None and answer.rung is Rung.ENTAILED
    assert "*" in answer.witness and "CORS" in answer.witness


def test_a_restrictive_literal_yields_no_finding() -> None:
    from openultrasast.model.config_value import verdict

    rows = [{"setting": 'CORS(app, origins="https://app.example")', "line": "3", "method": "create_app",
             "literalArgs": ['"https://app.example"'], "args": ["app", '"https://app.example"']}]
    assert verdict(_cpg(rows), _spec(), function="create_app") is None


def test_a_non_literal_argument_is_corroborated_not_entailed() -> None:
    """The value is computed, so constant abstraction cannot decide it — that residual is the LLM's."""
    from openultrasast.model.config_value import verdict
    from openultrasast.model.ladder import Rung

    rows = [{"setting": "CORS(app, origins=configured_origins)", "line": "3", "method": "create_app",
             "literalArgs": [], "args": ["app", "configured_origins"]}]
    answer = verdict(_cpg(rows), _spec(), function="create_app")
    assert answer is not None and answer.rung is Rung.CORROBORATED


def test_a_setting_that_is_not_in_the_spec_is_ignored() -> None:
    from openultrasast.model.config_value import verdict

    rows = [{"setting": 'print("*")', "line": "1", "method": "create_app", "literalArgs": ['"*"'], "args": ['"*"']}]
    assert verdict(_cpg(rows), _spec(), function="create_app") is None


def test_a_failed_query_is_not_read_as_a_safe_configuration() -> None:
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.config_value import verdict

    assert verdict(CpgResult(cpg_path=Path("c.bin"), run=lambda q, p: None), _spec(), function="f") is None


def test_the_verdict_is_deterministic() -> None:
    from openultrasast.model.config_value import verdict

    rows = [{"setting": 'set_cookie("s", secure=False)', "line": "9", "method": "login",
             "literalArgs": ["True", "0.0.0.0"], "args": ["x"]}]
    cpg = _cpg(rows)
    assert verdict(cpg, _spec(), function="login") == verdict(cpg, _spec(), function="login")
