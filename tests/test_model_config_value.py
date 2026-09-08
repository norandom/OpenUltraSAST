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


# --- framework coverage and the weak-algorithm arm --------------------------------------------------------
#
# The settings table was Flask/FastAPI-shaped (CORS, set_cookie, app.run) while the corpus contains aiohttp
# and Django. Separately, config_secrets spans three abstractions and only one was wired: a permissive
# setting VALUE. Weak algorithm CHOICE (CWE-326/327) has its data already -- `weak_literals` on the hashlib
# sink fact -- and nothing read it.


def test_the_settings_table_covers_the_frameworks_in_the_corpus() -> None:
    from openultrasast.model.specs import config_specs

    settings = set(config_specs(language="python")["config_secrets"].settings)
    for framework, call in (("aiohttp", "session_setup"), ("aiohttp", "EncryptedCookieStorage"),
                            ("django", "SECURE_SSL_REDIRECT"), ("flask", "set_cookie")):
        assert call in settings, f"{framework}'s {call} is not a modelled security setting"


def test_a_weak_algorithm_is_entailed_by_its_literal() -> None:
    """CWE-327: the danger is the algorithm NAMED, not a permissive flag."""
    from openultrasast.model.config_value import verdict
    from openultrasast.model.ladder import Rung
    from openultrasast.model.specs import config_specs

    spec = config_specs(language="python")["config_secrets"]
    rows = [{"setting": 'hashlib.new("md5")', "line": "4", "method": "digest",
             "literalArgs": ['"md5"'], "args": ['"md5"']}]
    answer = verdict(_cpg(rows), spec, function="digest")
    assert answer is not None and answer.rung is Rung.ENTAILED
    assert "md5" in answer.witness.lower()


def test_a_strong_algorithm_yields_no_finding() -> None:
    from openultrasast.model.config_value import verdict
    from openultrasast.model.specs import config_specs

    spec = config_specs(language="python")["config_secrets"]
    rows = [{"setting": 'hashlib.new("sha256")', "line": "4", "method": "digest",
             "literalArgs": ['"sha256"'], "args": ['"sha256"']}]
    assert verdict(_cpg(rows), spec, function="digest") is None
