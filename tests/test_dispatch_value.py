"""A registry read returns its VALUE argument, not its context: a fact, loaded and checked."""

import pytest

from openultrasast.model.specs import taint_specs
from openultrasast.semantic.facts import FactLoadError, load_facts


def _write(tmp_path, dispatch: str) -> None:
    (tmp_path / "php.toml").write_text('language = "php"\n[[source]]\nid = "g"\npatterns = ["$_GET"]\n' + dispatch)


def test_the_shipped_facts_say_which_argument_a_filter_returns() -> None:
    spec = taint_specs(language="php")["injection"]
    assert "apply_filters:2" in spec.dispatch_value and "do_action:0" in spec.dispatch_value


def test_a_dispatch_row_declares_returns_with_a_position(tmp_path) -> None:
    row = '[[dispatch]]\nid = "hooks"\nregister = ["add_filter"]\napply = ["apply_filters", "do_action"]\n'
    _write(tmp_path, row + 'returns = ["apply_filters"]\nvalue_arg = 2\n')
    (fact,) = load_facts(tmp_path).dispatches
    assert fact.returns == ("apply_filters",) and fact.value_arg == 2


@pytest.mark.parametrize(
    "row",
    [
        'returns = ["apply_filters"]\n',  # a returning call without the value's position
        'returns = ["not_an_apply_call"]\nvalue_arg = 2\n',
        "value_arg = -1\n",
    ],
)
def test_a_malformed_dispatch_row_is_refused(tmp_path, row: str) -> None:
    _write(tmp_path, '[[dispatch]]\nid = "hooks"\nregister = ["add_filter"]\napply = ["apply_filters"]\n' + row)
    with pytest.raises(FactLoadError):
        load_facts(tmp_path)
