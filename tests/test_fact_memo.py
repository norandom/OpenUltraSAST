"""The parsed ruleset is shared across calls, and never outlives a change to the files it came from.

Region discovery asked for the facts once per region and re-parsed the TOML every time: 89,127 parses and
275 s of a 339 s discovery on a WordPress plugin, twice per push.
"""

import shutil

from openultrasast.semantic.facts import DEFAULT_FACTS_DIR, load_facts
from openultrasast.semantic.obligations.facts import DEFAULT_OBLIGATION_FACTS_DIR, load_obligation_facts


def test_facts_are_parsed_once_and_reread_when_a_file_changes(tmp_path):
    root = tmp_path / "semantic"
    shutil.copytree(DEFAULT_FACTS_DIR, root)
    first = load_facts(root)
    assert load_facts(root) is first, "an unchanged ruleset must not be parsed again"
    python = root / "python.toml"
    python.write_text(python.read_text() + '\n[[sink]]\nid = "memo-probe"\ncwe = "CWE-78"\ncalls = ["memo_probe_call"]\n')
    edited = load_facts(root)
    assert edited is not first and any("memo_probe_call" in sink.calls for sink in edited.sinks), "an edit in place was not seen"
    (root / "zz_added.toml").write_text('language = "python"\n[[sink]]\nid = "added"\ncwe = "CWE-78"\ncalls = ["added_call"]\n')
    added = load_facts(root)
    assert any("added_call" in sink.calls for sink in added.sinks), "a new fact file was not seen"


def test_obligation_facts_are_parsed_once_and_reread_when_a_file_changes(tmp_path):
    root = tmp_path / "obligations"
    shutil.copytree(DEFAULT_OBLIGATION_FACTS_DIR, root)
    first = load_obligation_facts(root)
    assert load_obligation_facts(root) is first
    (root / "python.toml").write_text((root / "python.toml").read_text().replace('version = "', 'version = "memo-', 1))
    assert load_obligation_facts(root) is not first
