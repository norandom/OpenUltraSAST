"""Framework knowledge as tagged priors (learned-decision-engine task 2; Req 8.2, design section 2).

The lint: no untagged entry of ``ruleset/semantic/*.toml`` or of a quick ``rules.toml`` contains a symbol of
``ruleset/frameworks.toml`` (a symbol of a framework or library of the entry's language, matched as a whole token;
a quick rule's pattern is read with its regex escapes removed). ``priors="off"`` removes exactly the tagged entries
and activates the language-level fallbacks of mixed quick rules; the default ``"all"`` is today's ruleset.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from openultrasast.ruleset import DEFAULT_RULESET_DIR, load_ruleset
from openultrasast.ruleset.frameworks import FrameworksError, framework_ids, load_frameworks, symbol_in
from openultrasast.semantic.facts import DEFAULT_FACTS_DIR, load_facts

TABLES = ("source", "sink", "sanitizer", "dispatch")
LANGUAGE_FAMILY = {"typescript": "javascript", "cpp": "c"}


def _lexicon(language: str) -> dict[str, tuple[str, ...]]:
    wanted = LANGUAGE_FAMILY.get(language, language)
    return {row.id: row.symbols for row in load_frameworks() if wanted in {LANGUAGE_FAMILY.get(lang, lang) for lang in row.languages}}


def _texts(item: dict[str, object]) -> list[str]:
    keys = ("patterns", "calls", "register", "apply", "returns", "request_arguments", "origin_anchors")
    return [str(text) for key in keys for text in item.get(key, []) or []]  # type: ignore[union-attr]


def _semantic_entries() -> list[tuple[str, str, dict[str, object]]]:
    rows = []
    for path in sorted(DEFAULT_FACTS_DIR.glob("*.toml")):
        data = tomllib.loads(path.read_text())
        rows += [
            (str(data.get("language") or path.stem), f"{path.name} {table} {item['id']}", item)
            for table in TABLES
            for item in data.get(table, [])
        ]
    return rows


def _rules() -> list[dict[str, object]]:
    return [rule for path in sorted(DEFAULT_RULESET_DIR.glob("*/rules.toml")) for rule in tomllib.loads(path.read_text()).get("rule", [])]


def _unescaped(pattern: str) -> str:
    return re.sub(r"\\(.)", r"\1", pattern)


def test_no_untagged_entry_names_a_framework_symbol() -> None:
    offenders: list[str] = []
    for language, where, item in _semantic_entries():
        if item.get("framework") or item.get("library"):
            continue
        for framework, symbols in _lexicon(language).items():
            hits = sorted({s for s in symbols for text in _texts(item) if symbol_in(s, text)})
            if hits:
                offenders.append(f"{where}: {framework} {hits}")
    for rule in _rules():
        if rule.get("framework") or rule.get("library"):
            continue
        text = _unescaped(str(rule["pattern"]))
        for language in rule.get("languages") or []:  # type: ignore[union-attr]
            for framework, symbols in _lexicon(str(language)).items():
                hits = sorted(s for s in symbols if symbol_in(s, text))
                if hits:
                    offenders.append(f"rule {rule['rule_id']}: {framework} {hits}")
    assert not offenders, "untagged framework knowledge (tag it, or split the entry):\n" + "\n".join(sorted(set(offenders)))


def test_the_lint_catches_an_untagged_framework_entry() -> None:
    item = {"id": "x", "calls": ["$wpdb->get_var", "mysqli_query"]}
    assert any(symbol_in(s, t) for s in _lexicon("php")["wordpress"] for t in _texts(item))
    assert not any(symbol_in(s, "maybe_unserialized_value") for s in ("maybe_unserialize",)), "whole tokens only"
    assert symbol_in("wpdb->", _unescaped(r"\$(?!wpdb->)[A-Za-z_]")), "a symbol inside an exclusion still counts"


def test_every_tag_names_a_listed_id_and_the_lexicon_is_well_formed() -> None:
    ids = framework_ids()
    tags = [item.get("framework") or item.get("library") for _, _, item in _semantic_entries()]
    tags += [rule.get("framework") or rule.get("library") for rule in _rules()]
    assert {t for t in tags if t} <= ids
    assert {"wordpress", "flask", "django", "express", "spring", "jakarta-servlet"} <= ids
    for row in load_frameworks():
        assert row.symbols and row.languages and row.kind in ("framework", "library"), row.id


def _signature(facts: object) -> set[tuple[str, str, str, tuple[str, ...]]]:
    rows = set()
    for kind in ("sources", "sinks", "sanitizers", "dispatches"):
        for fact in getattr(facts, kind):
            texts = tuple(getattr(fact, "patterns", ()) or getattr(fact, "calls", ()) or getattr(fact, "register", ()))
            rows.add((kind, fact.language, fact.id, texts))
    return rows


def test_priors_off_removes_exactly_the_tagged_entries() -> None:
    every, off = load_facts(), load_facts(priors="off")
    assert load_facts(priors="all") is every, "the default is today's facts, memoised"
    tagged = {
        row for row in _signature(every)
        for fact in getattr(every, row[0]) if (fact.language, fact.id) == row[1:3]
        and tuple(getattr(fact, "patterns", ()) or getattr(fact, "calls", ()) or getattr(fact, "register", ())) == row[3]
        and (fact.framework or fact.library)
    }  # fmt: skip
    assert tagged, "the semantic facts carry tagged priors"
    assert _signature(every) - _signature(off) == tagged and _signature(off) <= _signature(every)
    assert off.layouts == every.layouts, "layouts are product filters, not detection"
    rules_all = {r.rule_id: r for r in load_ruleset(DEFAULT_RULESET_DIR)}
    rules_off = {r.rule_id: r for r in load_ruleset(DEFAULT_RULESET_DIR, priors="off")}
    tagged_rules = {rid for rid, r in rules_all.items() if r.framework or r.library}
    fallbacks = {rid for rid, r in rules_off.items() if r.fallback_for}
    assert tagged_rules and set(rules_all) - set(rules_off) == tagged_rules
    assert set(rules_off) - set(rules_all) == fallbacks and {rules_off[f].fallback_for for f in fallbacks} <= tagged_rules
    assert not any(r.fallback_for for r in rules_all.values()), "a fallback is inactive while its prior is on"


def test_split_entries_keep_their_language_level_calls() -> None:
    off = load_facts(priors="off")

    def calls(language: str, kind: str, ident: str) -> set[str]:
        scoped = off.for_language(language)
        return {c for f in getattr(scoped, kind) if f.id == ident for c in (getattr(f, "calls", ()) or getattr(f, "patterns", ()))}

    assert calls("php", "sinks", "unserialize") == {"unserialize"}
    assert calls("php", "sanitizers", "sql_escape") == {"mysqli_real_escape_string", "mysql_real_escape_string", "pg_escape_string"}
    assert calls("php", "sanitizers", "coerce") == {"intval", "floatval", "filter_var", "settype"}
    assert calls("php", "sinks", "wpdb") == set() and not off.for_language("php").dispatches
    assert calls("python", "sinks", "pickle.loads") == {"pickle.loads", "pickle.load", "marshal.loads", "cPickle.loads"}
    assert calls("python", "sinks", "path.open") == {"open", "os.remove", "os.unlink", "shutil.copy", "shutil.move", "shutil.rmtree"}
    assert calls("python", "sinks", "outbound.request") == {"urlopen", "urlretrieve"} and calls("python", "sources", "request") == set()
    assert calls("javascript", "sinks", "outbound.request") == {"fetch", "http.get", "http.request", "https.get", "https.request"}
    assert calls("javascript", "sinks", "prototype.merge") == {"Object.assign"}
    assert calls("javascript", "sanitizers", "html.escape") == {"encodeURIComponent", "encodeURI", "escape"}
    assert calls("java", "sinks", "outbound.request") == {"openConnection", "openStream"}
    assert calls("java", "sanitizers", "java.escape") == {"getCanonicalPath", "normalize", "URLEncoder.encode"}
    assert calls("java", "sources", "servlet") == {"readLine"}
    rules = {r.rule_id: r for r in load_ruleset(DEFAULT_RULESET_DIR, priors="off")}
    assert "php-unserialize" in rules and "php-maybe-unserialize" not in rules
    assert re.search(rules["php-unserialize"].pattern, "$x = unserialize($_POST['a']);")
    assert not re.search(rules["php-unserialize"].pattern, "$x = maybe_unserialize($_POST['a']);")
    assert re.search(rules["python-unsafe-deserialization-language"].pattern, "pickle.loads(data)")
    assert not re.search(rules["python-unsafe-deserialization-language"].pattern, "yaml.load(data)")


def test_a_chosen_prior_keeps_only_its_own_entries() -> None:
    wordpress = load_facts(priors=frozenset({"wordpress"}))
    assert {c for f in wordpress.for_language("php").sinks if f.id == "wpdb" for c in f.calls} >= {"$wpdb->get_var"}
    assert not any(f.framework == "flask" for f in wordpress.sources)
    rules = {r.rule_id for r in load_ruleset(DEFAULT_RULESET_DIR, priors=frozenset({"wordpress"}))}
    assert "php-wpdb-sql-composition" in rules and "python-ssti" not in rules and "python-unsafe-deserialization-language" in rules
    with pytest.raises(FrameworksError, match="unknown priors"):
        load_facts(priors=frozenset({"no-such-framework"}))
    with pytest.raises(FrameworksError):
        load_ruleset(DEFAULT_RULESET_DIR, priors="none")  # type: ignore[arg-type]


def test_a_tag_outside_frameworks_toml_is_refused(tmp_path: Path) -> None:
    (tmp_path / "x.toml").write_text('language = "php"\n[[sink]]\nid = "s"\nframework = "nope"\ncwe = "CWE-89"\ncalls = ["q"]\n')
    with pytest.raises(ValueError, match="not a framework id"):
        load_facts(tmp_path)
