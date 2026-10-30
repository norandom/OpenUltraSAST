"""Entry-fact packs loaded through the core fact-pack contract.

Packs live in ``ruleset/entries/*.json`` and are admitted only with a self-consistent
review attestation (`core.factpack.load_pack_file`). Languages map pack languages to
source languages; route patterns become extra recognition regexes.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from openultrasast.core.factpack import load_pack_file

_LANGUAGE_ALIASES = {"js": "javascript", "ts": "typescript"}
_cache: dict[tuple[str, tuple[tuple[str, float], ...]], dict[str, list[re.Pattern[str]]]] = {}


def load_entry_pack_patterns(repo_root: Path | None = None) -> dict[str, list[re.Pattern[str]]]:
    """Compiled route patterns per source language, from admitted entry packs.

    Packs resolve from the installed package's ``ruleset/entries`` (not the analyzed
    repository), so recognition is active on external repos; ``repo_root`` is accepted
    only for tests that stage a fake ruleset.
    """
    import openultrasast

    base = repo_root if repo_root is not None else Path(openultrasast.__file__).resolve().parent
    entries = base / "ruleset" / "entries"
    if not entries.is_dir():
        return {}
    files = sorted(entries.glob("*.json"))
    stamp = tuple((p.name, p.stat().st_mtime) for p in files)
    key = (str(entries.resolve()), stamp)
    if key in _cache:
        return _cache[key]
    patterns: dict[str, list[re.Pattern[str]]] = {}
    for pack_file in files:
        payload = json.loads(pack_file.read_text(encoding="utf-8"))
        pack = load_pack_file(pack_file)
        for raw_language in payload.get("languages", []):
            language = _LANGUAGE_ALIASES.get(str(raw_language), str(raw_language))
            for fact in pack.facts:
                if fact.get("handler_kind") == "route" and fact.get("pattern"):
                    patterns.setdefault(language, []).append(re.compile(str(fact["pattern"])))
    _cache[key] = patterns
    return patterns


__all__ = ["load_entry_pack_patterns"]
