"""Task 11.3: extract existing target knowledge into candidate records (Req 2.9).

Extraction mode of the initialization job: the legacy recognition strategies in
``mapping/legacy.py`` and the promoted fact rows in ``ruleset/obligations/*.toml``
are read -- never modified -- and returned as deterministic candidate records
carrying source, version and region evidence. Verification and promotion are the
acquisition workflow's job (tasks 11.4+), not extraction's.

This is a tools module, not an engine module: naming recognition targets here is
legitimate (the whole point is to extract their vocabulary into data).
"""

import hashlib
import re
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

_RECOGNISER_PATTERN = re.compile(
    r"^(def (_[a-z][a-z0-9_]*_entries)\(|def (_python_registered_routes)\(|(_PHP_REGISTRATION) = )",
    re.MULTILINE,
)


@dataclass(frozen=True)
class CandidateRecord:
    """A unit of extracted target knowledge awaiting verification (Req 2.9)."""

    kind: str  # 'operation' | 'discharger' | 'implication' | 'entry-strategy'
    name: str  # fact id or recogniser function/constant name
    source: str  # file the knowledge was read from (relative-style path tail)
    version: str  # sha256[:12] of the source file's bytes
    region: str  # '<file>:<table>:<id>' or 'legacy.py:<symbol>:<start>-<end>'
    payload: tuple[tuple[str, str], ...] = ()  # sorted field pairs


def extract_fact_rows(ruleset_dir: Path) -> tuple[CandidateRecord, ...]:
    """Extract operation, discharger and implication rows as candidates."""
    records: list[CandidateRecord] = []
    for path in sorted(ruleset_dir.glob("*.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        version = _digest(path)
        records.extend(_row_records(path.name, version, data))
    return tuple(records)


def extract_legacy_strategies(mapping_path: Path) -> tuple[CandidateRecord, ...]:
    """Extract the legacy recogniser inventory (symbol regions) as candidates."""
    text = mapping_path.read_text(encoding="utf-8")
    version = _digest(mapping_path)
    records = [
        CandidateRecord(
            kind="entry-strategy",
            name=symbol,
            source=mapping_path.name,
            version=version,
            region=f"legacy.py:{symbol}:{start}-{end}",
        )
        for symbol, start, end in _symbol_spans(text)
    ]
    return tuple(records)


def extract_all(repo_root: Path) -> tuple[CandidateRecord, ...]:
    """Extract every knowledge source: fact rows and legacy strategies."""
    ruleset_dir = repo_root / "src" / "openultrasast" / "ruleset" / "obligations"
    mapping_path = repo_root / "src" / "openultrasast" / "mapping" / "legacy.py"
    records = [*extract_fact_rows(ruleset_dir), *extract_legacy_strategies(mapping_path)]
    return tuple(sorted(records, key=lambda record: (record.kind, record.name, record.region)))


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def _row_records(file_name: str, version: str, data: dict) -> Iterator[CandidateRecord]:
    tables = (("operation", "operation"), ("discharger", "discharger"), ("implication", "implication"))
    for kind, table in tables:
        for row in data.get(table, []):
            row_id = str(row.get("id", row.get("kind", "")))
            yield CandidateRecord(
                kind=kind,
                name=row_id,
                source=file_name,
                version=version,
                region=f"{file_name}:{table}:{row_id}",
                payload=_payload(row),
            )


def _payload(row: dict) -> tuple[tuple[str, str], ...]:
    pairs = []
    for key, value in row.items():
        if isinstance(value, (list, tuple)):
            pairs.append((key, ",".join(str(item) for item in value)))
        else:
            pairs.append((key, str(value)))
    return tuple(sorted(pairs))


def _symbol_spans(text: str) -> Iterable[tuple[str, int, int]]:
    matches = list(_RECOGNISER_PATTERN.finditer(text))
    lines = text.splitlines()
    for index, match in enumerate(matches):
        symbol = match.group(2) or match.group(3) or match.group(4)
        start = text.count("\n", 0, match.start()) + 1
        end_line = text.count("\n", 0, matches[index + 1].start()) + 1 if index + 1 < len(matches) else len(lines)
        yield symbol, start, end_line - 1


__all__ = ["CandidateRecord", "extract_all", "extract_fact_rows", "extract_legacy_strategies"]
