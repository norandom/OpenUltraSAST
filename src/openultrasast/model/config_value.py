"""Constant abstraction for the configuration families (model-grounded-detection, Req 6.3).

The third arbiter form, and the simplest. A configuration bug has no flow to follow and no guard to dominate:
``CORS(app, origins="*")`` is dangerous because of the value it is *set to*. So the model evaluates the
setting's arguments against the closed permissive set from the obligation facts.

    ENTAILED      a security setting is passed a literal in the permissive set — the model can read the value
    CORROBORATED  the setting's argument is computed, so constant abstraction cannot decide it; whether the
                  computed value is permissive is the residual the judge asks about
    (none)        every literal argument is outside the permissive set, or the call is not a known setting
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..cpg.backend import CpgResult
from .ladder import Rung, Verdict
from .specs import ConfigSpec


def request_params(spec: ConfigSpec, *, function: str = "", file: str = "") -> dict[str, object]:
    """The query parameters this arbiter sends. Shared with the batcher; see the note in `taint.request_params`.

    ``file`` scopes the answer to one source file. A region with no enclosing function sends ``function=""``,
    which without this matches the whole repository and gets that answer attributed to it -- one permissive
    literal in `app.py` became eight identical entailed findings in eight files that do not contain it. Empty
    means unscoped, which is what the single-region pair path still uses.
    """
    return {"settings": spec.settings, "function": function, "file": file}


def verdicts(cpg: CpgResult, spec: ConfigSpec, *, function: str = "", file: str = "") -> list[Verdict]:
    """Every configuration defect this region establishes, one per setting, strongest first.

    A file configures many things, and one verdict per region reported the first of them. Measured on
    NodeGoat: `server.js` disables template auto-escaping at line 135 and configures a permissive session at
    line 78, both inside the same function, so the escaping defect was detected on every run and reported on
    none. A contributor was shown one of two defects and told nothing about the other, and which one depended
    on where in the file it sat.

    Only the decided band is plural. A setting whose value the model could not READ is a question for the
    judge rather than a finding, and asking it once per region is what that band has always cost; returning
    every undecided setting would multiply model calls for claims none of which the graph established.
    """
    rows = cpg.run("config", request_params(spec, function=function, file=file))
    settings = _settings(rows, spec, function=function)
    if not settings:
        return []

    # Both abstractions read the same literal: a permissive flag ("*", True) and a weak algorithm ("md5").
    permissive = {value.strip().strip("'\"").lower() for value in spec.permissive}
    permissive |= {value.strip().strip("'\"").lower() for value in spec.weak_algorithms}
    scoped = {setting: {value.strip().strip("'\"").lower() for value in values} for setting, values in spec.permissive_by_setting}
    found: list[Verdict] = []
    for row in settings:
        literals = row["literals"]
        if not isinstance(literals, list):
            continue
        allowed = _permissive_for(str(row["setting"]), scoped) or permissive
        for literal in literals:
            if str(literal).strip().strip("'\"").lower() in allowed:
                found.append(
                    Verdict(
                        rung=Rung.ENTAILED,
                        family=spec.family,
                        witness=f"{row['setting']} (line {row['line']}): permissive literal {literal}",
                        location=_location(row, file),
                    )
                )
                break  # one verdict per setting: a call with two permissive literals is one defect
    if found:
        return found

    # A setting whose value the model could not read. Not safe, not decided.
    computed = [row for row in settings if not row["literals"]]  # type: ignore[truthy-iterable]
    if computed:
        row = computed[0]
        return [
            Verdict(
                rung=Rung.CORROBORATED,
                family=spec.family,
                witness=f"{row['setting']} (line {row['line']}): value is computed, not a literal the model can evaluate",
                location=_location(row, file),
            )
        ]
    return []


def verdict(cpg: CpgResult, spec: ConfigSpec, *, function: str = "", file: str = "") -> Verdict | None:
    """The strongest single verdict, kept for callers that ask one question and want one answer."""
    answers = verdicts(cpg, spec, function=function, file=file)
    return answers[0] if answers else None


def _location(row: Mapping[str, object], file: str) -> str:
    """``path:line:function`` of the setting, when the region named a file.

    Two settings in one file are two findings only if they are two SITES. Without this they shared the
    region's own identity and the deduplicator kept one, which is the same defect dominance carried until its
    findings stopped arriving as `api_views/users.py:?:update_password`. The config query reports no file of
    its own, so the region's is used -- correct because this arbiter never leaves the file it was asked about.
    """
    line = str(row.get("line") or "")
    if not file or not line.lstrip("-").isdigit() or int(line) < 0:
        return ""
    return f"{file}:{line}:{row.get('method') or '?'}"


def _permissive_for(setting: str, scoped: Mapping[str, set[str]]) -> set[str]:
    """The values permissive for the setting THIS row calls, empty when the facts declare none for it.

    A boolean's meaning is a property of the setting, not of the language: `autoescape: false` disables
    escaping and `secure: false` disables a cookie flag, while `autoescape: true` is the fix and `origin: true`
    is the defect. Asking per setting is what lets the template engines join the table without reporting every
    repository that escapes its output.

    The longest declared name that appears in the call wins, so a specific `swig.setDefaults` is not decided by
    a shorter name that happens to be a substring of the same call.
    """
    matched = sorted((name for name in scoped if name in setting), key=len, reverse=True)
    return set(scoped[matched[0]]) if matched else set()


def _settings(rows: object, spec: ConfigSpec, *, function: str) -> list[dict[str, object]]:
    """Rows for calls this spec actually names. A non-list (an engine failure) yields nothing."""
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return []
    kept: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        setting = str(row.get("setting", ""))
        if not any(name in setting for name in spec.settings):
            continue  # a permissive literal passed to something that is not a security setting is not a bug
        if function and str(row.get("method", "")) != function:
            continue
        literals = row.get("literalArgs")
        kept.append(
            {
                "setting": setting[:200],
                "line": str(row.get("line", "")),
                "method": str(row.get("method", "")),
                "literals": [str(v) for v in literals] if isinstance(literals, Sequence) and not isinstance(literals, str) else [],
            }
        )

    # Deterministic order: the first row decides, so it must not depend on engine ordering. The line sorts
    # NUMERICALLY, which is what "the first row" was always meant to mean: as text, line 126 precedes line 78,
    # and which of a file's settings gets reported was decided by the spelling of its line number. Caught when
    # a second permissive setting was added to a file that already had one.
    def _line(row: dict[str, object]) -> tuple[int, str]:
        text = str(row["line"])
        return (int(text) if text.lstrip("-").isdigit() else 1 << 30, text)

    return sorted(kept, key=lambda row: (str(row["method"]), _line(row), str(row["setting"])))


__all__ = ["request_params", "verdict", "verdicts"]
