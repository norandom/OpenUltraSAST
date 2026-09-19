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


def verdict(cpg: CpgResult, spec: ConfigSpec, *, function: str = "", file: str = "") -> Verdict | None:
    """The verdict for a security setting in ``function``, or ``None`` when nothing is established."""
    rows = cpg.run("config", request_params(spec, function=function, file=file))
    settings = _settings(rows, spec, function=function)
    if not settings:
        return None

    # Both abstractions read the same literal: a permissive flag ("*", True) and a weak algorithm ("md5").
    permissive = {value.strip().strip("'\"").lower() for value in spec.permissive}
    permissive |= {value.strip().strip("'\"").lower() for value in spec.weak_algorithms}
    scoped = {setting: {value.strip().strip("'\"").lower() for value in values} for setting, values in spec.permissive_by_setting}
    for row in settings:
        literals = row["literals"]
        if not isinstance(literals, list):
            continue
        allowed = _permissive_for(str(row["setting"]), scoped) or permissive
        for literal in literals:
            if str(literal).strip().strip("'\"").lower() in allowed:
                return Verdict(
                    rung=Rung.ENTAILED,
                    family=spec.family,
                    witness=f"{row['setting']} (line {row['line']}): permissive literal {literal}",
                )

    # A setting whose value the model could not read. Not safe, not decided.
    computed = [row for row in settings if not row["literals"]]  # type: ignore[truthy-iterable]
    if computed:
        row = computed[0]
        return Verdict(
            rung=Rung.CORROBORATED,
            family=spec.family,
            witness=f"{row['setting']} (line {row['line']}): value is computed, not a literal the model can evaluate",
        )
    return None


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


__all__ = ["request_params", "verdict"]
