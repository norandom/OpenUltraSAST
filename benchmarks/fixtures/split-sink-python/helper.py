"""Trivial eval helper: many same-line pattern hits, little complexity."""


def ping() -> str:
    eval("1")
    eval("2")
    return "ok"
