"""Offline fixtures for the valid detection benchmark."""

import importlib
import json
import math
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

catalog = importlib.import_module("benchmarks.valid.catalog")
verify = importlib.import_module("benchmarks.valid.verify")
assemble = importlib.import_module("benchmarks.valid.assemble")
metrics = importlib.import_module("benchmarks.valid.metrics")
extract = importlib.import_module("benchmarks.unseen.extract")
replay = importlib.import_module("benchmarks.unseen.replay")
score = importlib.import_module("benchmarks.unseen.score")
ChatResponse = importlib.import_module("openultrasast.tool_hunter").ChatResponse


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("network or SZZ was invoked")

    import socket

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(extract, "introducing", forbidden)
    monkeypatch.setattr(extract.Git, "blame", forbidden)
    for var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def pair(tmp_path):
    commit_count = 0

    def runner(argv, **kwargs):
        nonlocal commit_count
        assert not {"fetch", "clone", "pull", "push", "blame"} & set(argv)
        assert not any(arg.startswith("-L") for arg in argv)
        if "commit" in argv:
            timestamp = f"@{1600000000 + commit_count * 86400} +0000"
            kwargs["env"] = {**os.environ, "GIT_AUTHOR_DATE": timestamp, "GIT_COMMITTER_DATE": timestamp}
            commit_count += 1
        return subprocess.run(argv, **kwargs)

    git = extract.Git(tmp_path, runner=runner)
    git.run("init", "-q")
    git.run("config", "user.name", "Fixture")
    git.run("config", "user.email", "fixture@example.invalid")
    pre = 'from flask import request\n@app.route("/run")\ndef handler():\n    return eval(request.args["code"])\n'
    post = pre.replace('eval(request.args["code"])', 'int(request.args["code"])')
    commits = []
    for text in (pre, post):
        (tmp_path / "app.py").write_text(text)
        git.run("add", "app.py")
        git.run("commit", "-qm", "fixture")
        commits.append(git.run("rev-parse", "HEAD").strip())
    source = dict(
        repository="fixture/app",
        url="https://github.com/fixture/app",
        parent=commits[0],
        fix=commits[1],
        advisory="GHSA-fixture",
        cwe="CWE-94",
        family="injection",
        advisory_text="Request code is evaluated.",
    )
    (case,) = catalog.build_cases(git, source)
    return git, case


def test_fix_site_catalog(pair, tmp_path):
    git, case = pair
    assert case["method"] == "fix_site"
    assert case["function"] == "handler"
    assert case["function_lines"] == [[3, 4]]
    assert case["language"] == "python" and case["cwe"] == "CWE-94"
    sides = catalog.read_functions(git, case)
    assert 'eval(request.args["code"])' in sides["pre_fix"]
    assert 'int(request.args["code"])' in sides["post_fix"]
    path = tmp_path / "catalog.toml"
    catalog.write_catalog(path, [case])
    assert tomllib.loads(path.read_text())["case"] == [case]


class Stub:
    def __init__(self, **changes):
        self.calls = []
        self.answer = dict(
            vulnerable_pre_fix=True,
            fix_addresses_it=True,
            reachable_in_repo=True,
            entry_point="Flask route /run using request.args",
            confidence=0.86,
            advisory_cited=True,
            **changes,
        )

    def complete(self, **kwargs):
        self.calls.append(kwargs)
        return ChatResponse(content=json.dumps(self.answer))


@pytest.mark.parametrize("failed", [None, "vulnerable_pre_fix", "fix_addresses_it", "reachable_in_repo"])
@pytest.mark.parametrize("decision", ["accept", "reject", None])
def test_verification_requires_three_checks_and_human(pair, capsys, failed, decision):
    git, case = pair
    stub = Stub()
    if failed:
        stub.answer[failed] = False
    record = verify.verify_case(git, case, client=stub)
    assert len(stub.calls) == 1
    assert record["verdict"] != "accepted"
    assert "pre_fix" in capsys.readouterr().out
    prompt = json.dumps(stub.calls[0]["messages"])
    assert "eval(" in prompt and "int(" in prompt and "@app.route" in prompt
    if decision:
        record = verify.spot_check(record, decision, "AB", "2026-10-12")
    assert (record["verdict"] == "accepted") == (not failed and decision == "accept")


def test_empty_read_and_invalid_verdict(pair, monkeypatch):
    git, case = pair
    stub = Stub()
    monkeypatch.setattr(git, "blob", lambda *args: "")
    with pytest.raises(extract.InstrumentFailure):
        verify.verify_case(git, case, client=stub)
    assert not stub.calls


def test_spot_check_cli(pair, tmp_path):
    git, case = pair
    record = verify.verify_case(git, case, client=Stub())
    path = tmp_path / "verification.json"
    verify.write_records(path, [record])
    assert verify.main(["spot-check", str(path), case["id"], "accept", "--reviewer", "AB", "--date", "2026-10-12"]) == 0
    assert json.loads(path.read_text())["cases"][0]["verdict"] == "accepted"


def ordinary_rows(n=90):
    return [
        dict(
            head=f"{i + 10:040x}",
            parents=[f"{i + 9:040x}"],
            timestamp=i,
            author="Fixture",
            message="ordinary edit",
            files=[dict(path="other.py", added=1, removed=1, head_lines=[[2, 2]], functions=["other"], generated=False)],
        )
        for i in range(n)
    ]


def accepted(case):
    return dict(
        id=case["id"],
        vulnerable_pre_fix=True,
        fix_addresses_it=True,
        reachable_in_repo=True,
        entry_point="Flask route /run",
        confidence=0.86,
        model="stub",
        advisory_cited=True,
        human_spot_check=dict(decision="accept", reviewer="AB", date="2026-10-12"),
        verdict="accepted",
    )


def test_deterministic_freeze_and_replay(pair, tmp_path, monkeypatch):
    git, case = pair
    calls = []

    def history(git, head):
        calls.append(head)
        return ordinary_rows()

    monkeypatch.setattr(extract, "ordinary_history", history)
    kwargs = dict(cases=[case], verifications=[accepted(case)], repos={case["repo"]: git}, used=set(), seed=7)
    a = assemble.freeze(tmp_path / "a", **kwargs)
    b = assemble.freeze(tmp_path / "b", **kwargs)
    assert a == b and calls
    manifest = tomllib.loads((tmp_path / "a/pool-valid.toml").read_text())
    (row,) = manifest["repository"]
    pos = [c for c in row["changes"] if c["kind"] == "vulnerability"]
    neg = [c for c in row["changes"] if c["kind"] == "ordinary"]
    assert len(neg) >= 20 * len(pos) and len({c["head"] for c in neg}) == len(neg)
    assert pos[0]["base"] == case["commit"] and pos[0]["head"] == case["parent"]
    assert case["commit"] not in {c["head"] for c in neg}
    loaded = replay.load_slice(tmp_path / "a/pool-valid.toml", 1)
    assert len(loaded) == len(row["changes"]) and loaded[0]["case_id"] == case["id"]
    assert assemble.freeze(tmp_path / "a", **kwargs) == a


def test_held_out_guard_drops_used_repo_before_reading(pair, tmp_path, monkeypatch):
    git, case = pair
    other = {**case, "repo": "fixture/used", "id": "used-case"}
    monkeypatch.setattr(extract, "ordinary_history", lambda *args: ordinary_rows())
    result = assemble.freeze(
        tmp_path,
        cases=[case, other],
        verifications=[accepted(case), accepted(other)],
        repos={case["repo"]: git},
        used={"https://github.com/FIXTURE/USED.git"},
        seed=7,
    )
    assert result["guard_result"] == 0 and result["dropped_count"] == 1
    assert [r["repository"] for r in tomllib.loads((tmp_path / "pool-valid.toml").read_text())["repository"]] == [case["repo"]]


def record(id, kind, flagged, caught=True):
    return dict(
        id=id,
        case_id=id,
        repo="fixture/app",
        kind=kind,
        family="injection",
        path="app.py",
        function="handler",
        files=[dict(path="app.py", head_lines=[[4, 4]])],
        instrument=dict(head_verified=True, base_verified=True, hook_exit=0, changed_bytes={"app.py": 40}, hook_bytes_read=40),
        push=dict(admission=dict(defects=[dict(locations=[["app.py", 4]], family="injection" if caught else "path")] if flagged else [])),
    )


def hand_wilson(k, n):
    denominator = n + 1.96**2
    center = (k + 1.96**2 / 2) / denominator
    half = 1.96 * math.sqrt(k * (n - k) / n + 1.96**2 / 4) / denominator
    return [center - half, center + half]


def proof(id, observed=True):
    return dict(
        case_id=id,
        verification=dict(
            outcome="demonstrated" if observed else "inconclusive",
            sides=[dict(outcome="observed", runs=[dict(observed=v)] * 3) for v in (observed, False)],
        ),
    )


def test_metrics_hand_calculations():
    rows = [
        record("p1", "vulnerability", True),
        record("p2", "vulnerability", True),
        record("p3", "vulnerability", False),
        record("n1", "ordinary", True),
        record("n2", "ordinary", False),
    ]
    base = score.score(rows)
    result = metrics.summarize(rows, scored=base, proofs=[proof("p1")])
    assert result["recall"]["rate"] == pytest.approx(2 / 3)
    assert result["recall"]["wilson95"] == pytest.approx(hand_wilson(2, 3))
    assert result["recall"]["cluster95"] == pytest.approx([2 / 3, 2 / 3])
    assert result["precision"]["rate"] == pytest.approx(2 / 3)
    assert result["precision"]["wilson95"] == pytest.approx(hand_wilson(2, 3))
    fa = result["false_alarms_per_100_pushes"]
    assert fa["rate"] == 50 and fa["wilson95"] == pytest.approx([v * 100 for v in hand_wilson(1, 2)])
    assert fa["cluster95"] == [50, 50]
    proved = result["exploit_verified"]
    assert proved["count"] == proved["n"] == 1 and proved["rate"] == 1
    assert proved["flagged_positives"] == 2 and proved["not_yet_proved"] == ["p2"]
    assert proved["wilson95"] == pytest.approx(hand_wilson(1, 1))
    assert result["headline"] == (
        "On unseen app repos: recall 66.7% (Wilson 20.8-93.9), false alarms 50.0 per 100 pushes, "
        "precision 66.7%; exploit-verified 1 of 2 (1 not yet proved)."
    )


def test_precision_counts_unmatched_positive_flags_and_proof_failures():
    rows = [record("p", "vulnerability", True, caught=False), record("q", "vulnerability", True), record("n", "ordinary", True)]
    result = metrics.summarize(rows, proofs=[proof("q", observed=False)])
    assert result["precision"]["rate"] == pytest.approx(1 / 3)
    assert result["exploit_verified"]["count"] == 0
    assert result["exploit_verified"]["n"] == 1
    assert result["exploit_verified"]["not_yet_proved"] == ["p"]


@pytest.mark.parametrize("suffix,language", [(".js", "javascript"), (".ts", "typescript"), (".php", "php"), (".rb", None)])
def test_catalog_language_scope_and_single_line_function(suffix, language):
    class Git:
        def parents(self, sha):
            return ["a" * 40]

        def stats(self, *args):
            return [("app" + suffix, 1, 1)]

        def hunks(self, *args):
            return [(1, 1, 1, 1)]

        def blob(self, sha, path):
            return "function handler(value) { return " + ("eval(value)" if sha == "a" * 40 else "Number(value)") + "; }"

    cases = catalog.build_cases(
        Git(),
        dict(
            repository="fixture/app",
            url="https://github.com/fixture/app",
            fix="b" * 40,
            parent="a" * 40,
            advisory="GHSA-fixture",
            cwe="CWE-94",
            family="injection",
        ),
    )
    if language:
        (case,) = cases
        assert case["language"] == language and "eval(value)" in case["pre_fix"]
    else:
        assert cases == []


@pytest.mark.parametrize("empty", [False, True])
def test_shipped_provider_is_bounded_to_one_attempt(pair, monkeypatch, empty):
    from openultrasast.model.endpoint import ChatEndpoint, DeepSeekChatClient
    from openultrasast.provider.openrouter import OpenRouterChatClient

    git, case = pair
    calls = []

    def transport(self, **kwargs):
        calls.append(kwargs)
        assert self.max_attempts == 1
        assert kwargs["extra_body"]["max_tokens"] == 1200
        assert kwargs["extra_body"]["thinking"] == {"type": "disabled"}
        return {"choices": [{"message": {"content": "" if empty else json.dumps(Stub().answer)}}]}

    endpoint = ChatEndpoint(provider="deepseek", base_url="", thinking=False)
    client = DeepSeekChatClient(OpenRouterChatClient(api_key="offline-fixture"), endpoint=endpoint)
    monkeypatch.setattr(OpenRouterChatClient, "complete_chat_raw", transport)
    monkeypatch.setattr(verify, "resolve_chat_endpoint", lambda config: (client, endpoint))
    if empty:
        with pytest.raises(json.JSONDecodeError):
            verify.verify_case(git, case)
    else:
        assert verify.verify_case(git, case)["verdict"] == "pending_human"
    assert len(calls) == 1


@pytest.mark.parametrize(
    "key,value",
    [("reachable_in_repo", "true"), ("confidence", True), ("confidence", 1.5), ("confidence", float("nan")), ("entry_point", None)],
)
def test_malformed_model_reply_cannot_accept(pair, key, value):
    git, case = pair
    stub = Stub()
    stub.answer[key] = value
    with pytest.raises(ValueError):
        verify.verify_case(git, case, client=stub)
    assert len(stub.calls) == 1


def test_empty_entry_point_cannot_accept(pair):
    git, case = pair
    stub = Stub()
    stub.answer["entry_point"] = ""
    assert verify.spot_check(verify.verify_case(git, case, client=stub), "accept", "AB", "2026-10-12")["verdict"] == "rejected"


@pytest.mark.parametrize("use_cache", [False, True])
def test_real_local_history_freezes_without_network(pair, tmp_path, monkeypatch, use_cache):
    git, case = pair
    for i in range(55):
        (git.path / "other.py").write_text(f"def other():\n    return {i}\n")
        git.run("add", "other.py")
        git.run("commit", "-qm", "ordinary edit")
    kwargs = dict(cases=[case], verifications=[accepted(case)], repos={case["repo"]: git}, used=set())
    expected = assemble.freeze(tmp_path / "uncached", **kwargs)
    cache = tmp_path / "history-cache" if use_cache else None
    result = assemble.freeze(tmp_path / "freeze", **kwargs, history_cache=cache)
    assert result == expected
    assert result["label_check_counts"]["confirmed"] == 1
    assert len(replay.load_slice(tmp_path / "freeze/pool-valid.toml", 1)) == 21
    if use_cache:
        (path,) = cache.glob("*.jsonl")
        before = path.read_bytes()
        assert len(before.splitlines()) == 57

        def forbidden(*args):
            pytest.fail("cached freeze repeated per-commit work")

        for name in ("stats", "hunks", "blob"):
            monkeypatch.setattr(git, name, forbidden)
        assert assemble.freeze(tmp_path / "freeze", **kwargs, history_cache=cache) == result
        assert path.read_bytes() == before


def test_freeze_cli_passes_history_cache(pair, tmp_path, monkeypatch, capsys):
    git, case = pair
    catalog_path = tmp_path / "catalog.toml"
    catalog.write_catalog(catalog_path, [case])
    verification_path = tmp_path / "verification.json"
    verification_path.write_text(json.dumps({"cases": [accepted(case)]}))
    repos_path = tmp_path / "repos.json"
    repos_path.write_text(json.dumps({case["repo"]: str(git.path)}))
    used_path = tmp_path / "used.json"
    used_path.write_text("[]")
    cache = tmp_path / "history-cache"

    def freeze(directory, **kwargs):
        assert directory == tmp_path / "out"
        assert kwargs["history_cache"] == cache
        return {"checked": True}

    monkeypatch.setattr(assemble, "freeze", freeze)
    assert (
        assemble.main(
            [
                str(catalog_path),
                str(verification_path),
                "--repos",
                str(repos_path),
                "--used",
                str(used_path),
                "--out",
                str(tmp_path / "out"),
                "--history-cache",
                str(cache),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {"checked": True}


def test_insufficient_negatives_and_invalid_ratio(pair, tmp_path, monkeypatch):
    git, case = pair
    monkeypatch.setattr(extract, "ordinary_history", lambda *args: ordinary_rows(19))
    kwargs = dict(cases=[case], verifications=[accepted(case)], repos={case["repo"]: git}, used=set())
    with pytest.raises(ValueError, match="insufficient ordinary"):
        assemble.freeze(tmp_path, **kwargs)
    with pytest.raises(ValueError, match="at least 20"):
        assemble.freeze(tmp_path, ratio=19, **kwargs)
    with pytest.raises(ValueError, match="at least the ratio"):
        assemble.freeze(tmp_path, floor=19, **kwargs)
    assert not (tmp_path / "freeze-valid.json").exists()
    # A training freeze lowers the floor to the ratio: 20 eligible commits now suffice, and the record says so.
    monkeypatch.setattr(extract, "ordinary_history", lambda *args: ordinary_rows(20))
    with pytest.raises(ValueError, match="ordinary_floor"):  # Rejected is a ValueError with a fixed reason code
        assemble.freeze(tmp_path / "default", **kwargs)
    result = assemble.freeze(tmp_path / "train", floor=20, **kwargs)
    assert result["ordinary_floor"] == 20 and result["negative_ratio"] == 20
    # Twenty eligible commits for a ratio of twenty: every one of them is drawn, none twice.
    ordinary = [c for c in replay.load_slice(tmp_path / "train/pool-valid.toml", 1) if c["kind"] == "ordinary"]
    assert len(ordinary) == 20 and len({c["head"] for c in ordinary}) == 20


def test_freeze_cannot_overwrite_or_trust_verdict_alone(pair, tmp_path, monkeypatch):
    git, case = pair
    monkeypatch.setattr(extract, "ordinary_history", lambda *args: ordinary_rows())
    kwargs = dict(cases=[case], verifications=[accepted(case)], repos={case["repo"]: git}, used=set())
    assemble.freeze(tmp_path, **kwargs)
    before = (tmp_path / "pool-valid.toml").read_bytes()
    with pytest.raises(FileExistsError):
        assemble.freeze(tmp_path, seed=1, **kwargs)
    assert (tmp_path / "pool-valid.toml").read_bytes() == before
    kwargs["verifications"][0]["human_spot_check"]["decision"] = "reject"
    with pytest.raises(ValueError, match="no accepted"):
        assemble.freeze(tmp_path / "rejected", **kwargs)


def test_no_flags_and_invalid_proof_are_not_false_proofs():
    result = metrics.summarize([record("p", "vulnerability", False), record("n", "ordinary", False)])
    assert result["precision"] == dict(n=0, count=0, rate=None, wilson95=[None, None])
    assert result["exploit_verified"]["rate"] is None
    bad = proof("p")
    bad["verification"]["sides"][1]["runs"] = [dict(observed=True)] * 3
    result = metrics.summarize([record("p", "vulnerability", True)], proofs=[bad])
    assert result["exploit_verified"]["count"] == 0


def test_multi_function_fix_is_one_push_with_all_case_ids(pair, tmp_path, monkeypatch):
    git, original = pair
    parent_text = "def first(value):\n    return eval(value)\n\ndef second(value):\n    return eval(value)\n"
    commits = []
    for text in (parent_text, parent_text.replace("eval(value)", "int(value)")):
        (git.path / "multi.py").write_text(text)
        git.run("add", "multi.py")
        git.run("commit", "-qm", "fixture")
        commits.append(git.run("rev-parse", "HEAD").strip())
    source = dict(
        repository=original["repo"],
        url=original["url"],
        parent=commits[0],
        fix=commits[1],
        advisory="GHSA-multi",
        cwe="CWE-94",
        family="injection",
        advisory_text="Two functions evaluate user code.",
    )
    cases = catalog.build_cases(git, source)
    assert len(cases) == 2
    monkeypatch.setattr(extract, "ordinary_history", lambda *args: ordinary_rows())
    assemble.freeze(
        tmp_path / "multi", cases=cases, verifications=[accepted(case) for case in cases], repos={original["repo"]: git}, used=set()
    )
    loaded = replay.load_slice(tmp_path / "multi/pool-valid.toml", 1)
    # One fix commit is one positive change, so the 20x negative ratio is 20, not 20 per
    # accepted function. Two accepted functions still collapse to a single vulnerability push.
    assert len(loaded) == 21 and len({row["id"] for row in loaded}) == 21
    (positive,) = [row for row in loaded if row["kind"] == "vulnerability"]
    assert set(positive["case_ids"]) == {case["id"] for case in cases}
    target = positive["targets"][1]
    detected = record(positive["id"], "vulnerability", True)
    detected.update({key: value for key, value in positive.items() if key not in {"id", "repo"}})
    detected["push"] = dict(
        admission=dict(
            defects=[dict(locations=[[target["path"], target["function_lines"][0]]], function=target["function"], family="injection")]
        )
    )
    detected["instrument"]["changed_bytes"] = {target["path"]: 40}
    result = metrics.summarize([detected, record("negative", "ordinary", False)], proofs=[proof(positive["case_ids"][0])])
    assert result["recall"]["n"] == result["recall"]["count"] == 1
    assert result["precision"]["rate"] == 1
    assert result["exploit_verified"]["flagged_positives"] == 2
    assert result["exploit_verified"]["flagged_positive_pushes"] == 1
    assert result["exploit_verified"]["not_yet_proved"] == [positive["case_ids"][1]]


def test_grouped_targets_different_families_use_shipped_scorer():
    row = record("p", "vulnerability", True)
    row["targets"] = [
        dict(case_id="one", path="miss.py", function="first", function_lines=[40, 42], family="path"),
        dict(case_id="two", path="app.py", function="handler", function_lines=[3, 4], family="injection"),
    ]
    row["case_ids"] = ["one", "two"]
    row.update({key: value for key, value in row["targets"][0].items() if key != "case_id"})
    row["files"] = [{"path": "miss.py", "head_lines": [[40, 42]]}]
    legacy = score.score([row])
    assert legacy["catch"]["count"] == 0
    result = metrics.summarize([row], scored=legacy)
    assert result["recall"]["count"] == 1 and result["precision"]["rate"] == 1
