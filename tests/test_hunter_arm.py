"""Offline coverage of the frozen benchmark hunter arm and replay join."""

import hashlib
import importlib
import json
import socket
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from openultrasast import tool_hunter
from openultrasast.complexity.map import Hotspot
from openultrasast.config import load_config
from openultrasast.learn import program
from openultrasast.learn.program import ANSWER_FORMAT, PARSE_FAILED, Caller, Decision, aggregate
from openultrasast.model.endpoint import resolve_models
from openultrasast.model.taxonomy import FAMILY_IDS, load_families

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
hunter_arm = importlib.import_module("benchmarks.valid.hunter_arm")
catalog = importlib.import_module("benchmarks.valid.catalog")
score = importlib.import_module("benchmarks.unseen.score")


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(tool_hunter, "resolve_hunter_client", lambda: tool_hunter.scripted_hunter_client())
    monkeypatch.setattr(hunter_arm, "classify", lambda *args, **kwargs: decision("injection"))


@pytest.fixture
def fixture(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git = catalog.local_git(root)
    git.run("init", "-q")
    git.run("config", "user.name", "Fixture")
    git.run("config", "user.email", "fixture@example.invalid")
    heads = []
    for text in ('def search(q):\n    return db.execute("select " + q)\n', "# Later checkout\n"):
        (root / "app.py").write_text(text)
        git.run("add", "app.py")
        git.run("-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture")
        heads.append(git.run("rev-parse", "HEAD").strip())
    change = dict(
        id="fixture-positive",
        repo="fixture/app",
        repository_url="https://example.invalid/app",
        kind="vulnerability",
        base=heads[1],
        head=heads[0],
        family="injection",
        cwe="CWE-89",
        files=[{"path": "app.py", "head_lines": [[2, 2]]}],
        function="search",
        function_lines=[1, 2],
    )
    manifest = tmp_path / "frozen.json"
    manifest.write_text(
        json.dumps({"changes": [change], "sha256": hashlib.sha256(json.dumps([change], sort_keys=True).encode()).hexdigest()})
    )
    repos = tmp_path / "repos.json"
    repos.write_text(json.dumps({"fixture/app": str(root)}))
    return git, change, manifest, repos, tmp_path / "out"


def flagged_client():
    return tool_hunter.ScriptedChatClient(
        [
            tool_hunter.ChatResponse(tool_calls=(tool_hunter.ToolCall("read", "read_file", {"path": "app.py"}),)),
            tool_hunter.ChatResponse(
                content=json.dumps(
                    [
                        {
                            "path": "app.py",
                            "line": 2,
                            "function_name": "search",
                            "title": "SQL injection (CWE-89)",
                            "rationale": "Input reaches a SQL interpreter",
                            "family": "sql-injection",
                        }
                    ]
                )
            ),
        ]
    )


def record_path(out, item_id):
    return out / (hashlib.sha256(item_id.encode()).hexdigest() + ".json")


def decision(family):
    return Decision("vulnerable", family, 0.9, {"vulnerable": 1}, "Protected operation has no guard at line 2", (2,), 0, ())


def raw_finding(*, line=2):
    (finding,) = tool_hunter._findings_from_content(
        Path("/tmp"),
        [],
        json.dumps(
            [
                {
                    "path": "app.py",
                    "line": line,
                    "title": "Read-only mode bypass",
                    "rationale": "A protected write is allowed",
                    "family": "sql-parser",
                }
            ]
        ),
    )
    return finding


def test_positive_is_scoreable_and_checkout_is_removed(fixture, monkeypatch, capsys):
    git, change, manifest, repos, out = fixture
    client = flagged_client()
    monkeypatch.setattr(tool_hunter, "resolve_hunter_client", lambda: client)
    assert hunter_arm.main(["run", str(manifest), "--repos", str(repos), "--out", str(out), "--max-steps", "2"]) == 0
    (row,) = score.load_records(out)
    (defect,) = row["push"]["admission"]["defects"]
    assert score.catches(row) == ["alerts"]
    assert defect["family"] == "injection" and defect["cwe"] == "CWE-77"
    assert defect["locations"] == [["app.py", 2]] and defect["function"] == "search"
    assert defect["source"] == "hunter"
    assert row["status"] == "hunter_covered" and row["done"]
    assert row["instrument"]["hook_bytes_read"] == len(git.blob(change["head"], "app.py").encode())
    assert score.coverage(row) != "instrument_failure"
    assert row["input_digest"] == json.loads((out / "inputs.json").read_text())[0]["input_digest"]
    assert client.calls[0]["model"] == resolve_models(load_config(dotenv=False))[0]
    assert "fixture-positive app.py:" in capsys.readouterr().out
    assert git.run("worktree", "list", "--porcelain").count("worktree ") == 1
    assert (git.path / "app.py").read_text() == "# Later checkout\n"


@pytest.mark.parametrize("failure", ["empty", "unreadable", "hunter", "missing", "bad_head", "bad_base"])
def test_failed_input_never_emits_findings(fixture, monkeypatch, capsys, failure):
    git, change, manifest, repos, out = fixture
    if failure in {"empty", "missing"}:
        change["files"] = [{"path": "empty.py" if failure == "empty" else "absent.py"}]
        if failure == "empty":
            (git.path / "empty.py").write_bytes(b"")
            git.run("add", "empty.py")
            git.run("-c", "core.hooksPath=/dev/null", "commit", "-qm", "empty")
            change["head"] = git.run("rev-parse", "HEAD").strip()
    if failure in {"bad_head", "bad_base"}:
        change[failure.removeprefix("bad_")] = "f" * 40
    monkeypatch.setattr(hunter_arm, "load_slice", lambda *args: [change])
    if failure == "unreadable":
        original = Path.read_bytes

        def unreadable(path):
            if path.name == "app.py":
                raise PermissionError("fixture")
            return original(path)

        monkeypatch.setattr(Path, "read_bytes", unreadable)

    def hunter(*args, **kwargs):
        if failure == "hunter":
            raise RuntimeError("private model key must not be logged")
        pytest.fail("hunter must not run on unread input")

    monkeypatch.setattr(tool_hunter, "run_tool_hunter", hunter)
    assert hunter_arm.main(["run", str(manifest), "--repos", str(repos), "--out", str(out)]) != 0
    (row,) = score.load_records(out)
    assert row["status"] == "instrument_failure"
    assert list(score.findings(row)) == [] and row["instrument"]["failure"]
    assert "instrument_failure" in capsys.readouterr().err
    assert "private model key" not in record_path(out, change["id"]).read_text()
    assert git.run("worktree", "list", "--porcelain").count("worktree ") == 1


def test_missing_file_skipped_and_hotspots_are_unlabelled(fixture, monkeypatch):
    _, change, manifest, repos, out = fixture
    change["files"].append({"path": "removed.py", "head_lines": []})
    monkeypatch.setattr(hunter_arm, "load_slice", lambda *args: [change])

    def hunter(root, hotspots, **kwargs):
        (hotspot,) = hotspots
        assert isinstance(hotspot, Hotspot) and hotspot.path == "app.py"
        assert hotspot.function_name is None and "injection" not in hotspot.rationale
        assert kwargs["max_steps"] == tool_hunter.DEFAULT_MAX_STEPS
        return []

    monkeypatch.setattr(tool_hunter, "run_tool_hunter", hunter)
    assert hunter_arm.main(["run", str(manifest), "--repos", str(repos), "--out", str(out)]) == 0
    (row,) = score.load_records(out)
    assert row["skipped"] == [{"path": "removed.py", "reason": "missing_at_head"}]


@pytest.mark.parametrize("with_inputs", [True, False])
def test_resume_skips_done_without_client_or_checkout(fixture, monkeypatch, with_inputs):
    _, change, manifest, repos, out = fixture
    out.mkdir()
    existing = {"id": change["id"], "done": True, "input_digest": "existing-digest", "status": "hunter_covered"}
    record_path(out, change["id"]).write_text(json.dumps(existing))
    if with_inputs:
        (out / "inputs.json").write_text(json.dumps([{"item_id": change["id"], "change": change, "input_digest": "existing-digest"}]))

    def forbidden(*args, **kwargs):
        pytest.fail("completed change was executed again")

    monkeypatch.setattr(tool_hunter, "resolve_hunter_client", forbidden)
    monkeypatch.setattr(hunter_arm, "local_git", forbidden)
    assert hunter_arm.main(["run", str(manifest), "--repos", str(repos), "--out", str(out)]) == 0
    assert json.loads(record_path(out, change["id"]).read_text()) == existing
    assert score.load_records(out)[0]["input_digest"] == "existing-digest"


def test_no_client_fails_clearly(fixture, monkeypatch, capsys):
    _, _, manifest, repos, out = fixture
    monkeypatch.setattr(tool_hunter, "resolve_hunter_client", lambda: None)
    assert hunter_arm.main(["run", str(manifest), "--repos", str(repos), "--out", str(out)]) != 0
    assert "no hunter client" in capsys.readouterr().err.lower()
    assert not list(out.glob("*.json"))


def test_classification_does_not_borrow_change_label(fixture):
    _, change, _, _, _ = fixture
    (finding,) = tool_hunter._findings_from_content(
        Path("/tmp"),
        [],
        json.dumps(
            [
                {
                    "path": "app.py",
                    "line": 2,
                    "title": "Path traversal",
                    "family": "path",
                }
            ]
        ),
    )
    defect = hunter_arm.finding_defect(finding)
    assert defect["family"] == "path" and defect["cwe"] == "CWE-22"
    row = {**change, "push": {"admission": {"defects": [defect]}}}
    assert not score.catches(row)
    unknown = hunter_arm.finding_defect(replace(finding, tags=[], title="Unclassified concern", rationale=""))
    assert unknown["family"] == "unknown" and unknown["cwe"] is None


def test_free_text_family_is_classified_and_scoreable(fixture, monkeypatch):
    _, change, manifest, repos, out = fixture
    change["family"] = "access_control"
    change["cwe"] = "CWE-284"
    monkeypatch.setattr(hunter_arm, "load_slice", lambda *args: [change])
    finding = raw_finding()
    monkeypatch.setattr(tool_hunter, "run_tool_hunter", lambda *args, **kwargs: [finding, replace(finding, finding_id="second")])
    client = tool_hunter.scripted_hunter_client()
    monkeypatch.setattr(tool_hunter, "resolve_hunter_client", lambda: client)
    prompts = []

    def classify(prompt, caller, k, *, families):
        assert isinstance(caller, Caller) and caller.client is client
        assert caller.model == resolve_models(load_config(dotenv=False))[0]
        assert k == 1 and tuple(families) == tuple(f for f in FAMILY_IDS if f != "unknown")
        assert prompt.example_ids == prompt.demo_ids == ()
        assert prompt.valid_lines == frozenset({1, 2})
        system, user = prompt.messages
        assert system["role"] == "system" and user["role"] == "user"
        content = user["content"]
        for family in families:
            assert load_families().by_id(family).description in content
        assert "sql-parser" in content and finding.title in content and finding.rationale in content
        assert "app.py:2" in content and "1  def search(q):" in content and "2      return db.execute" in content
        assert content.endswith(ANSWER_FORMAT)
        assert change["id"] not in content and change["cwe"] not in content
        prompts.append(prompt)
        return decision("access_control")

    monkeypatch.setattr(hunter_arm, "classify", classify)
    assert hunter_arm.main(["run", str(manifest), "--repos", str(repos), "--out", str(out)]) == 0
    (row,) = score.load_records(out)
    assert score.catches(row) == ["alerts"]
    assert len(prompts) == 2
    assert row["classifier"] == {"calls": 2, "parse_failed": 0, "families": {"access_control": 2}}
    for defect in row["push"]["admission"]["defects"]:
        assert defect["family"] == "access_control" and defect["cwe"] == "CWE-284"
        assert defect["hunter_family"] == "sql-parser" and defect["title"] == finding.title
        assert defect["rationale"] == finding.rationale
        assert defect["classifier"] == {
            "family": "access_control",
            "verdict": "vulnerable",
            "confidence": 0.9,
            "rationale": decision("access_control").rationale,
            "cited_lines": [2],
            "parse_failed": 0,
        }


@pytest.mark.parametrize("result", [decision("none"), aggregate([PARSE_FAILED])])
def test_classifier_abstention_is_unknown_and_done(fixture, monkeypatch, result):
    _, _, manifest, repos, out = fixture
    monkeypatch.setattr(tool_hunter, "run_tool_hunter", lambda *args, **kwargs: [raw_finding()])
    monkeypatch.setattr(hunter_arm, "classify", lambda *args, **kwargs: result)
    assert hunter_arm.main(["run", str(manifest), "--repos", str(repos), "--out", str(out)]) == 0
    (row,) = score.load_records(out)
    (defect,) = row["push"]["admission"]["defects"]
    assert defect["family"] == "unknown" and defect["cwe"] is None
    assert defect["classifier"]["parse_failed"] == result.parse_failed
    assert row["classifier"] == {"calls": 1, "parse_failed": result.parse_failed, "families": {"unknown": 1}}
    assert row["done"] and row["status"] == "hunter_covered"
    assert score.coverage(row) != "instrument_failure" and score.catches(row) == []


def test_classifier_exception_is_a_scoreable_miss(fixture, monkeypatch):
    _, _, manifest, repos, out = fixture
    monkeypatch.setattr(tool_hunter, "run_tool_hunter", lambda *args, **kwargs: [raw_finding()])

    def classify(*args, **kwargs):
        raise RuntimeError("private model key must not be logged")

    monkeypatch.setattr(hunter_arm, "classify", classify)
    assert hunter_arm.main(["run", str(manifest), "--repos", str(repos), "--out", str(out)]) == 0
    (row,) = score.load_records(out)
    (defect,) = row["push"]["admission"]["defects"]
    assert defect["family"] == "unknown" and defect["classifier"]["error"] == "RuntimeError"
    assert row["done"] and row["status"] == "hunter_covered"
    assert score.coverage(row) != "instrument_failure" and score.catches(row) == []
    assert row["classifier"] == {"calls": 1, "parse_failed": 0, "families": {"unknown": 1}}
    assert "private model key" not in json.dumps(row)


def test_no_classify_retains_heuristic_and_audit(fixture, monkeypatch):
    _, _, manifest, repos, out = fixture
    finding = replace(raw_finding(), title="SQL injection (CWE-89)")
    monkeypatch.setattr(tool_hunter, "run_tool_hunter", lambda *args, **kwargs: [finding])

    def forbidden(*args, **kwargs):
        pytest.fail("classifier called with --no-classify")

    monkeypatch.setattr(hunter_arm, "classify", forbidden)
    assert hunter_arm.main(["run", str(manifest), "--repos", str(repos), "--out", str(out), "--no-classify"]) == 0
    (row,) = score.load_records(out)
    (defect,) = row["push"]["admission"]["defects"]
    assert defect["family"] == "injection" and defect["cwe"] == "CWE-89"
    assert score.catches(row) == ["alerts"]
    assert defect["hunter_family"] == "sql-parser" and defect["title"] == finding.title
    assert defect["rationale"] == finding.rationale and defect["classifier"] is None
    assert row["classifier"] == {"calls": 0, "parse_failed": 0, "families": {"injection": 1}}


@pytest.mark.parametrize("line, expected", [(1, range(1, 22)), (30, range(10, 51)), (60, range(40, 61))])
def test_classify_family_excerpt_is_numbered_and_clamped(tmp_path, monkeypatch, line, expected, capsys):
    text = "".join(f"source_{n}\n" for n in range(1, 61))
    (tmp_path / "app.py").write_text(text)

    def classify(prompt, caller, k, *, families):
        assert prompt.valid_lines == frozenset(expected)
        content = prompt.messages[1]["content"]
        for n in expected:
            assert f"{n}  source_{n}\n" in content
        return decision("access_control")

    monkeypatch.setattr(hunter_arm, "classify", classify)
    result = hunter_arm.classify_family(raw_finding(line=line), tmp_path, caller=Caller(None, "offline"), families=("access_control",))
    assert result["family"] == "access_control"
    assert f"{len(text.encode())} bytes read" in capsys.readouterr().out


@pytest.mark.parametrize("failure", ["empty", "unreadable", "out_of_range"])
def test_missing_excerpt_is_unknown_without_classifying(fixture, monkeypatch, failure):
    _, _, manifest, repos, out = fixture

    def hunter(root, *args, **kwargs):
        if failure == "empty":
            (root / "app.py").write_text("")
        if failure == "unreadable":
            (root / "app.py").unlink()
        return [raw_finding(line=200 if failure == "out_of_range" else 2)]

    def forbidden(*args, **kwargs):
        pytest.fail("classifier called without a readable excerpt")

    monkeypatch.setattr(tool_hunter, "run_tool_hunter", hunter)
    monkeypatch.setattr(hunter_arm, "classify", forbidden)
    assert hunter_arm.main(["run", str(manifest), "--repos", str(repos), "--out", str(out)]) == 0
    (row,) = score.load_records(out)
    (defect,) = row["push"]["admission"]["defects"]
    assert defect["family"] == "unknown"
    assert defect["classifier"]["error"] == ("input_error:FileNotFoundError" if failure == "unreadable" else "empty_excerpt")
    assert row["classifier"] == {"calls": 0, "parse_failed": 0, "families": {"unknown": 1}}
    assert row["done"] and row["status"] == "hunter_covered" and score.catches(row) == []


@pytest.mark.parametrize("failure", ["off_list", "bad_citation", "retry_success"])
def test_classify_family_reuses_parser_and_retry(tmp_path, monkeypatch, failure):
    (tmp_path / "app.py").write_text("def search(q):\n    write(q)\n")
    good = {
        "verdict": "vulnerable",
        "family": "access_control",
        "confidence": 0.9,
        "rationale": "Missing guard at line 2",
        "cited_lines": [2],
    }
    bad = {**good, "family": "sql-parser"} if failure == "off_list" else {**good, "cited_lines": [1000]}
    contents = [bad] if failure == "off_list" else [bad, good if failure == "retry_success" else bad]
    client = tool_hunter.ScriptedChatClient([tool_hunter.ChatResponse(content=json.dumps(answer)) for answer in contents])
    monkeypatch.setattr(hunter_arm, "classify", program.classify)
    result = hunter_arm.classify_family(
        raw_finding(), tmp_path, caller=Caller(client, "offline"), families=tuple(f for f in FAMILY_IDS if f != "unknown")
    )
    assert len(client.calls) == len(contents)
    assert result["family"] == ("access_control" if failure == "retry_success" else "unknown")
    assert result["parse_failed"] == (1 if failure == "bad_citation" else 0)


def write_arm(out, entries, records):
    out.mkdir()
    (out / "inputs.json").write_text(json.dumps(entries))
    for item_id, record in records.items():
        record_path(out, item_id).write_text(json.dumps(record))


def test_combine_preserves_a_and_scores_b(fixture, tmp_path):
    _, change, _, _, _ = fixture
    changes = [{**change, "id": name} for name in ("both", "a-only", "b-only")]
    entries_a = [{"item_id": "replay-" + c["id"], "change": c, "input_digest": "a"} for c in changes]
    entries_b = [{"item_id": c["id"], "change": c, "input_digest": "b"} for c in changes]
    defect = {
        "defect_id": "hunter",
        "family": "injection",
        "cwe": "CWE-89",
        "function": "search",
        "locations": [["app.py", 2]],
        "source": "hunter",
    }
    a = {
        "status": "quick_only",
        "input_digest": "a",
        "done": True,
        "instrument": {"sentinel": "keep"},
        "push": {"admission": {"defects": [], "dispositions": [{"sentinel": "keep"}]}, "quick_tier": [{"sentinel": "keep"}]},
    }
    b = {
        "status": "hunter_covered",
        "input_digest": "b",
        "done": True,
        "push": {"admission": {"defects": [defect], "dispositions": []}, "quick_tier": []},
    }
    replay_out, hunter_out, combined = tmp_path / "a", tmp_path / "b", tmp_path / "combined.json"
    write_arm(replay_out, entries_a, {"replay-both": a, "replay-a-only": a})
    write_arm(hunter_out, entries_b, {"both": b, "b-only": b})
    assert hunter_arm.main(["combine", str(replay_out), str(hunter_out), "--out", str(combined)]) == 0
    both, a_only, b_only = score.load_records(combined)
    assert score.catches(both) == ["alerts"] and score.catches(b_only) == ["alerts"]
    assert both["instrument"] == a["instrument"] and both["status"] == a["status"]
    assert both["arms"] == {"a": "quick_only", "b": "hunter_covered"}
    assert both["push"]["quick_tier"] == a["push"]["quick_tier"]
    assert both["push"]["admission"]["dispositions"] == [{"sentinel": "keep"}]
    assert a_only == {**changes[1], **a, "arms": {"a": "quick_only", "b": "missing"}}
    assert b_only["arms"] == {"a": "missing", "b": "hunter_covered"}
    a["push"]["admission"]["defects"] = [{**defect, "defect_id": "a-defect", "source": "engine"}]
    record_path(replay_out, "replay-both").write_text(json.dumps(a))
    hunter_arm.main(["combine", str(replay_out), str(hunter_out), "--out", str(combined)])
    defects = score.load_records(combined)[0]["push"]["admission"]["defects"]
    assert len(defects) == 1 and defects[0]["source"] == "engine"


@pytest.mark.parametrize("arm", ["a", "b"])
def test_combine_rejects_duplicate_ids(fixture, tmp_path, arm):
    _, change, _, _, _ = fixture
    entry = {"item_id": change["id"], "change": change, "input_digest": "digest"}
    a, b = tmp_path / "a", tmp_path / "b"
    write_arm(a, [entry, entry] if arm == "a" else [entry], {})
    write_arm(b, [entry, entry] if arm == "b" else [entry], {})
    with pytest.raises(ValueError, match="duplicate"):
        hunter_arm.combine(a, b, tmp_path / "combined.json")


@pytest.mark.parametrize("directory_exists", [True, False])
def test_combine_without_hunter_index_keeps_replay(fixture, tmp_path, directory_exists):
    _, change, _, _, _ = fixture
    replay_out, hunter_out = tmp_path / "a", tmp_path / "b"
    entry = {"item_id": "replay-item", "change": change, "input_digest": "replay-digest"}
    a = {
        "status": "quick_only",
        "input_digest": "replay-digest",
        "done": True,
        "instrument": {"sentinel": "keep"},
        "push": {"admission": {"defects": []}},
    }
    write_arm(replay_out, [entry], {"replay-item": a})
    if directory_exists:
        hunter_out.mkdir()
    combined = tmp_path / "combined.json"
    hunter_arm.combine(replay_out, hunter_out, combined)
    assert score.load_records(combined) == [{**change, **a, "arms": {"a": "quick_only", "b": "missing"}}]


def test_build_caller_classifies_through_the_real_deepseek_wrapper(tmp_path, monkeypatch):
    """Regression: a bare DeepSeekChatClient keeps `usage` as a list, which made Caller.ask raise
    ValueError on every live classification. build_caller must meter the client first."""
    from types import SimpleNamespace

    from openultrasast.model.endpoint import DeepSeekChatClient

    answer = {
        "verdict": "vulnerable",
        "family": "access_control",
        "confidence": 0.9,
        "rationale": "The guard is skipped on line 2.",
        "cited_lines": [2],
    }

    class Raw:
        def complete_chat_raw(self, **kw):
            return {"choices": [{"message": {"content": json.dumps(answer)}}], "usage": {"prompt_tokens": 3}}

    (tmp_path / "app.py").write_text("def view(user):\n    return secret()\n")
    finding = SimpleNamespace(
        path="app.py", line=2, title="guard skipped", rationale="no check", tags=["tool-hunter", "family:views"], function_name="view"
    )
    # The module-wide fixture stubs classify; this test must run the real parser and Caller.
    monkeypatch.setattr(hunter_arm, "classify", program.classify)
    caller = hunter_arm.build_caller(DeepSeekChatClient(Raw()), "test-model")
    assert isinstance(caller.client, hunter_arm.MeteredClient)
    # A scripted client has no usage list and must pass through unwrapped.
    assert hunter_arm.build_caller(tool_hunter.scripted_hunter_client(), "m").client is not None
    assert not isinstance(hunter_arm.build_caller(tool_hunter.scripted_hunter_client(), "m").client, hunter_arm.MeteredClient)
    families = tuple(family for family in hunter_arm.FAMILY_IDS if family != "unknown")
    result = hunter_arm.classify_family(finding, tmp_path, caller=caller, families=families)
    assert result["family"] == "access_control" and "error" not in result
    assert result["verdict"] == "vulnerable" and result["cited_lines"] == [2]
