"""Exercise the snapshot resolver with real local Git objects, not mocked answers."""
import subprocess
from pathlib import Path

import pytest

from openultrasast.push.snapshot import SnapshotAdapter


def git(repo: Path, *args: str, input: str | None = None) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], input=input, text=True, capture_output=True, check=True)
    return result.stdout.strip()


@pytest.fixture(params=["sha1", "sha256"])
def repo(tmp_path: Path, request: pytest.FixtureRequest) -> Path:
    git(tmp_path, "init", "--object-format=" + request.param)
    git(tmp_path, "config", "user.name", "Fixture")
    git(tmp_path, "config", "user.email", "fixture@example.invalid")
    return tmp_path


def commit(repo: Path, label: str, *parents: str) -> str:
    blob = git(repo, "hash-object", "-w", "--stdin", input=label)
    assert git(repo, "cat-file", "-s", blob) == str(len(label))
    tree = git(repo, "mktree", input=f"100644 blob {blob}\tfile.js\n")
    args = ["commit-tree", tree]
    for parent in parents:
        args.extend(["-p", parent])
    return git(repo, *args, input=label)


def line(head: str, base: str, name: str = "main") -> str:
    return f"refs/heads/{name} {head} refs/heads/{name} {base}\n"


def test_preserves_every_ref_and_distinct_comparisons(repo: Path) -> None:
    base = commit(repo, "base")
    other = commit(repo, "other", base)
    head = commit(repo, "head", base)
    result = SnapshotAdapter(repo).resolve_updates(line(head, base) + line(head, other, "force") + line(head, base, "alias"))
    assert result.targets == (head,)
    assert [(c.head_oid, c.base_oid, c.refs) for c in result.comparisons] == [
        (head, base, ("refs/heads/main", "refs/heads/alias")), (head, other, ("refs/heads/force",))]
    assert [r.disposition for r in result.updates] == ["ready"] * 3
    assert len(result.updates) == 3


def test_configured_new_branch_uses_unique_merge_base(repo: Path) -> None:
    base = commit(repo, "base")
    left, right = commit(repo, "left", base), commit(repo, "right", base)
    git(repo, "update-ref", "refs/heads/baseline", right)
    merge = commit(repo, "merge", left, right)
    result = SnapshotAdapter(repo, comparison_base="refs/heads/baseline").resolve_updates(line(merge, "0" * len(base)))
    assert result.comparisons[0].base_oid == right
    assert result.comparisons[0].head_oid == merge
    assert result.updates[0].base_reason == "configured_unique_merge_base:" + right
    assert result.updates[0].disposition == "ready"


def test_no_implicit_head_or_fetch_for_missing_base(repo: Path) -> None:
    head = commit(repo, "head")
    git(repo, "update-ref", "HEAD", head)
    for configured in (None, "refs/remotes/origin/absent"):
        result = SnapshotAdapter(repo, comparison_base=configured).resolve_updates(line(head, "0" * len(head)))
        assert result.updates[0].disposition == "missing_base"
        assert result.comparisons[0].base_oid is None
    result = SnapshotAdapter(repo).resolve_updates(line(head, "1" * len(head)))
    assert result.updates[0].disposition == "missing_base"
    assert result.comparisons[0].base_reason == "supplied_remote_tip"


def test_unrelated_and_ambiguous_new_branch_bases(repo: Path) -> None:
    root = commit(repo, "root")
    unrelated = commit(repo, "unrelated")
    result = SnapshotAdapter(repo, comparison_base=unrelated).resolve_updates(line(root, "0" * len(root)))
    assert result.updates[0].disposition == "no_merge_base"
    left, right = commit(repo, "left", root), commit(repo, "right", root)
    one, two = commit(repo, "one", left, right), commit(repo, "two", right, left)
    result = SnapshotAdapter(repo, comparison_base=one).resolve_updates(line(two, "0" * len(root)))
    assert result.updates[0].disposition == "ambiguous_base"
    assert result.comparisons[0].base_oid is None


def test_tags_peel_to_commit_and_retain_input_identity(repo: Path) -> None:
    base, head = commit(repo, "base"), commit(repo, "head")
    git(repo, "tag", "-a", "old", base, "-m", "old")
    git(repo, "tag", "-a", "new", head, "-m", "new")
    old_tag, new_tag = git(repo, "rev-parse", "old"), git(repo, "rev-parse", "new")
    data = f"refs/tags/new {new_tag} refs/tags/new {old_tag}\n" + line(head, base)
    result = SnapshotAdapter(repo).resolve_updates(data)
    assert result.targets == (head,)
    assert result.comparisons[0].base_oid == base
    assert result.comparisons[0].refs == ("refs/tags/new", "refs/heads/main")
    assert result.updates[0].update.local_oid == new_tag
    assert result.updates[0].update.remote_oid == old_tag
    assert type(result).from_payload(result.to_payload()) == result


def test_deletion_only_has_no_analysis(repo: Path) -> None:
    old = commit(repo, "old")
    result = SnapshotAdapter(repo).resolve_updates(f"(delete) {'0' * len(old)} refs/heads/old {old}\n")
    assert result.targets == result.comparisons == ()
    assert result.updates[0].disposition == "deleted"
    assert SnapshotAdapter(repo).resolve_updates("").updates == ()


def test_missing_and_unsupported_objects_are_explicit(repo: Path) -> None:
    head = commit(repo, "head")
    blob = git(repo, "hash-object", "-w", "--stdin", input="unsupported source")
    git(repo, "tag", "-a", "blob-tag", blob, "-m", "unsupported")
    tag = git(repo, "rev-parse", "blob-tag")
    result = SnapshotAdapter(repo).resolve_updates(line("1" * len(head), head) + line(blob, head, "blob") + line(tag, head, "tag"))
    assert [r.disposition for r in result.updates] == ["missing_target", "unsupported_target", "unsupported_target"]
    assert result.targets == result.comparisons == ()
    result = SnapshotAdapter(repo).resolve_updates(line(head, blob))
    assert result.updates[0].disposition == "unsupported_base"


def test_bad_protocol_never_silently_skips_lines(repo: Path) -> None:
    from openultrasast.push.snapshot import SnapshotInputError
    head = commit(repo, "head")
    for invalid in ("\n", "only three fields\n", line(head[:-1], head), line(head, head, "bad..ref"),
                    line("0" * len(head), head), f"(delete) {head} refs/heads/main {head}\n"):
        with pytest.raises(SnapshotInputError):
            SnapshotAdapter(repo).resolve_updates(line(head, head) + invalid)


def test_replacements_and_inherited_git_environment_do_not_change_identity(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = commit(repo, "root")
    original = commit(repo, "original", root)
    replacement = commit(repo, "replacement")
    git(repo, "replace", original, replacement)
    monkeypatch.setenv("GIT_DIR", str(repo / "nonexistent"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(repo / "nonexistent"))
    result = SnapshotAdapter(repo, comparison_base=root).resolve_updates(line(original, "0" * len(root)))
    assert result.updates[0].disposition == "ready"
    assert result.comparisons[0].base_oid == root
    assert result.comparisons[0].head_oid == original


def test_missing_promisor_object_cannot_fetch_even_when_repo_allows_file(repo: Path, tmp_path: Path) -> None:
    source = repo / "source"
    source.mkdir()
    fmt = git(repo, "rev-parse", "--show-object-format")
    git(source, "init", "--object-format=" + fmt)
    git(source, "config", "user.name", "Fixture")
    git(source, "config", "user.email", "fixture@example.invalid")
    missing = commit(source, "must not fetch")
    git(source, "update-ref", "refs/heads/main", missing)
    git(repo, "config", "remote.origin.url", str(source))
    git(repo, "config", "remote.origin.promisor", "true")
    git(repo, "config", "remote.origin.partialclonefilter", "blob:none")
    git(repo, "config", "protocol.file.allow", "always")
    before = sorted(p.relative_to(repo / ".git/objects") for p in (repo / ".git/objects").rglob("*") if p.is_file())
    result = SnapshotAdapter(repo).resolve_updates(line(missing, "0" * len(missing)))
    after = sorted(p.relative_to(repo / ".git/objects") for p in (repo / ".git/objects").rglob("*") if p.is_file())
    assert result.updates[0].disposition == "missing_target"
    assert before == after


def test_missing_tag_referent_is_missing_not_unsupported(repo: Path) -> None:
    head = commit(repo, "head")
    git(repo, "tag", "-a", "dangling", head, "-m", "dangling")
    tag = git(repo, "rev-parse", "dangling")
    (repo / ".git" / "objects" / head[:2] / head[2:]).unlink()
    result = SnapshotAdapter(repo).resolve_updates(f"refs/tags/dangling {tag} refs/tags/dangling {'0' * len(head)}\n")
    assert result.updates[0].disposition == "missing_target"


def test_legacy_grafts_cannot_rewrite_comparison_ancestry(repo: Path) -> None:
    root = commit(repo, "root")
    head = commit(repo, "head", root)
    (repo / ".git/info/grafts").write_text(head + "\n")
    result = SnapshotAdapter(repo, comparison_base=root).resolve_updates(line(head, "0" * len(head)))
    assert result.comparisons[0].base_oid == root


def test_dirty_non_head_and_duplicate_update_records_are_preserved(repo: Path) -> None:
    base = commit(repo, "base")
    pushed = commit(repo, "pushed", base)
    checked = commit(repo, "checked", base)
    git(repo, "update-ref", "HEAD", checked)
    (repo / "file.js").write_text("dirty file")
    git(repo, "add", "file.js")
    before_index = (repo / ".git/index").read_bytes()
    result = SnapshotAdapter(repo).resolve_updates(line(pushed, base) * 2)
    assert result.targets == (pushed,)
    assert len(result.updates) == 2
    assert len(result.comparisons) == 1
    assert (repo / ".git/index").read_bytes() == before_index
    assert (repo / "file.js").read_text() == "dirty file"
    assert git(repo, "rev-parse", "HEAD") == checked


@pytest.mark.parametrize("name", ["unicode\u00a0inside", "unicode-trailing\u00a0", "unicode\u2028separator"])
def test_git_valid_unicode_ref_names_are_preserved(repo: Path, name: str) -> None:
    base = commit(repo, "base")
    head = commit(repo, "head", base)
    ref = "refs/heads/" + name
    git(repo, "check-ref-format", ref)
    git(repo, "update-ref", ref, head)
    result = SnapshotAdapter(repo).resolve_updates(line(head, base, name))
    assert result.updates[0].update.local_ref == ref
    assert result.updates[0].update.remote_ref == ref
    assert result.comparisons[0].refs == (ref,)
    assert result.updates[0].disposition == "ready"
