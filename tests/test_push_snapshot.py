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
        (head, base, ("refs/heads/main", "refs/heads/alias")),
        (head, other, ("refs/heads/force",)),
    ]
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
    for invalid in (
        "\n",
        "only three fields\n",
        line(head[:-1], head),
        line(head, head, "bad..ref"),
        line("0" * len(head), head),
        f"(delete) {head} refs/heads/main {head}\n",
    ):
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


def test_materialize_reads_non_head_objects_and_cleans(repo: Path, tmp_path: Path) -> None:
    pushed = commit(repo, "<?php echo $_GET['x'];")
    checked = commit(repo, "dirty baseline")
    git(repo, "update-ref", "HEAD", checked)
    (repo / "file.js").write_bytes(b"staged")
    git(repo, "add", "file.js")
    (repo / "file.js").write_bytes(b"dirty")
    before = (repo / ".git/index").read_bytes()
    with SnapshotAdapter(repo).materialize(pushed) as snapshot:
        root = snapshot.root
        assert (root / "file.js").read_bytes() == b"<?php echo $_GET['x'];"
        assert snapshot.manifest.complete
        assert snapshot.manifest.bytes_read == 22
        assert snapshot.manifest.commit_oid == pushed
    assert not root.exists()
    assert (repo / ".git/index").read_bytes() == before
    assert (repo / "file.js").read_bytes() == b"dirty"
    assert git(repo, "rev-parse", "HEAD") == checked


def binary_commit(repo: Path, entries: list[tuple[bytes, bytes, bytes]]) -> str:
    records = []
    for mode, path, data in entries:
        if mode == b"160000":
            oid = data
            kind = b"commit"
        else:
            oid = subprocess.run(
                ["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=data, capture_output=True, check=True
            ).stdout.rstrip(b"\n")
            kind = b"blob"
            assert int(git(repo, "cat-file", "-s", oid.decode())) == len(data)
        records.append(mode + b" " + kind + b" " + oid + b"\t" + path + b"\0")
    tree = (
        subprocess.run(["git", "-C", str(repo), "mktree", "-z"], input=b"".join(records), capture_output=True, check=True)
        .stdout.decode()
        .strip()
    )
    return git(repo, "commit-tree", tree, input="binary fixture")


def test_snapshot_exact_binary_paths_and_no_filters(repo: Path) -> None:
    import os

    entries = [
        (b"100644", path, data)
        for path, data in [
            (b"handler.php", b"<?php echo $_GET['x'];\n"),
            (b"api.js", b"app.post('/x', (req,res)=>res.send(req.body.x));\n"),
            (b"newline\nname\t.js", b"\x00\xffbinary\r\n"),
            ("\u03b1.js".encode(), b"unicode"),
            (b"\xff.js", b"invalid UTF8 name"),
            (b" ", b"space"),
            (b".gitattributes", b"* filter=trap\n"),
        ]
    ]
    oid = binary_commit(repo, entries)
    sentinel = repo / "FILTER_RAN"
    git(repo, "config", "filter.trap.smudge", "touch " + str(sentinel))
    with SnapshotAdapter(repo).materialize(oid) as snapshot:
        assert snapshot.manifest.complete
        assert snapshot.manifest.bytes_read == sum(len(data) for _, _, data in entries)
        assert {f.path_bytes for f in snapshot.manifest.files} == {path for _, path, _ in entries}
        for _, path, data in entries:
            assert (snapshot.root / os.fsdecode(path)).read_bytes() == data
        assert type(snapshot.manifest).from_payload(snapshot.manifest.to_payload()) == snapshot.manifest
    assert not sentinel.exists()


def test_snapshot_omits_symlinks_gitlinks_and_lfs(repo: Path) -> None:
    target = commit(repo, "submodule")
    oid = binary_commit(
        repo,
        [
            (b"120000", b"outside", b"/etc/passwd"),
            (b"160000", b"submodule", target.encode()),
            (b"100644", b"large.js", b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"0" * 64 + b"\nsize 3\n"),
        ],
    )
    with SnapshotAdapter(repo).materialize(oid) as snapshot:
        assert not snapshot.manifest.complete
        assert snapshot.manifest.tree_complete
        assert {b.reason for b in snapshot.manifest.boundaries} == {
            "symlink_not_materialized",
            "gitlink_not_materialized",
            "lfs_content_unavailable",
        }
        assert list(snapshot.root.iterdir()) == []


@pytest.mark.parametrize(
    "limit,reason",
    [
        ("max_files", "file_count_limit"),
        ("max_tree_bytes", "git_output_limit"),
        ("max_blob_bytes", "source_byte_limit"),
        ("max_total_bytes", "source_byte_limit"),
        ("max_path_bytes", "unsupported_path"),
    ],
)
def test_snapshot_limits_are_explicit(repo: Path, limit: str, reason: str) -> None:
    from openultrasast.push.snapshot import SnapshotLimits

    oid = binary_commit(repo, [(b"100644", b"one.js", b"123"), (b"100644", b"two.php", b"456")])
    with SnapshotAdapter(repo).materialize(oid, limits=SnapshotLimits(**{limit: 1})) as snapshot:
        root = snapshot.root
        assert not snapshot.manifest.complete
        assert reason in {b.reason for b in snapshot.manifest.boundaries}
        assert snapshot.manifest.bytes_read <= 1 if limit == "max_total_bytes" else True
    assert not root.exists()


@pytest.mark.parametrize("failure", ["cancel", "deadline", "missing_blob", "consumer"])
def test_snapshot_failure_preserves_live_state_and_cleans(repo: Path, failure: str) -> None:
    import time

    from openultrasast.model.contracts import ExecutionBudget
    from openultrasast.push.snapshot import SnapshotInputError

    oid = commit(repo, "object bytes")
    git(repo, "update-ref", "HEAD", oid)
    (repo / "file.js").write_bytes(b"staged")
    git(repo, "add", "file.js")
    (repo / "file.js").write_bytes(b"dirty")
    hooks = repo / ".git/hooks/pre-push"
    hooks.write_bytes(b"existing hook")
    if failure == "missing_blob":
        blob = git(repo, "rev-parse", oid + ":file.js")
        (repo / ".git/objects" / blob[:2] / blob[2:]).unlink()
    before = {p.relative_to(repo): p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    calls = 0

    def cancel() -> bool:
        nonlocal calls
        calls += 1
        return failure == "cancel" and calls >= 5

    budget = ExecutionBudget(time.monotonic() + (-1 if failure == "deadline" else 10), 2.0)
    root = None
    try:
        with SnapshotAdapter(repo).materialize(oid, budget=budget, cancelled=cancel) as snapshot:
            root = snapshot.root
            if failure == "consumer":
                raise RuntimeError("consumer cancelled")
            assert not snapshot.manifest.complete
            assert snapshot.manifest.boundaries
    except RuntimeError:
        assert failure == "consumer"
    except SnapshotInputError as error:
        assert failure == "deadline" and str(error) == "deadline_exhausted"
    assert (root is None and failure == "deadline") or (root is not None and not root.exists())
    after = {p.relative_to(repo): p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    assert before == after


def test_snapshot_rejects_live_scratch_parent(repo: Path) -> None:
    from openultrasast.push.snapshot import SnapshotInputError

    oid = commit(repo, "input")
    for parent in (repo, repo / ".git", repo / ".git/objects"):
        with pytest.raises(SnapshotInputError, match="outside"), SnapshotAdapter(repo).materialize(oid, scratch_parent=parent):
            pytest.fail("unsafe scratch accepted")


def test_snapshot_missing_tree_and_unsupported_object_are_not_clean(repo: Path) -> None:
    oid = commit(repo, "input")
    blob = git(repo, "rev-parse", oid + ":file.js")
    with SnapshotAdapter(repo).materialize(blob) as snapshot:
        assert not snapshot.manifest.complete
        assert not snapshot.manifest.tree_complete
    tree = git(repo, "rev-parse", oid + "^{tree}")
    (repo / ".git/objects" / tree[:2] / tree[2:]).unlink()
    with SnapshotAdapter(repo).materialize(oid) as snapshot:
        assert not snapshot.manifest.complete
        assert not snapshot.manifest.tree_complete
        assert not snapshot.manifest.files


def test_snapshot_refuses_oversize_blob_before_reading_it(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.push.snapshot import SnapshotLimits

    oid = commit(repo, "large payload")
    adapter = SnapshotAdapter(repo)
    original = adapter._bounded_git
    commands = []

    def capture(args, *rest):
        commands.append(args)
        return original(args, *rest)

    monkeypatch.setattr(adapter, "_bounded_git", capture)
    with adapter.materialize(oid, limits=SnapshotLimits(max_blob_bytes=1)) as snapshot:
        assert not snapshot.manifest.complete
    assert not any(args[:2] == ("cat-file", "blob") for args in commands)


def test_cleanup_does_not_follow_consumer_symlinks(repo: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    outside = tmp_path_factory.mktemp("outside")
    (outside / "keep").write_bytes(b"preserve")
    oid = commit(repo, "source")
    with SnapshotAdapter(repo).materialize(oid) as snapshot:
        (snapshot.root / "external").symlink_to(outside, target_is_directory=True)
    assert (outside / "keep").read_bytes() == b"preserve"
    with SnapshotAdapter(repo).materialize(oid) as snapshot:
        (snapshot.root / "file.js").unlink()
        snapshot.root.rmdir()
        snapshot.root.symlink_to(outside, target_is_directory=True)
    assert (outside / "keep").read_bytes() == b"preserve"
    assert not snapshot.root.exists()


def test_snapshot_deadline_kills_slow_git_and_cleans(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import time

    from openultrasast.model.contracts import ExecutionBudget

    oid = commit(repo, "input")
    adapter = SnapshotAdapter(repo)
    real_popen = subprocess.Popen
    processes = []

    def slow_git(command, **kwargs):
        process = real_popen([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", slow_git)
    start = time.monotonic()
    with adapter.materialize(oid, budget=ExecutionBudget(start + 0.1, 1.0)) as snapshot:
        assert {b.reason for b in snapshot.manifest.boundaries} == {"deadline_exhausted"}
        assert not snapshot.manifest.complete
    assert time.monotonic() - start < 1.5
    assert processes and all(process.poll() is not None for process in processes)
    assert not snapshot.root.exists()


def test_snapshot_manifest_rejects_forged_census(repo: Path) -> None:
    from dataclasses import replace

    oid = commit(repo, "input")
    with SnapshotAdapter(repo).materialize(oid) as snapshot:
        manifest = snapshot.manifest
        file = manifest.files[0]
        for changes in ({"bytes_read": -1}, {"files": (file, file)}, {"tree_complete": False}):
            with pytest.raises(ValueError):
                replace(manifest, **changes)
        for changes in ({"path_hex": "zz"}, {"size_bytes": -1}, {"sha256": "bad"}, {"path_hex": "00"}):
            with pytest.raises(ValueError):
                replace(file, **changes)


def test_snapshot_subdirectory_adapter_cannot_scratch_in_live_parent(repo: Path) -> None:
    from openultrasast.push.snapshot import SnapshotInputError

    oid = commit(repo, "input")
    nested = repo / "nested"
    nested.mkdir()
    with pytest.raises(SnapshotInputError, match="outside"), SnapshotAdapter(nested).materialize(oid, scratch_parent=repo):
        pytest.fail("live parent accepted")


def test_snapshot_write_failure_cleans_partial_scratch(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    oid = commit(repo, "input")
    original = Path.open

    def broken(path, mode="r", *args, **kwargs):
        if mode == "xb":
            raise OSError("scratch_write_failed")
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", broken)
    with SnapshotAdapter(repo).materialize(oid) as snapshot:
        assert not snapshot.manifest.complete
        assert any(b.reason == "scratch_write_failed" for b in snapshot.manifest.boundaries)
    assert not snapshot.root.exists()


def comparison(base: str | None, head: str):
    from openultrasast.push.contracts import PushComparison

    return PushComparison(head, base, "supplied_remote_tip", ("refs/heads/main",))


@pytest.mark.parametrize(
    "extension,prefix,guard,sink",
    [
        (b"php", b"<?php\n", b"  require_permission($user);\n", b"  execute($input);\n"),
        (b"js", b"", b"  requirePermission(user);\n", b"  execute(input);\n"),
    ],
)
def test_change_context_function_rename_and_removed_guard(repo: Path, extension, prefix, guard, sink) -> None:
    path = b"handler." + extension
    old = prefix + b"function oldHandler() {\n" + guard + sink + b"}\n"
    new = prefix + b"function newHandler() {\n" + sink + b"}\n"
    base = binary_commit(repo, [(b"100644", path, old)])
    head = binary_commit(repo, [(b"100644", path, new)])
    result = SnapshotAdapter(repo).compare(comparison(base, head), declaration_paths=())
    assert result.base_revision == base and result.head_revision == head
    assert result.path_encoding == "filesystem-bytes-hex"
    assert result.changed_paths == (path.hex(),)
    base_guard = old.split(b"\n").index(guard.rstrip(b"\n")) + 1
    assert any(s.side == "base" and s.start_line <= base_guard <= s.end_line for s in result.spans)
    base_sink = old.split(b"\n").index(sink.rstrip(b"\n")) + 1
    head_sink = new.split(b"\n").index(sink.rstrip(b"\n")) + 1
    assert any(
        m.base_start_line <= base_sink <= m.base_end_line and m.head_start_line + base_sink - m.base_start_line == head_sink
        for m in result.line_correspondences
    )
    assert not any(s.side == "head" and s.start_line <= head_sink <= s.end_line for s in result.spans)
    assert result.relationships == ()  # Snapshot evidence cannot invent semantic call/guard edges.
    assert type(result).from_payload(result.to_payload()) == result


def test_change_context_nul_paths_renames_deletions_and_declarations(repo: Path) -> None:
    old_path, new_path = b"old\n\xff.js", b"new\t\xfe.js"
    payload = b"function unchanged() {\n  uniqueOperation();\n}\n"
    base = binary_commit(
        repo, [(b"100644", old_path, payload), (b"100644", b" ", b"deleted\n"), (b"100644", b"package.json", b'{"mode":"old"}\n')]
    )
    head = binary_commit(repo, [(b"100644", new_path, payload), (b"100644", b"package.json", b'{"mode":"new"}\n')])
    result = SnapshotAdapter(repo).compare(comparison(base, head), declaration_paths=(b"package.json",))
    assert {(r.base_path, r.head_path) for r in result.renames} == {(old_path.hex(), new_path.hex())}
    assert result.deleted_paths == (b" ".hex(),)
    assert result.declaration_paths == (b"package.json".hex(),)
    assert any(m.base_path == old_path.hex() and m.head_path == new_path.hex() for m in result.line_correspondences)
    assert any(s.path == b" ".hex() and s.side == "base" for s in result.spans)


def test_change_context_unknown_base_binary_and_ambiguous_lines_are_unresolved(repo: Path) -> None:
    base = binary_commit(repo, [(b"100644", b"api.js", b"old();\nsink();\nsink();\n"), (b"100644", b"binary", b"\x00old")])
    head = binary_commit(repo, [(b"100644", b"api.js", b"new();\nsink();\nsink();\n"), (b"100644", b"binary", b"\x00new")])
    missing = SnapshotAdapter(repo).compare(comparison(None, head))
    assert "comparison_base_unavailable" in missing.unresolved_boundaries
    result = SnapshotAdapter(repo).compare(comparison(base, head))
    assert "declaration_paths_unavailable" in result.unresolved_boundaries
    assert any("ambiguous_line_correspondence" in b for b in result.unresolved_boundaries)
    assert any("binary_line_correspondence_unavailable" in b for b in result.unresolved_boundaries)
    assert not result.line_correspondences


def test_change_context_is_bounded_and_never_executes_diff_helpers(repo: Path) -> None:
    from openultrasast.push.snapshot import SnapshotLimits

    marker = repo / "DIFF_RAN"
    git(repo, "config", "diff.external", "touch " + str(marker))
    git(repo, "config", "diff.trap.textconv", "touch " + str(marker))
    (repo / ".gitattributes").write_text("* diff=trap\n")
    base, head = commit(repo, "old\n"), commit(repo, "new\n")
    result = SnapshotAdapter(repo).compare(comparison(base, head), declaration_paths=())
    assert result.spans
    assert not marker.exists()
    limited = SnapshotAdapter(repo).compare(comparison(base, head), limits=SnapshotLimits(max_blob_bytes=1))
    assert any("source_byte_limit" in b for b in limited.unresolved_boundaries)
    cancelled = SnapshotAdapter(repo).compare(comparison(base, head), cancelled=lambda: True)
    assert "cancelled" in cancelled.unresolved_boundaries


def test_change_context_moved_repeated_operations_do_not_claim_identity(repo: Path) -> None:
    base = binary_commit(repo, [(b"100644", b"api.js", b"function a() {\n  sink();\n}\nfunction b() {\n  sink();\n}\n")])
    head = binary_commit(repo, [(b"100644", b"api.js", b"function b() {\n  sink();\n}\nfunction renamed() {\n  sink();\n}\n")])
    result = SnapshotAdapter(repo).compare(comparison(base, head), declaration_paths=())
    assert any("ambiguous_line_correspondence" in b for b in result.unresolved_boundaries)
    assert not any(m.base_start_line in (2, 5) for m in result.line_correspondences)
    assert result.decode_path(result.changed_paths[0]) == "api.js"


@pytest.mark.parametrize("limit", ["max_total_bytes", "max_diff_bytes", "max_mapping_lines", "max_files"])
def test_change_context_total_limits_are_explicit(repo: Path, limit: str) -> None:
    from openultrasast.push.snapshot import SnapshotLimits

    base = binary_commit(repo, [(b"100644", b"a.js", b"old\n"), (b"100644", b"b.js", b"old2\n")])
    head = binary_commit(repo, [(b"100644", b"a.js", b"new\n"), (b"100644", b"b.js", b"new2\n")])
    result = SnapshotAdapter(repo).compare(comparison(base, head), declaration_paths=(), limits=SnapshotLimits(**{limit: 1}))
    assert result.unresolved_boundaries
    assert not result.line_correspondences


def test_change_context_missing_blob_and_invalid_revisions_are_not_clean(repo: Path) -> None:
    base, head = commit(repo, "old\n"), commit(repo, "new\n")
    blob = git(repo, "rev-parse", base + ":file.js")
    (repo / ".git/objects" / blob[:2] / blob[2:]).unlink()
    result = SnapshotAdapter(repo).compare(comparison(base, head), declaration_paths=())
    assert result.unresolved_boundaries
    assert not result.spans and not result.line_correspondences
    result = SnapshotAdapter(repo).compare(comparison("HEAD", head), declaration_paths=())
    assert result.unresolved_boundaries == ("comparison_requires_immutable_commit_oid",)


def test_change_context_lf_lines_and_final_newline_changes(repo: Path) -> None:
    # CR, vertical tab and Unicode line separators are source bytes, not LF lines.
    before = b"first\x0b\xe2\x80\xa8\rline\noperation();\n"
    after = b"changed\x0b\xe2\x80\xa8\rline\noperation();\n"
    base = binary_commit(repo, [(b"100644", b"api.js", before)])
    head = binary_commit(repo, [(b"100644", b"api.js", after)])
    result = SnapshotAdapter(repo).compare(comparison(base, head), declaration_paths=())
    assert [(s.start_line, s.end_line) for s in result.spans] == [(1, 1), (1, 1)]
    assert [(m.base_start_line, m.head_start_line) for m in result.line_correspondences] == [(2, 2)]
    no_newline = binary_commit(repo, [(b"100644", b"api.js", after[:-1])])
    result = SnapshotAdapter(repo).compare(comparison(head, no_newline), declaration_paths=())
    assert any(s.side == "head" and s.start_line == 2 for s in result.spans)
    assert not any(m.head_start_line == 2 for m in result.line_correspondences)


def test_change_context_zero_changes_are_real_equal_objects(repo: Path) -> None:
    oid = commit(repo, "source read by Git\n")
    result = SnapshotAdapter(repo).compare(comparison(oid, oid), declaration_paths=())
    assert result.changed_paths == result.spans == result.unresolved_boundaries == ()


def test_change_context_generic_hex_contract_validation(repo: Path) -> None:
    import os
    from dataclasses import replace

    oid = binary_commit(repo, [(b"100644", b" \xff", b"a\n")])
    new = binary_commit(repo, [(b"100644", b" \xff", b"b\n")])
    context = SnapshotAdapter(repo).compare(comparison(oid, new), declaration_paths=())
    assert os.fsencode(context.decode_path(context.changed_paths[0])) == b" \xff"
    for invalid in ("zz", "00", "FF", "20 ff"):
        with pytest.raises(ValueError):
            replace(context, changed_paths=(invalid,))


def test_change_context_unmatched_move_is_not_proven_new_behavior(repo: Path) -> None:
    base = binary_commit(repo, [(b"100644", b"old.js", b"function old() {\n guard();\n sink();\n}\n")])
    head = binary_commit(repo, [(b"100644", b"new.js", b"function renamed() {\n sink();\n newCall();\n}\n")])
    result = SnapshotAdapter(repo).compare(comparison(base, head), declaration_paths=())
    assert not result.renames
    assert "unmatched_added_deleted_path_correspondence" in result.unresolved_boundaries
    assert {span.side for span in result.spans} == {"base", "head"}


def test_change_context_ambiguous_identical_file_renames_preserve_gap(repo: Path) -> None:
    payload = b"function original() {\n operation();\n}\n"
    base = binary_commit(repo, [(b"100644", b"a.js", payload), (b"100644", b"b.js", payload)])
    head = binary_commit(repo, [(b"100644", b"c.js", payload), (b"100644", b"d.js", payload)])
    result = SnapshotAdapter(repo).compare(comparison(base, head), declaration_paths=())
    assert result.renames  # Git's attribution retained, with its ambiguity alongside.
    assert not result.line_correspondences
    assert any("ambiguous_path_rename_correspondence" in b for b in result.unresolved_boundaries)
