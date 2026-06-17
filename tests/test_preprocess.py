import json
from pathlib import Path

from openultrasast.preprocess import detect_language, preprocess_repository


def test_preprocess_emits_file_targets_with_tags(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".gitignore").write_text("ignored.c\n")
    (repo / "parser.c").write_text(
        "\n".join(
            [
                "int LLVMFuzzerTestOneInput(const unsigned char *data, int size) {",
                "  parse_frame(data, size);",
                "  return 0;",
                "}",
            ]
        )
    )
    (repo / "auth.py").write_text("def login(session):\n    return open(session)\n")
    (repo / "ignored.c").write_text("int ignored(void) { return 0; }\n")

    output = tmp_path / "file_targets.json"
    snapshot, targets = preprocess_repository(repo, output)

    assert snapshot.file_count == 2
    by_path = {target.path: target for target in targets}
    assert by_path["parser.c"].language == "c"
    assert by_path["parser.c"].has_fuzz_entry_point is True
    assert set(by_path["parser.c"].tags) >= {"memory_unsafe", "parser", "fuzzable"}
    assert set(by_path["auth.py"].tags) >= {"auth_boundary", "filesystem_entry"}

    payload = json.loads(output.read_text())
    assert payload["snapshot"]["file_count"] == 2
    assert [item["path"] for item in payload["file_targets"]] == ["auth.py", "parser.c"]


def test_detect_language_uses_shebang(tmp_path: Path) -> None:
    script = tmp_path / "tool"
    script.write_text("#!/usr/bin/env python3\nprint('ok')\n")

    assert detect_language(script) == "python"
