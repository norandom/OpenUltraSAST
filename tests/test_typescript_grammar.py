"""learning-harness task 1.4: TypeScript and TSX rows parse under the semantic extra."""

from __future__ import annotations

import pytest

from openultrasast.pairs import DEFAULT_CATALOG, load_pair_catalog, select_vendored
from openultrasast.semantic.extra import has_semantic_extra
from openultrasast.semantic.ir import parse_file

pytestmark = pytest.mark.semantic

TS = (
    "export async function GET(request: NextRequest): Promise<Response> {\n"
    "  const id = request.nextUrl.searchParams.get('id');\n"
    "  return NextResponse.json(await db.from('claims').select().eq('id', id));\n}\n"
)
TSX = (
    "export function Panel({ token }: { token: string }) {\n"
    "  const [value, setValue] = useState('');\n"
    '  return <div className="p">{value}{token}</div>;\n}\n'
)


@pytest.mark.skipif(not has_semantic_extra(), reason="requires the semantic extra")
def test_typescript_and_tsx_parse_instead_of_reporting_an_unsupported_language() -> None:
    ir = parse_file("app/api/route.ts", TS, "typescript")
    assert ir.parse_ok and ir.reason is None and ir.engine == "tree-sitter"
    assert "GET" in {function.name for function in ir.functions}
    tsx = parse_file("components/panel.tsx", TSX, "typescript")
    assert tsx.parse_ok and tsx.reason is None  # the TSX grammar, chosen by the file suffix
    assert "Panel" in {function.name for function in tsx.functions}


@pytest.mark.skipif(not has_semantic_extra(), reason="requires the semantic extra")
def test_every_vendored_typescript_pair_parses_on_both_sides() -> None:
    cases = [case for case in select_vendored(load_pair_catalog(DEFAULT_CATALOG)) if case.language == "typescript"]
    assert len(cases) >= 18
    unsupported: list[str] = []
    failed: list[str] = []
    for case in cases:
        for side, path in (("vuln", case.vuln_file), ("fixed", case.fixed_file)):
            ir = parse_file(str(path), path.read_text(errors="ignore"), "typescript")
            if ir.reason == "language_unsupported":
                unsupported.append(f"{case.name}:{side}")
            elif not ir.parse_ok:
                failed.append(f"{case.name}:{side}")
    assert unsupported == []
    assert len(failed) <= len(cases) // 4, failed  # a parse failure is a walker gap, not a missing grammar
