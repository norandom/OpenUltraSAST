# VFC training catalog

Each JSONL row is one isolated snapshot: **vuln** (positive) or **fixed** (negative).

```bash
python3 benchmarks/pairs/vfc/generate_catalog.py
```

`manifest.jsonl` fields: `id`, `pair`, `label` (`vuln`|`fixed`), `cve`, `year`, `cwe`, `project`, `file`, `relpath`, `license`, `commit`, `commit_url`.

The JSONL is the training index. Pair eval (`ousast pairs --slice vfc`) is the honesty dashboard, not a merge gate.

Filter 2020–2026:

```python
import json
from pathlib import Path
rows = [json.loads(line) for line in Path("benchmarks/pairs/vfc/training/manifest.jsonl").read_text().splitlines()]
recent = [row for row in rows if 2020 <= row["year"] <= 2026]
```

Do not treat this slice as a merge gate. Memory-safety pairs often LEAK after the fix; UAF/type-confusion often MISS inventory.
