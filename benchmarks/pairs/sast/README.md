# SAST bake-off slice (OWASP + Juliet + Python)

Labeled true/false cases from the suites SAST papers actually quote. Not
cheat-sheet fixtures and not the 90% smoke gate.

| Suite | Upstream | License | Protocol |
| --- | --- | --- | --- |
| OWASP Benchmark Java v1.2 | [OWASP-Benchmark/BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) | GPL-2.0 | true file = TP if we fire; false file = FP if we fire. Score = TPR − FPR. |
| OWASP Benchmark Python v0.1 | [OWASP-Benchmark/BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) | GPL-3.0 | Same CSV protocol (`expectedresults-0.1.csv`). |
| Juliet C 1.3 | [arichardson/juliet-test-suite-c](https://github.com/arichardson/juliet-test-suite-c) | CC0 | `bad()` vs `goodB2G()` / `goodG2B()`. |
| Juliet Java 1.3 | [UnitTestBot/juliet-java-test-suite](https://github.com/UnitTestBot/juliet-java-test-suite) | CC0 | `bad()` vs `goodG2B()` (same sink, hardcoded source). |

This directory vendors a **representative slice**, not the full 2,740 / 180k cases.

```bash
uv run ousast pairs --slice sast
```

`slice=sast` is an honesty dashboard: CI still only fails the local fixture pairs.
Juliet `goodG2B` often keeps the dangerous sink (`strcpy`, `Runtime.exec`); a
regex harness is *supposed* to keep firing there.
