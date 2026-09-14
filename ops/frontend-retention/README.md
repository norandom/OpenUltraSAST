# First-party JavaScript test retention

This source adaptation implements contributor-scan task 2.18 for the pinned Linux
x86-64 Joern 4.0.625 installation. ASTGen 3.50.1 excludes test directories and
filenames; jssrc2cpg additionally excludes test suffixes. Both filters must accept
the explicit inclusion policy for a retained source file to reach the graph.

`install.py` verifies pinned upstream source and tool archives and the original
jssrc2cpg jar, rebuilds ASTGen with its frozen dependency lockfile, and compiles
the adapted Scala source against Joern's shipped compiler and libraries. The
changes affect test filtering only. Original input paths, bytes and imports are
preserved. Vendor and user exclusions still apply.

Docker and `ops/joern.py` run the same installer. A manual installation requires
Python 3.12 or later, Java 21, network access for the pinned build inputs, and a
pristine matching Joern installation:

```bash
python3 ops/frontend-retention/install.py /opt/joern-cli
```

The installer writes `ousast-frontend-retention-v1/manifest.json` under the Joern
root, including builder, dependency and output hashes. A repeated invocation
verifies the installed outputs and needs no network. If the recipe or installed
outputs change, reinstall the pristine pinned engine before rebuilding; the
installer refuses to layer an unverified adaptation onto modified jars.

The adapted frontend keeps stock behavior unless `OUSAST_INCLUDE_TESTS=1`.
`JoernBackend` explicitly enables it by default; `include_tests=False` supplies
the regression control. Direct frontend users must set the variable themselves.
Engine provenance must include the installed adaptation and effective policy:
the upstream version string alone cannot distinguish these graphs.

After building the image, run `ops/smoke_partitions.py` as described in `ops/README.md`.
Its off control uses `OUSAST_SMOKE_INCLUDE_TESTS=0` and must fail the test-retention
assertion. First-party test retention does not imply security capability admission.

The 2026-09-14 retention correction adds `OUSAST_INCLUDE_BUILD_CONFIGS=1` for
`Gruntfile.js`, which Joern otherwise filters even after test retention is enabled.
`JoernBackend(include_build_configs=True)` sets this explicit default; false restores
that upstream exclusion. Other configuration/minification filters are unchanged.
The option is part of graph/runtime identity. Source paths and bytes are preserved,
and the configuration is parsed, never executed. Real NodeGoat census and the packaged
PHP/JavaScript partition smoke verify this input-retention correction separately from
hook latency, actionable detection and capability admission.
