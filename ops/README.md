# ops

Infrastructure for the optional engines. Nothing here is a project dependency: the core install is
`dependencies = []` and every engine below degrades to a recorded reason when it is absent.

## Use it as a command

Source the wrapper once and Docker stops being something you think about:

```bash
# ~/.bashrc or ~/.zshrc
source /path/to/OpenUltraSAST/ops/shell/ousast.sh
```

```powershell
# $PROFILE
. C:\path\to\OpenUltraSAST\ops\shell\ousast.ps1
```

Then, from any directory:

```bash
ousast scan .
ousast scan src/api
ousast-with-judge scan .     # opt into the LLM judge: needs network and a key
```

The wrapper rewrites paths under your working directory to their mounted equivalents, so `src/api` means what
you expect. Anything outside the mount is passed through unchanged with a warning rather than silently
rewritten into a path the container cannot see. Your directory is mounted **read-only**; findings go to
`./.ousast`, the one writable mount. The image builds itself on first use and says so.

If `joern-parse` is already on your PATH and a local venv exists, the wrapper uses those instead — someone who
installed the engine deliberately should not be quietly routed through a container. Set
`OUSAST_PREFER_NATIVE=0` to always containerise.

## Two ways to get the engine

**Docker (recommended for contributors).** The tool and Joern ship in one image, so nothing is installed on
the host and there is no container-to-container call, no docker socket, and no host/container path
translation:

```bash
docker compose build
TARGET=/path/to/repo docker compose run --rm ousast scan /target
```

The target is mounted read-only; `/work` is a tmpfs so CPG scratch never outlives the run. The LLM endpoint
is optional and passed through the environment, never baked into a layer — without it the model layer still
entails and only the `suspicion` band goes unasked. `network_mode` defaults to `none`; set it to `bridge`
only when you want the judge.

**pyinfra (for a persistent host install).** Same engine, same pin, same checksum, but on the machine:

```bash
uv pip install pyinfra              # tooling only
pyinfra @local ops/joern.py         # this machine
```

Pin the version and its checksum in an inventory rather than editing the deploy:

```python
# inventory.py
hosts = [("@local", {"joern_version": "v4.0.623", "joern_prefix": "/opt/joern"})]
```

The checksum needs no inventory entry: the deploy fetches the `.sha512` upstream publishes beside the
archive and runs `sha512sum -c` against it, before unpacking. (pyinfra's `files.download` offers
sha384/sha256/sha1/md5 but not sha512, which is what Joern publishes — so verification is an explicit
shell step rather than a download argument.)

Why this exists: Joern was first installed here by hand with `curl` and `unzip`, which is fine once and
unreproducible thereafter. The engine decides whether a finding is a `suspicion` or a `model_entailed`, and
every ceiling number in `benchmarks/measurements` is only comparable against a fixed version — so the version
is pinned, the download is checksum-verified, and a re-run with a matching stamp is a no-op.

It installs an engine; it does not become one. No sandbox, no container, no service. `openultrasast.cpg.backend`
reaches Joern by subprocess and this changes nothing about that.

## What we actually use from Joern

A small, deliberately narrow surface — worth stating, because it is what determines whether a given Joern
version works for us:

| entry point | use |
|---|---|
| `joern-parse <src> --output cpg.bin` | build the CPG |
| `joern --script q.sc --param k=v` | run a shipped CPGQL query, JSON fenced on stdout |

CPGQL steps, all of them in `src/openultrasast/cpg/queries/*.sc`:

| step | why |
|---|---|
| `cpg.call` / `cpg.method` / `cpg.identifier` | locate sinks, operations, sources |
| `.reachableByFlows` | the interprocedural dataflow the flat IR could not do |
| `.argument`, `.argumentIndexGt(0)` | arity and the safe-shape test — index 0 is the receiver, named args are −1 |
| `.ast.isLiteral` | constant abstraction; a keyword argument is assignment-shaped so the literal sits in its subtree |
| `.dominatedBy`, `.controlledBy` | guard dominance for absence bugs; `controlledBy` is what catches a check that runs *after* the fetch |
| `.controlStructure.condition` | identity branches |
| `.method.filename` / `.lineNumber` / `.lineNumberEnd` | closure scoping by line-range containment |
| `.methodFullName` | resolved sink matching |
| `ujson` | the fenced JSON payload |

No Joern server mode, no workspace/project management, no `joern-scan`, no overlays beyond the defaults.

## Languages

Joern ships frontends for C/C++, Java (source and bytecode), JavaScript/TypeScript, Python, Kotlin, Go, C#,
PHP, ABAP and Ghidra binaries. We currently model **python, javascript, java, c**.

**PHP works but needs a PHP interpreter**: `php2cpg` drives PHP-Parser and shells out to `php`, so on a host
without it a PHP tree fails to build with an opaque "Process exited with code 1". Set `php_frontend: True` in
the inventory to install `php-cli` alongside the JVM.
