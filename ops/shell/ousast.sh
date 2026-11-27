# OpenUltraSAST as a local command. Source this from ~/.bashrc or ~/.zshrc:
#
#     source /path/to/OpenUltraSAST/ops/shell/ousast.sh
#
# Then use it like any other linter, from any directory:
#
#     ousast scan .
#     ousast scan src/api
#
# Docker is an implementation detail on purpose. The engine is a JVM and ~2 GB of Joern, and a contributor
# evaluating this tool should not have to install either to try it. What they get instead is a command.
#
# The one thing worth knowing: your working directory is mounted READ-ONLY, and findings are written to
# ~/.cache/openultrasast/runs, where a native scan writes them too. That directory is mounted at /reports, the
# only writable mount, so nothing is written to the directory being scanned. A tool that reads your source to
# tell you about it has no business being able to change it.

# Resolve this script's own location so the function works from anywhere, under bash or zsh.
if [ -n "${BASH_SOURCE[0]:-}" ]; then
    _OUSAST_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
elif [ -n "${(%):-%N}" ] 2>/dev/null; then
    _OUSAST_HOME="$(cd "$(dirname "${(%):-%N}")/../.." && pwd)"
fi
export OUSAST_HOME="${OUSAST_HOME:-$_OUSAST_HOME}"

ousast() {
    local compose="$OUSAST_HOME/docker-compose.yml"
    if [ ! -f "$compose" ]; then
        echo "ousast: cannot find $compose (set OUSAST_HOME to the checkout)" >&2
        return 1
    fi

    # A native install wins when it is there: it is faster, and someone who installed Joern deliberately
    # should not be quietly routed through a container. It runs in the caller's directory, as the container
    # does, so `.`, relative names and relative options mean the caller's files. -P keeps that directory off
    # the interpreter's path, where a file of it could stand in for a module the CLI imports. Joern is looked
    # for as well: the batch queries run `joern`, and with `joern-parse` alone every one fails while the scan
    # still exits 0.
    if [ "${OUSAST_PREFER_NATIVE:-1}" = "1" ] && command -v joern >/dev/null 2>&1 \
       && command -v joern-parse >/dev/null 2>&1 && [ -x "$OUSAST_HOME/.venv/bin/python" ]; then
        "$OUSAST_HOME/.venv/bin/python" -P -m openultrasast.cli "$@"
        return $?
    fi

    if ! command -v docker >/dev/null 2>&1; then
        echo "ousast: docker is not installed, and no local joern and joern-parse were found" >&2
        return 1
    fi

    # The runs go under HOME. Both checks come before the build: on a cold one it pulls ~2 GB, and a run that
    # cannot write its runs should say so first.
    if [ -z "${HOME:-}" ]; then
        echo "ousast: HOME is not set, so there is no ~/.cache/openultrasast/runs to write the runs to" >&2
        return 1
    fi
    local runs="$HOME/.cache/openultrasast/runs"
    if ! mkdir -p "$runs"; then
        echo "ousast: cannot create $runs, where the runs are written" >&2
        return 1
    fi

    # Build once, the first time. The run says why it waits, then the build's progress shows: on a cold build it
    # is the only sign that a long download is running.
    if ! docker image inspect "openultrasast:${OUSAST_VERSION:-dev}" >/dev/null 2>&1; then
        echo "ousast: building the analysis image once (this pulls ~2 GB of engine; later runs are instant)" >&2
        ( cd "$OUSAST_HOME" && docker compose build ) || return 1
    fi

    # Rewrite paths that live under the current directory to their mounted equivalent, so `ousast scan src/api`
    # means what the user expects. Anything outside the mount is left alone and warned about rather than
    # silently rewritten into a path the container cannot see.
    local args=() a abs
    for a in "$@"; do
        if [ -e "$a" ]; then
            abs="$(cd "$(dirname "$a")" 2>/dev/null && pwd)/$(basename "$a")"
            case "$abs" in
                "$PWD") args+=("/target") ;;
                "$PWD"/*) args+=("/target${abs#"$PWD"}") ;;
                *) echo "ousast: $a is outside $PWD and is not mounted; passing it through unchanged" >&2
                   args+=("$a") ;;
            esac
        else
            args+=("$a")
        fi
    done

    # /reports is the runs directory itself here, not a reports directory with runs under it: the override puts
    # the run beside a native one, where the scan in the image prunes the expired runs as a native scan does. The
    # retention goes in without a value: compose sets it in the container only when the host has it, so a host
    # that keeps every run with 0 keeps them through the wrapper too.
    TARGET="$PWD" OUSAST_REPORTS="$runs" \
    OUSAST_NETWORK="${OUSAST_NETWORK:-none}" \
        docker compose -f "$compose" run --rm -e OPENULTRASAST_RUNS_DIR=/reports \
            -e OPENULTRASAST_RUNS_RETENTION_DAYS ousast "${args[@]}"
}

# The LLM judge needs the network and a key; without them the model layer still entails and only the
# `suspicion` band goes unasked. This makes that opt-in explicit rather than a surprise.
ousast-with-judge() {
    OUSAST_NETWORK=bridge ousast "$@"
}
