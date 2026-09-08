# OpenUltraSAST as a local command. Source this from ~/.bashrc or ~/.zshrc:
#
#     source /path/to/OpenUltraSAST/ops/shell/ousast.sh
#
# Then use it like any other linter, from any directory:
#
#     ousast scan .
#     ousast scan src/api
#     ousast pairs --slice vibe-py
#
# Docker is an implementation detail on purpose. The engine is a JVM and ~2 GB of Joern, and a contributor
# evaluating this tool should not have to install either to try it. What they get instead is a command.
#
# The one thing worth knowing: your working directory is mounted READ-ONLY, and findings are written to
# ./.ousast, which is the only writable mount. A tool that reads your source to tell you about it has no
# business being able to change it.

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
    # should not be quietly routed through a container.
    if [ "${OUSAST_PREFER_NATIVE:-1}" = "1" ] && command -v joern-parse >/dev/null 2>&1 \
       && [ -x "$OUSAST_HOME/.venv/bin/python" ]; then
        ( cd "$OUSAST_HOME" && .venv/bin/python -m openultrasast.cli "$@" )
        return $?
    fi

    if ! command -v docker >/dev/null 2>&1; then
        echo "ousast: docker is not installed, and no local joern-parse was found" >&2
        return 1
    fi

    # Build once, silently, the first time. A first run that prints a wall of build output and then works is
    # worse than one that pauses and explains itself.
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

    mkdir -p "$PWD/.ousast"
    TARGET="$PWD" OUSAST_REPORTS="$PWD/.ousast" \
    OUSAST_NETWORK="${OUSAST_NETWORK:-none}" \
        docker compose -f "$compose" run --rm ousast "${args[@]}"
}

# The LLM judge needs the network and a key; without them the model layer still entails and only the
# `suspicion` band goes unasked. This makes that opt-in explicit rather than a surprise.
ousast-with-judge() {
    OUSAST_NETWORK=bridge ousast "$@"
}
