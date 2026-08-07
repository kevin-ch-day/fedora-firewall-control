#!/usr/bin/env bash
# Launch the compiled, loopback-only Fedora Firewall Control dashboard.

set -Eeuo pipefail

fail() {
    printf '[ERROR] %s\n' "$*" >&2
    exit 1
}

show_help() {
    cat <<'EOF'
Fedora Firewall Control launcher

Usage:
  ./run.sh
  ./run.sh --check
  ./run.sh --help

Starts the compiled local dashboard at http://127.0.0.1:8787/.
The service is loopback-only and read-only. The web server invokes the
repository-local native FFC binary for validated host snapshots.

Required prebuilt artifacts:
  build/ffc
  web/dist/server/index.js

After native source changes, run:
  ./scripts/build.sh

After web source or dependency changes, run:
  cd web
  npm run check
  cd ..

Normal use never installs packages, builds artifacts, or changes the firewall.
Press Ctrl-C to stop the foreground dashboard.
EOF
}

resolve_script_dir() {
    local source_path="${BASH_SOURCE[0]}"
    local source_dir link_target

    while [[ -h "$source_path" ]]; do
        source_dir="$(cd -P -- "$(dirname -- "$source_path")" && pwd)"
        link_target="$(readlink -- "$source_path")"
        if [[ "$link_target" == /* ]]; then
            source_path="$link_target"
        else
            source_path="${source_dir}/${link_target}"
        fi
    done

    cd -P -- "$(dirname -- "$source_path")" && pwd
}

validate_native_binary() {
    local mode

    FFC_BIN="$(realpath -e -- "${REPOSITORY_ROOT}/build/ffc" 2>/dev/null || true)"
    [[ -n "$FFC_BIN" && -f "$FFC_BIN" && -x "$FFC_BIN" ]] ||
        fail "Native FFC executable is missing or not executable: ${REPOSITORY_ROOT}/build/ffc"

    mode="$(stat -Lc '%a' -- "$FFC_BIN")"
    (( (8#$mode & 0002) == 0 )) ||
        fail "Native FFC executable must not be world-writable: $FFC_BIN"
}

validate_web_server() {
    WEB_SERVER="${REPOSITORY_ROOT}/web/dist/server/index.js"
    [[ -f "$WEB_SERVER" && -r "$WEB_SERVER" ]] || {
        printf '[ERROR] Compiled web server is missing.\n\n' >&2
        printf 'Build and validate it first:\n\n  cd web\n  npm run check\n' >&2
        exit 1
    }
}

validate_node() {
    local node_version

    command -v node >/dev/null 2>&1 || {
        printf '[ERROR] Fedora Firewall Control requires Node.js 24.\n' >&2
        printf 'Run: ./scripts/setup-firewall-web-dev.sh --check\n' >&2
        exit 1
    }

    node_version="$(node --version 2>/dev/null || true)"
    if [[ ! "$node_version" =~ ^v([0-9]+)[.] ]] || [[ "${BASH_REMATCH[1]}" != 24 ]]; then
        printf '[ERROR] Fedora Firewall Control requires Node.js 24.\n' >&2
        printf 'Run: ./scripts/setup-firewall-web-dev.sh --check\n' >&2
        exit 1
    fi
}

validate_startup() {
    validate_native_binary
    validate_web_server
    validate_node
}

if [[ "$EUID" -eq 0 ]]; then
    fail "Run Fedora Firewall Control as your normal user, not root."
fi

case "${1:-}" in
    --help)
        [[ $# -eq 1 ]] || { show_help >&2; exit 2; }
        show_help
        exit 0
        ;;
    --check)
        [[ $# -eq 1 ]] || { show_help >&2; exit 2; }
        ;;
    '')
        ;;
    *)
        printf '[ERROR] Unknown option: %s\n' "$1" >&2
        show_help >&2
        exit 2
        ;;
esac

REPOSITORY_ROOT="$(resolve_script_dir)"
FFC_BIN=""
WEB_SERVER=""
validate_startup

if [[ "${1:-}" == --check ]]; then
    printf '[PASS] Native FFC executable\n'
    printf '[PASS] Compiled web server\n'
    printf '[PASS] Node.js 24\n'
    printf '[PASS] FFC_BIN will use repository-local build/ffc\n'
    printf '[PASS] Launcher readiness\n'
    exit 0
fi

printf 'Fedora Firewall Control\n'
printf 'Local dashboard: http://127.0.0.1:8787/\n'
printf 'Access: loopback only\n'
printf 'Mode: read-only\n'
printf 'Press Ctrl-C to stop.\n'

export FFC_BIN
exec node "$WEB_SERVER"
