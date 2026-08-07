#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
LAUNCHER="${REPOSITORY_ROOT}/run.sh"
TEMP_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_ROOT"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

expect_status() {
    local expected=$1
    shift
    set +e
    "$@" >/dev/null 2>&1
    local actual=$?
    set -e
    [[ "$actual" -eq "$expected" ]] || fail "expected exit ${expected}, got ${actual}: $*"
}

FIXTURE_ROOT="${TEMP_ROOT}/fixture repository"
mkdir -p "${FIXTURE_ROOT}/build" "${FIXTURE_ROOT}/web/dist/server" "${TEMP_ROOT}/node-bin" "${TEMP_ROOT}/empty-path"
cp -- "$LAUNCHER" "${FIXTURE_ROOT}/run.sh"
chmod 755 "${FIXTURE_ROOT}/run.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"${FIXTURE_ROOT}/build/ffc"
chmod 755 "${FIXTURE_ROOT}/build/ffc"
printf 'export {};\n' >"${FIXTURE_ROOT}/web/dist/server/index.js"

cat >"${TEMP_ROOT}/node-bin/node" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == --version ]]; then
    printf '%s\n' "${FAKE_NODE_VERSION:-v24.20.0}"
    exit 0
fi
printf '%s\n' "${FFC_BIN:-missing}" >"${RUN_SH_TEST_CAPTURE:?}"
EOF
chmod 755 "${TEMP_ROOT}/node-bin/node"

expect_status 0 "$LAUNCHER" --help
expect_status 2 "$LAUNCHER" --unknown
expect_status 1 env PATH="${TEMP_ROOT}/empty-path" /usr/bin/bash "${FIXTURE_ROOT}/run.sh" --check
expect_status 1 env PATH="${TEMP_ROOT}/node-bin:${PATH}" FAKE_NODE_VERSION=v22.9.0 "${FIXTURE_ROOT}/run.sh" --check
expect_status 0 env PATH="${TEMP_ROOT}/node-bin:${PATH}" FAKE_NODE_VERSION=v24.13.1 "${FIXTURE_ROOT}/run.sh" --check

mv "${FIXTURE_ROOT}/build/ffc" "${FIXTURE_ROOT}/build/ffc.missing"
expect_status 1 env PATH="${TEMP_ROOT}/node-bin:${PATH}" "${FIXTURE_ROOT}/run.sh" --check
mv "${FIXTURE_ROOT}/build/ffc.missing" "${FIXTURE_ROOT}/build/ffc"

chmod 777 "${FIXTURE_ROOT}/build/ffc"
expect_status 1 env PATH="${TEMP_ROOT}/node-bin:${PATH}" "${FIXTURE_ROOT}/run.sh" --check
chmod 755 "${FIXTURE_ROOT}/build/ffc"

mv "${FIXTURE_ROOT}/web/dist/server/index.js" "${FIXTURE_ROOT}/web/dist/server/index.js.missing"
expect_status 1 env PATH="${TEMP_ROOT}/node-bin:${PATH}" "${FIXTURE_ROOT}/run.sh" --check
mv "${FIXTURE_ROOT}/web/dist/server/index.js.missing" "${FIXTURE_ROOT}/web/dist/server/index.js"

before_listeners="$(ss -H -lnt | grep -c ':8787' || true)"
expect_status 0 env PATH="${TEMP_ROOT}/node-bin:${PATH}" "${FIXTURE_ROOT}/run.sh" --check
after_listeners="$(ss -H -lnt | grep -c ':8787' || true)"
[[ "$before_listeners" == "$after_listeners" ]] || fail "--check opened a listener"

capture_file="${TEMP_ROOT}/ffc-bin"
RUN_SH_TEST_CAPTURE="$capture_file" FFC_BIN=/untrusted/path PATH="${TEMP_ROOT}/node-bin:${PATH}" "${FIXTURE_ROOT}/run.sh"
[[ "$(<"$capture_file")" == "${FIXTURE_ROOT}/build/ffc" ]] || fail "caller FFC_BIN was not replaced"

if command -v unshare >/dev/null 2>&1; then
    set +e
    root_output="$(unshare --user --map-root-user -- /usr/bin/bash "${FIXTURE_ROOT}/run.sh" --check 2>&1)"
    root_result=$?
    set -e
    [[ "$root_result" -eq 1 ]] || fail "root-execution fixture returned ${root_result}"
    [[ "$root_output" == *'not root'* ]] || fail "root execution was not rejected"
fi

printf 'Launcher tests passed.\n'
