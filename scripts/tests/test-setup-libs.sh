#!/usr/bin/env bash
# Non-destructive regression checks for scripts/lib/*.sh.
set -Eeuo pipefail

SCRIPT_PATH="$(realpath -e -- "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname -- "$SCRIPT_PATH")"
REPOSITORY_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"

# shellcheck source=scripts/lib/setup-common.sh
source "$REPOSITORY_ROOT/scripts/lib/setup-common.sh"
# shellcheck source=scripts/lib/fedora-system.sh
source "$REPOSITORY_ROOT/scripts/lib/fedora-system.sh"
# shellcheck source=scripts/lib/user-prompt-common.sh
source "$REPOSITORY_ROOT/scripts/lib/user-prompt-common.sh"
# shellcheck source=scripts/lib/menu-common.sh
source "$REPOSITORY_ROOT/scripts/lib/menu-common.sh"
# shellcheck source=scripts/lib/system-update.sh
source "$REPOSITORY_ROOT/scripts/lib/system-update.sh"

tests_run=0

pass() {
    tests_run=$((tests_run + 1))
    printf '[PASS] %s\n' "$1"
}

fail_test() {
    printf '[FAIL] %s\n' "$1" >&2
    exit 1
}

assert_equal() {
    local expected="$1" actual="$2" label="$3"
    [[ "$actual" == "$expected" ]] ||
        fail_test "$label (expected '$expected', received '$actual')"
    pass "$label"
}

test_duplicate_sources() {
    source "$REPOSITORY_ROOT/scripts/lib/setup-common.sh"
    source "$REPOSITORY_ROOT/scripts/lib/fedora-system.sh"
    source "$REPOSITORY_ROOT/scripts/lib/user-prompt-common.sh"
    source "$REPOSITORY_ROOT/scripts/lib/menu-common.sh"
    source "$REPOSITORY_ROOT/scripts/lib/system-update.sh"
    pass "libraries tolerate duplicate sourcing"
}

test_fedora_release_parsing() {
    (
        read_fedora_release <(printf 'ID=fedora\nPRETTY_NAME="Fedora Test"\nVERSION_ID=44\n')
        [[ "$FEDORA_RELEASE" == 44 && "$FEDORA_NAME" == "Fedora Test" ]]
    ) || fail_test "Fedora release fixture is accepted"
    pass "Fedora release fixture is accepted"

    if (read_fedora_release <(printf 'ID=debian\nPRETTY_NAME="Debian Test"\n') >/dev/null 2>&1); then
        fail_test "non-Fedora fixture is rejected"
    fi
    pass "non-Fedora fixture is rejected"
}

test_prompt_assignment() {
    local captured=""
    prompt_read captured '' <<<"DEFCON"
    assert_equal DEFCON "$captured" "prompt input is assigned without evaluation"
}

test_prompt_output_name_collision() {
    local response=""
    prompt_read response '' <<<"CANCEL"
    assert_equal CANCEL "$response" "prompt output does not collide with framework internals"
}

test_menu_rendering() {
    local rendered status_rendered
    rendered="$(menu_item '1)' 'Check prerequisites' 'read-only')"
    [[ "$rendered" == *'Check prerequisites'* && "$rendered" == *'read-only'* ]] ||
        fail_test "menu item renders its label and note"
    pass "menu item renders its label and note"
    status_rendered="$(menu_status_item 'Runtime' '[READY] Node v24')"
    [[ "$status_rendered" == *'Runtime'* && "$status_rendered" == *'[READY] Node v24'* ]] ||
        fail_test "menu status item renders its label and state"
    pass "menu status item renders its label and state"
}

test_menu_selection_normalization() {
    local selection=""
    menu_read_selection selection <<<"  H  " >/dev/null
    assert_equal H "$selection" "menu selection trims surrounding whitespace"
    menu_read_selection selection <<<".6" >/dev/null
    assert_equal 6 "$selection" "menu selection accepts an accidental leading period"
    menu_read_selection selection <<<"6)" >/dev/null
    assert_equal 6 "$selection" "menu selection accepts a rendered menu suffix"
    menu_read_selection selection <<<"[6]" >/dev/null
    assert_equal 6 "$selection" "menu selection accepts bracketed keys"
}

test_unavailable_menu_action() {
    local output status
    if output="$(menu_unavailable_action 'Dependency audit' 'initialize web first' 2>&1)"; then
        status=0
    else
        status=$?
    fi
    assert_equal 0 "$status" "unavailable menu action is informational"
    [[ "$output" == *'Dependency audit is unavailable: initialize web first'* ]] ||
        fail_test "unavailable menu action explains its prerequisite"
    pass "unavailable menu action explains its prerequisite"
}

test_update_status_semantics() {
    local status
    PACKAGE_MANAGER=dnf5
    # Invoked indirectly through the PACKAGE_MANAGER variable.
    # shellcheck disable=SC2329
    dnf5() { return 100; }
    check_fedora_updates >/dev/null 2>&1 || fail_test "DNF status 100 means updates are available"
    pass "DNF status 100 means updates are available"

    # shellcheck disable=SC2329
    dnf5() { return 37; }
    if check_fedora_updates >/dev/null 2>&1; then
        fail_test "unexpected DNF errors remain failures"
    else
        status=$?
    fi
    assert_equal 37 "$status" "unexpected DNF errors preserve their status"
    unset -f dnf5
}

test_repository_query_errors_are_distinct() {
    local output status
    if output="$(
        /usr/bin/bash -c '
            source "$1"
            PACKAGE_MANAGER=dnf5
            dnf5() { return 37; }
            assert_packages_available example-package
        ' _ "$REPOSITORY_ROOT/scripts/lib/setup-common.sh" 2>&1
    )"; then
        status=0
    else
        status=$?
    fi
    assert_equal 1 "$status" "repository query failure stops package validation"
    [[ "$output" == *"repository query failed"* && "$output" == *"exit 37"* ]] ||
        fail_test "repository query failure preserves its diagnostic"
    pass "repository query failure preserves its diagnostic"
}

test_update_command_is_inert_and_bounded() {
    local -a captured_args=()
    PACKAGE_MANAGER=dnf5
    verify_rpm_database() { :; }
    report_reboot_state() { :; }
    run_privileged() { captured_args=("$@"); }
    update_fedora_system >/dev/null 2>&1
    local joined=" ${captured_args[*]} "
    [[ "$joined" == *' dnf5 upgrade --refresh -y '* ]] ||
        fail_test "system update uses the bounded DNF upgrade command"
    [[ "$joined" != *'--allowerasing'* ]] ||
        fail_test "system update never enables allowerasing"
    pass "system update command is explicit and excludes allowerasing"
}

test_noninteractive_confirmation() {
    local status
    update_fedora_system() { fail_test "noninteractive confirmation invoked the updater"; }
    if confirm_fedora_system_update </dev/null >/dev/null 2>&1; then
        status=0
    else
        status=$?
    fi
    assert_equal 2 "$status" "noninteractive system-update confirmation is refused"
}

test_canceled_confirmation_status() {
    local status
    prompt_confirm_phrase() { return 1; }
    update_fedora_system() { fail_test "canceled confirmation invoked the updater"; }
    if confirm_fedora_system_update >/dev/null 2>&1; then
        status=0
    else
        status=$?
    fi
    assert_equal "$FFC_ACTION_CANCELED" "$status" "canceled confirmation has a distinct status"
}

test_library_dependency_contract() {
    if /usr/bin/bash -c "source '$REPOSITORY_ROOT/scripts/lib/menu-common.sh'" >/dev/null 2>&1; then
        fail_test "menu library enforces its source-order contract"
    fi
    pass "menu library enforces its source-order contract"
}

test_library_name_validation() {
    if (
        source "$REPOSITORY_ROOT/scripts/setup-firewall-dev.sh"
        source_trusted_library '../outside.sh'
    ) >/dev/null 2>&1; then
        fail_test "trusted loader rejects path traversal"
    fi
    pass "trusted loader rejects path traversal"
}

test_missing_web_workspace_stops_cleanly() {
    local missing_workspace="$REPOSITORY_ROOT/.ffc-missing-web-test" output status
    [[ ! -e "$missing_workspace" ]] || fail_test "missing-workspace fixture path must not exist"
    if output="$(
        FFC_WEB_DIR="$missing_workspace" /usr/bin/bash -c '
            source "$1"
            require_node24_for_npm() { :; }
            install_dependencies
        ' _ "$REPOSITORY_ROOT/scripts/setup-firewall-web-dev.sh" 2>&1
    )"; then
        status=0
    else
        status=$?
    fi
    assert_equal 1 "$status" "missing web workspace returns one failure"
    [[ "$output" == *"Web workspace directory does not exist"* ]] ||
        fail_test "missing web workspace reports its root cause"
    [[ "$output" != *'/package.json'* && "$output" != *'sha256sum:'* && "$output" != *'npm ci'* && "$output" != *'null directory'* ]] ||
        fail_test "missing web workspace does not cascade into secondary errors"
    pass "missing web workspace stops before manifest and npm operations"
}

test_web_workspace_initializer() {
    local fixture output resolved_workspace status
    fixture="$(/usr/bin/mktemp -d)" || fail_test "web initializer fixture can be created"
    /usr/bin/mkdir -p -- "$fixture/scripts"
    /usr/bin/cp -- "$REPOSITORY_ROOT/scripts/setup-firewall-web-dev.sh" "$fixture/scripts/"
    /usr/bin/cp -a -- "$REPOSITORY_ROOT/scripts/lib" "$REPOSITORY_ROOT/scripts/templates" "$fixture/scripts/"
    if ! /usr/bin/bash -c '
        source "$1/scripts/setup-firewall-web-dev.sh"
        initialize_web_workspace
    ' _ "$fixture" >/dev/null 2>&1; then
        /usr/bin/rm -rf -- "$fixture"
        fail_test "web initializer creates a workspace from the offline template"
    fi
    [[ -f "$fixture/web/package.json" && -f "$fixture/web/package-lock.json" ]] || {
        /usr/bin/rm -rf -- "$fixture"
        fail_test "web initializer creates both npm manifests"
    }
    /usr/bin/jq -e '.private == true' "$fixture/web/package.json" >/dev/null || {
        /usr/bin/rm -rf -- "$fixture"
        fail_test "initialized package is private"
    }
    if ! /usr/bin/bash -c '
        source "$1/scripts/setup-firewall-web-dev.sh"
        web_manifests_authorized_for_npm
    ' _ "$fixture" >/dev/null 2>&1; then
        /usr/bin/rm -rf -- "$fixture"
        fail_test "the exact offline starter must enable npm actions"
    fi
    resolved_workspace="$(/usr/bin/bash -c '
        source "$1/scripts/setup-firewall-web-dev.sh"
        require_workspace_for_npm
    ' _ "$fixture" 2>/dev/null)" || {
        /usr/bin/rm -rf -- "$fixture"
        fail_test "trusted starter workspace resolves for npm"
    }
    [[ "$resolved_workspace" == "$fixture/web" ]] || {
        /usr/bin/rm -rf -- "$fixture"
        fail_test "workspace resolver stdout contains only the canonical path"
    }
    /usr/bin/cp -- "$fixture/web/package-lock.json" "$fixture/package-lock.valid"
    /usr/bin/jq '.version = "mismatch"' "$fixture/web/package-lock.json" >"$fixture/package-lock.invalid"
    /usr/bin/mv -- "$fixture/package-lock.invalid" "$fixture/web/package-lock.json"
    if /usr/bin/bash -c '
        source "$1/scripts/setup-firewall-web-dev.sh"
        validate_workspace_manifest_contract "$1/web"
    ' _ "$fixture" >/dev/null 2>&1; then
        /usr/bin/rm -rf -- "$fixture"
        fail_test "manifest contract rejects a package-lock version mismatch"
    fi
    /usr/bin/cp -- "$fixture/package-lock.valid" "$fixture/web/package-lock.json"
    pass "manifest contract rejects package and lockfile drift"
    /usr/bin/cp -- "$fixture/web/.npmrc" "$fixture/npmrc.valid"
    /usr/bin/printf '%s\n' 'ignore-scripts=false' >>"$fixture/web/.npmrc"
    if /usr/bin/bash -c '
        source "$1/scripts/setup-firewall-web-dev.sh"
        require_safe_npm_policy_file "$1/web"
    ' _ "$fixture" >/dev/null 2>&1; then
        /usr/bin/rm -rf -- "$fixture"
        fail_test "npm policy rejects a conflicting ignore-scripts override"
    fi
    /usr/bin/cp -- "$fixture/npmrc.valid" "$fixture/web/.npmrc"
    pass "npm policy rejects conflicting lifecycle-script settings"
    /usr/bin/git -C "$fixture" init -q
    /usr/bin/git -C "$fixture" config user.name 'FFC setup test'
    /usr/bin/git -C "$fixture" config user.email 'ffc-setup-test@invalid'
    /usr/bin/git -C "$fixture" add -- web/package.json web/package-lock.json
    /usr/bin/git -C "$fixture" commit -qm 'test: add web manifests'
    if ! /usr/bin/bash -c '
        source "$1/scripts/setup-firewall-web-dev.sh"
        web_manifests_committed_for_menu
    ' _ "$fixture" >/dev/null 2>&1; then
        /usr/bin/rm -rf -- "$fixture"
        fail_test "committed clean manifests enable npm actions"
    fi
    if output="$(/usr/bin/bash -c '
        source "$1/scripts/setup-firewall-web-dev.sh"
        initialize_web_workspace
    ' _ "$fixture" 2>&1)"; then
        status=0
    else
        status=$?
    fi
    assert_equal 1 "$status" "web initializer refuses an existing workspace"
    [[ "$output" == *'Refusing to overwrite'* ]] || {
        /usr/bin/rm -rf -- "$fixture"
        fail_test "web initializer explains overwrite protection"
    }
    /usr/bin/rm -rf -- "$fixture"
    pass "web initializer creates valid manifests and preserves existing workspaces"
}

test_bounded_snapshot_timeout() {
    local fixture status
    fixture="$(/usr/bin/mktemp -d)" || fail_test "snapshot timeout fixture can be created"
    /usr/bin/printf '%s\n' '#!/usr/bin/sh' '/usr/bin/sleep 3' >"$fixture/slow-ffc"
    /usr/bin/chmod 700 "$fixture/slow-ffc"
    if /usr/bin/bash -c '
        source "$1"
        run_bounded_ffc_snapshot "$2" "$3" "$4" 1 128
    ' _ "$REPOSITORY_ROOT/scripts/setup-firewall-web-dev.sh" "$fixture/slow-ffc" "$fixture/stdout" "$fixture/stderr"; then
        status=0
    else
        status=$?
    fi
    [[ "$status" == 124 || "$status" == 137 ]] || {
        /usr/bin/rm -rf -- "$fixture"
        fail_test "bounded snapshot runner terminates a hung producer"
    }
    /usr/bin/rm -rf -- "$fixture"
    pass "bounded snapshot runner terminates a hung producer"
}

test_direct_system_update_requires_confirmation() {
    local script output status
    for script in setup-firewall-dev.sh setup-firewall-web-dev.sh; do
        if output="$("$REPOSITORY_ROOT/scripts/$script" --update-system </dev/null 2>&1)"; then
            status=0
        else
            status=$?
        fi
        assert_equal 2 "$status" "$script refuses a noninteractive system update"
        [[ "$output" == *'confirmation requires an interactive terminal'* ]] ||
            fail_test "$script reports its confirmation requirement"
        [[ "$output" != *'upgrade --refresh'* ]] ||
            fail_test "$script reached the Fedora upgrade command without confirmation"
    done
}

test_non_fedora_node_provider_is_rejected() {
    local output status
    if output="$(
        /usr/bin/bash -c '
            source "$1"
            command() { printf "/usr/bin/true\n"; }
            resolve_fedora_node_commands
        ' _ "$REPOSITORY_ROOT/scripts/setup-firewall-web-dev.sh" 2>&1
    )"; then
        status=0
    else
        status=$?
    fi
    assert_equal 1 "$status" "non-Fedora Node command provider is rejected"
    [[ "$output" == *'not provided by Fedora nodejs24-bin'* ]] ||
        fail_test "Node provider rejection explains the Fedora policy"
    pass "Node provider rejection explains the Fedora policy"
}

test_duplicate_sources
test_fedora_release_parsing
test_prompt_assignment
test_prompt_output_name_collision
test_menu_rendering
test_menu_selection_normalization
test_unavailable_menu_action
test_update_status_semantics
test_repository_query_errors_are_distinct
test_update_command_is_inert_and_bounded
test_noninteractive_confirmation
test_canceled_confirmation_status
test_library_dependency_contract
test_library_name_validation
test_missing_web_workspace_stops_cleanly
test_web_workspace_initializer
test_bounded_snapshot_timeout
test_direct_system_update_requires_confirmation
test_non_fedora_node_provider_is_rejected

printf '[PASS] %s setup-library regression checks completed.\n' "$tests_run"
