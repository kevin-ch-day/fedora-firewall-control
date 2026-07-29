#!/usr/bin/env bash
# Shared Fedora setup helpers for scripts/setup-firewall-*.sh.
# This file is a library and must be sourced by an executable setup script.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    printf '[ERROR] setup-common.sh is a library; run a setup-firewall-*.sh script instead.\n' >&2
    exit 2
fi

if [[ "${FFC_SETUP_COMMON_LOADED:-0}" == 1 ]]; then
    return 0
fi
readonly FFC_SETUP_COMMON_LOADED=1
# Shared action status consumed by menu-common.sh and system-update.sh.
# shellcheck disable=SC2034
readonly FFC_ACTION_CANCELED=125

info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[PASS] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
fail() { printf '[ERROR] %s\n' "$*" >&2; }
die() { fail "$*"; exit 1; }

require_shell_function() {
    local function_name="$1"
    declare -F "$function_name" >/dev/null 2>&1 || {
        fail "Required shell-library function is unavailable: $function_name"
        return 1
    }
}

run_privileged() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        [[ -x /usr/bin/sudo ]] || die "sudo is required to install Fedora packages."
        /usr/bin/sudo -- "$@"
    fi
}

package_installed() {
    /usr/bin/rpm -q "$1" >/dev/null 2>&1
}

package_group_installed() {
    local package
    for package in "$@"; do
        package_installed "$package" || return 1
    done
}

report_package_group() {
    local package missing=0
    for package in "$@"; do
        if package_installed "$package"; then
            ok "$package installed"
        else
            fail "$package missing"
            missing=1
        fi
    done
    return "$missing"
}

assert_packages_available() {
    local package result status
    [[ -n "$PACKAGE_MANAGER" ]] || die "Fedora package manager has not been detected."
    for package in "$@"; do
        if result="$($PACKAGE_MANAGER repoquery --available --qf '%{name}\n' "$package" 2>/dev/null)"; then
            :
        else
            status=$?
            die "Fedora repository query failed while checking '$package' (exit $status)."
        fi
        /usr/bin/grep -Fxq "$package" <<<"$result" ||
            die "Required Fedora package '$package' is unavailable from the enabled repositories."
    done
}

install_missing_packages() {
    local -a missing=()
    local package
    for package in "$@"; do
        if package_installed "$package"; then
            ok "$package installed"
        else
            missing+=("$package")
        fi
    done
    if ((${#missing[@]} == 0)); then
        ok "${SETUP_PACKAGES_READY_MESSAGE:-Requested Fedora packages are already installed.}"
        return
    fi
    info "Checking enabled Fedora repositories for: ${missing[*]}"
    assert_packages_available "${missing[@]}"
    info "Installing: ${missing[*]}"
    run_privileged "$PACKAGE_MANAGER" install -y "${missing[@]}"
    report_package_group "${missing[@]}"
}
