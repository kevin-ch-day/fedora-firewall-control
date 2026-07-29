#!/usr/bin/env bash
# Fedora platform detection shared by the project setup scripts.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    printf '[ERROR] fedora-system.sh is a library; run a setup-firewall-*.sh script instead.\n' >&2
    exit 2
fi

if [[ "${FFC_FEDORA_SYSTEM_LOADED:-0}" == 1 ]]; then
    return 0
fi
declare -F require_shell_function >/dev/null 2>&1 || {
    printf '[ERROR] fedora-system.sh requires setup-common.sh to be sourced first.\n' >&2
    return 1
}
require_shell_function die || return 1
require_shell_function info || return 1
readonly FFC_FEDORA_SYSTEM_LOADED=1

PACKAGE_MANAGER="${PACKAGE_MANAGER:-}"
FEDORA_RELEASE="${FEDORA_RELEASE:-unknown}"
FEDORA_NAME="${FEDORA_NAME:-unknown}"

read_fedora_release() {
    local release_file="$1" ID="" PRETTY_NAME="unknown" VERSION_ID="unknown"
    [[ -r "$release_file" ]] || die "Cannot read operating-system release data: $release_file"
    # shellcheck disable=SC1090
    source "$release_file"
    [[ "${ID:-}" == fedora ]] || die "Fedora is required (detected: ${PRETTY_NAME:-unknown})."
    FEDORA_RELEASE="${VERSION_ID:-unknown}"
    FEDORA_NAME="${PRETTY_NAME:-Fedora Linux}"
}

detect_fedora_package_manager() {
    if [[ -x /usr/bin/dnf5 ]]; then
        PACKAGE_MANAGER=/usr/bin/dnf5
    elif [[ -x /usr/bin/dnf ]]; then
        PACKAGE_MANAGER=/usr/bin/dnf
    else
        die "Neither dnf5 nor dnf is installed."
    fi
}

detect_fedora() {
    read_fedora_release /etc/os-release
    detect_fedora_package_manager
}

report_fedora_system() {
    [[ -n "$PACKAGE_MANAGER" ]] || detect_fedora
    info "Fedora system: $FEDORA_NAME"
    info "Fedora release: $FEDORA_RELEASE"
    info "Package manager: $PACKAGE_MANAGER"
}
