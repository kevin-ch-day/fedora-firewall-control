#!/usr/bin/env bash
# Install the minimal Fedora toolchain required to build fedora-firewall-control.
# This script does not modify firewalld configuration or any network settings.
set -Eeuo pipefail

readonly SCRIPT_NAME="${0##*/}"
SCRIPT_PATH="$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")" || {
    printf '[ERROR] Cannot resolve the script path.\n' >&2
    exit 1
}
readonly SCRIPT_PATH
SCRIPT_DIR="$(/usr/bin/dirname -- "$SCRIPT_PATH")"
readonly SCRIPT_DIR

bootstrap_fail() {
    printf '[ERROR] %s\n' "$*" >&2
    exit 1
}

source_trusted_library() {
    local library="$SCRIPT_DIR/lib/$1" path owner mode
    [[ "$1" =~ ^[a-z0-9-]+\.sh$ ]] || bootstrap_fail "Invalid library name: $1"
    for path in "$SCRIPT_DIR" "$SCRIPT_DIR/lib"; do
        [[ -d "$path" && ! -L "$path" ]] || bootstrap_fail "Unsafe script directory: $path"
        owner="$(/usr/bin/stat -c '%u' -- "$path")" || bootstrap_fail "Cannot inspect script directory: $path"
        mode="$(/usr/bin/stat -c '%a' -- "$path")" || bootstrap_fail "Cannot inspect script directory permissions: $path"
        [[ "$owner" == 0 || "$owner" == "$EUID" ]] || bootstrap_fail "Untrusted script directory owner: $path"
        (((8#$mode & 022) == 0)) || bootstrap_fail "Group/world-writable script directory is not trusted: $path"
    done
    [[ -f "$library" && ! -L "$library" ]] || bootstrap_fail "Required library is missing or unsafe: $library"
    owner="$(/usr/bin/stat -c '%u' -- "$library")" || bootstrap_fail "Cannot inspect library ownership: $library"
    mode="$(/usr/bin/stat -c '%a' -- "$library")" || bootstrap_fail "Cannot inspect library permissions: $library"
    [[ "$owner" == 0 || "$owner" == "$EUID" ]] || bootstrap_fail "Untrusted library owner: $library"
    (((8#$mode & 022) == 0)) || bootstrap_fail "Group/world-writable library is not trusted: $library"
    # shellcheck disable=SC1090
    source "$library"
}

source_trusted_library setup-common.sh
source_trusted_library fedora-system.sh
source_trusted_library user-prompt-common.sh
source_trusted_library menu-common.sh
source_trusted_library system-update.sh
readonly PACKAGES=(gcc-c++ cmake ninja-build firewalld iputils traceroute)

usage() {
    cat <<EOF
Usage: ./$SCRIPT_NAME
       ./$SCRIPT_NAME [--install | --check | --check-updates | --update-system | --help]

Install only the Fedora packages currently needed to build and run this
read-only firewalld controller:
  gcc-c++     C++20 compiler
  cmake       Build configuration and CTest
  ninja-build Build executor
  firewalld   The Fedora firewall service and firewall-cmd client
  iputils     Bounded ICMP reachability probes (ping)
  traceroute  Bounded numeric route diagnostics

Options:
  no option   Open the interactive development setup menu.
  --install   Install missing dependencies.
  --check     Report whether each dependency is installed; make no changes.
  --check-updates
              Contact Fedora repositories and report available system updates.
  --update-system
              Update installed Fedora packages after typed confirmation.
  --help      Show this help.

Build the project afterwards with: ./scripts/build.sh
EOF
}

check() {
    report_package_group "${PACKAGES[@]}"
}

install() {
    SETUP_PACKAGES_READY_MESSAGE="Development dependencies are already installed." \
        install_missing_packages "${PACKAGES[@]}"
}

show_menu() {
    local dependency_note='packages missing'
    package_group_installed "${PACKAGES[@]}" && dependency_note='installed'
    menu_begin 'Fedora Firewall Control — C++ development setup'
    menu_item '1)' 'Check development dependencies' 'read-only'
    menu_item '2)' 'Install development dependencies' "$dependency_note"
    menu_item '3)' 'Check for Fedora system updates' 'contacts Fedora repositories'
    menu_item '4)' 'Update the Fedora system' 'confirmation; system-wide changes'
    printf '\n'
    menu_item 'H)' 'Help'
    menu_item '0)' 'Exit'
    menu_end
}

interactive_menu() {
    local selection
    while :; do
        show_menu
        if ! menu_read_selection selection; then
            printf '\n'
            info "Input closed; exiting setup."
            return
        fi
        case "${selection,,}" in
            1) menu_run_action "Development dependency check" check ;;
            2) menu_run_action "Development dependency installation" install ;;
            3) menu_run_action "Fedora update check" check_fedora_updates ;;
            4) menu_run_action "Fedora system-update workflow" confirm_fedora_system_update ;;
            h|help|'?') usage; prompt_pause ;;
            0|q|quit|exit) info "Setup closed."; return ;;
            '') warn "Enter a menu selection." ;;
            *) warn "Unknown selection: $selection" ;;
        esac
    done
}

main() {
    local action
    (($# <= 1)) || { usage >&2; exit 2; }
    if (($# == 0)); then
        if [[ $EUID -eq 0 ]]; then
            die "The interactive setup must run as a normal user; it requests sudo internally when required."
        fi
        detect_fedora
        interactive_menu
        return
    fi
    action="$1"
    case "$action" in
        --install|--check|--check-updates|--update-system) ;;
        --help|-h) usage; return ;;
        *) usage >&2; exit 2 ;;
    esac
    detect_fedora
    case "$action" in
        --install) install ;;
        --check) check ;;
        --check-updates) check_fedora_updates ;;
        --update-system) confirm_fedora_system_update ;;
    esac
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
