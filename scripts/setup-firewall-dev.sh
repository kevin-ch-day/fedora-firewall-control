#!/usr/bin/env bash
# Install the minimal Fedora toolchain required to build fedora-firewall-control.
# This script does not modify firewalld configuration or any network settings.
set -Eeuo pipefail

readonly SCRIPT_NAME="${0##*/}"
readonly PACKAGES=(gcc-c++ cmake ninja-build firewalld iputils traceroute)
PACKAGE_MANAGER=""

info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[ERROR] %s\n' "$*" >&2; }
die() { fail "$*"; exit 1; }

usage() {
    cat <<EOF
Usage: ./$SCRIPT_NAME [--install | --check | --help]

Install only the Fedora packages currently needed to build and run this
read-only firewalld controller:
  gcc-c++     C++20 compiler
  cmake       Build configuration and CTest
  ninja-build Build executor
  firewalld   The Fedora firewall service and firewall-cmd client
  iputils     Bounded ICMP reachability probes (ping)
  traceroute  Bounded numeric route diagnostics

Options:
  --install   Install missing dependencies (default).
  --check     Report whether each dependency is installed; make no changes.
  --help      Show this help.

Build the project afterwards with: ./scripts/build.sh
EOF
}

detect_fedora() {
    [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release."
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == fedora ]] || die "Fedora is required (detected: ${PRETTY_NAME:-unknown})."
    if command -v dnf5 >/dev/null 2>&1; then
        PACKAGE_MANAGER=dnf5
    elif command -v dnf >/dev/null 2>&1; then
        PACKAGE_MANAGER=dnf
    else
        die "Neither dnf5 nor dnf is installed."
    fi
}

run_privileged() {
    if [[ $EUID -eq 0 ]]; then "$@"
    else
        command -v sudo >/dev/null 2>&1 || die "sudo is required to install packages."
        sudo "$@"
    fi
}

check() {
    local missing=0 package
    for package in "${PACKAGES[@]}"; do
        if rpm -q "$package" >/dev/null 2>&1; then ok "$package installed"
        else fail "$package missing"; missing=1
        fi
    done
    return "$missing"
}

install() {
    local -a missing=()
    local package
    for package in "${PACKAGES[@]}"; do
        if rpm -q "$package" >/dev/null 2>&1; then ok "$package installed"
        else missing+=("$package")
        fi
    done
    if ((${#missing[@]} == 0)); then ok "Development dependencies are already installed."; return; fi
    info "Installing: ${missing[*]}"
    run_privileged "$PACKAGE_MANAGER" install -y "${missing[@]}"
    check
}

main() {
    detect_fedora
    case "${1:---install}" in
        --install) install ;;
        --check) check ;;
        --help|-h) usage ;;
        *) usage >&2; exit 2 ;;
    esac
}
main "$@"
