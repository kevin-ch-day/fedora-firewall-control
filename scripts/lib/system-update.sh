#!/usr/bin/env bash
# Explicit Fedora system-update operations shared by project setup scripts.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    printf '[ERROR] system-update.sh is a library; run a setup-firewall-*.sh script instead.\n' >&2
    exit 2
fi

if [[ "${FFC_SYSTEM_UPDATE_LOADED:-0}" == 1 ]]; then
    return 0
fi
declare -F require_shell_function >/dev/null 2>&1 || {
    printf '[ERROR] system-update.sh requires setup-common.sh to be sourced first.\n' >&2
    return 1
}
require_shell_function detect_fedora || return 1
require_shell_function run_privileged || return 1
require_shell_function prompt_confirm_phrase || return 1
readonly FFC_SYSTEM_UPDATE_LOADED=1

require_fedora_package_manager() {
    [[ -n "${PACKAGE_MANAGER:-}" ]] || detect_fedora
}

check_fedora_updates() {
    local status
    require_fedora_package_manager
    info "Checking Fedora repositories for available system updates."
    if "$PACKAGE_MANAGER" check-upgrade --refresh; then
        status=0
    else
        status=$?
    fi
    case "$status" in
        0)
            ok "No Fedora system updates are currently available."
            return 0
            ;;
        100)
            warn "Fedora system updates are available."
            return 0
            ;;
        *)
            fail "The Fedora update check failed with exit $status."
            return "$status"
            ;;
    esac
}

verify_rpm_database() {
    info "Verifying the RPM database before the system update."
    /usr/bin/rpm --verifydb >/dev/null 2>&1 ||
        die "RPM database verification failed; repair it before attempting a system update."
    ok "RPM database verification passed"
}

run_fedora_upgrade_transaction() {
    local status
    if [[ -x /usr/bin/systemd-inhibit ]]; then
        info "Blocking shutdown and sleep while the package transaction is active."
        if run_privileged /usr/bin/systemd-inhibit \
            --what=shutdown:sleep \
            --who="Fedora Firewall Control setup" \
            --why="Fedora package update in progress" \
            --mode=block \
            "$PACKAGE_MANAGER" upgrade --refresh -y; then
            status=0
        else
            status=$?
        fi
    elif run_privileged "$PACKAGE_MANAGER" upgrade --refresh -y; then
        status=0
    else
        status=$?
    fi
    if ((status != 0)); then
        fail "Fedora package update failed with exit $status."
        return "$status"
    fi
}

report_reboot_state() {
    if [[ -x /usr/bin/needs-restarting ]]; then
        if /usr/bin/needs-restarting -r >/dev/null 2>&1; then
            ok "No reboot requirement was detected."
        else
            warn "A reboot is recommended to finish applying system updates."
        fi
    else
        info "Reboot detection is unavailable; review the transaction for kernel or core-library updates."
    fi
}

update_fedora_system() {
    require_fedora_package_manager
    warn "This operation updates installed Fedora packages system-wide."
    info "Running: $PACKAGE_MANAGER upgrade --refresh -y"
    verify_rpm_database
    run_fedora_upgrade_transaction
    ok "Fedora system package update completed."
    report_reboot_state
}

confirm_fedora_system_update() {
    local status
    warn "This will update installed Fedora packages and may require a reboot."
    if prompt_confirm_phrase UPDATE 'Type UPDATE to continue: '; then
        update_fedora_system
    else
        status=$?
        if ((status == 1)); then
            info "System update canceled."
            return "$FFC_ACTION_CANCELED"
        fi
        return "$status"
    fi
}
