#!/usr/bin/env bash
# Shared compact terminal-menu rendering and action helpers.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    printf '[ERROR] menu-common.sh is a library; run a project script instead.\n' >&2
    exit 2
fi

if [[ "${FFC_MENU_COMMON_LOADED:-0}" == 1 ]]; then
    return 0
fi
declare -F require_shell_function >/dev/null 2>&1 || {
    printf '[ERROR] menu-common.sh requires setup-common.sh to be sourced first.\n' >&2
    return 1
}
require_shell_function prompt_read || return 1
require_shell_function prompt_pause || return 1
readonly FFC_MENU_COMMON_LOADED=1

readonly MENU_RULE='------------------------------------------------------------------------'

menu_begin() {
    local title="$1"
    printf '\n%s\n%s\n' "$title" "$MENU_RULE"
}

menu_item() {
    local key="$1" label="$2" note="${3:-}"
    if [[ -n "$note" ]]; then
        printf '  %-3s %-40s %s\n' "$key" "$label" "$note"
    else
        printf '  %-3s %s\n' "$key" "$label"
    fi
}

menu_status_item() {
    local label="$1" value="$2"
    printf '  %-13s %s\n' "$label" "$value"
}

menu_end() {
    printf '%s\n' "$MENU_RULE"
}

menu_read_selection() {
    local output_name="$1"
    prompt_read "$output_name" 'Selection > ' || return 1
    local -n __ffc_menu_selection_ref="$output_name"
    __ffc_menu_selection_ref="${__ffc_menu_selection_ref#"${__ffc_menu_selection_ref%%[![:space:]]*}"}"
    __ffc_menu_selection_ref="${__ffc_menu_selection_ref%"${__ffc_menu_selection_ref##*[![:space:]]}"}"
    if [[ "$__ffc_menu_selection_ref" == \[*\] && ${#__ffc_menu_selection_ref} -ge 3 ]]; then
        __ffc_menu_selection_ref="${__ffc_menu_selection_ref:1:${#__ffc_menu_selection_ref}-2}"
    fi
    if [[ "$__ffc_menu_selection_ref" == .[0-9]* || "$__ffc_menu_selection_ref" == .[hHqQ?] ]]; then
        __ffc_menu_selection_ref="${__ffc_menu_selection_ref:1}"
    fi
    if [[ "$__ffc_menu_selection_ref" == *')' || "$__ffc_menu_selection_ref" == *'.' ]]; then
        __ffc_menu_selection_ref="${__ffc_menu_selection_ref::-1}"
    fi
}

menu_run_action() {
    local label="$1" status
    shift
    printf '\n'
    if ("$@"); then
        ok "$label completed."
    else
        status=$?
        if ((status == FFC_ACTION_CANCELED)); then
            info "$label canceled."
        else
            warn "$label did not complete successfully (exit $status)."
        fi
    fi
    prompt_pause
    return 0
}

menu_unavailable_action() {
    local label="$1" reason="$2"
    printf '\n'
    info "$label is unavailable: $reason"
    prompt_pause
    return 0
}
