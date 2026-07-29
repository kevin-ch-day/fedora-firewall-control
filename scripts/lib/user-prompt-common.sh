#!/usr/bin/env bash
# Shared, shell-safe interactive prompt helpers for project scripts.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    printf '[ERROR] user-prompt-common.sh is a library; run a project script instead.\n' >&2
    exit 2
fi

if [[ "${FFC_USER_PROMPT_COMMON_LOADED:-0}" == 1 ]]; then
    return 0
fi
declare -F require_shell_function >/dev/null 2>&1 || {
    printf '[ERROR] user-prompt-common.sh requires setup-common.sh to be sourced first.\n' >&2
    return 1
}
require_shell_function fail || return 1
readonly FFC_USER_PROMPT_COMMON_LOADED=1

prompt_read() {
    local output_name="$1" prompt_text="$2"
    [[ "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || {
        fail "Invalid prompt output variable name: $output_name"
        return 2
    }
    [[ "$output_name" != __ffc_* ]] || {
        fail "Reserved prompt output variable name: $output_name"
        return 2
    }
    local -n __ffc_prompt_output_ref="$output_name"
    printf '%s' "$prompt_text"
    IFS= read -r __ffc_prompt_output_ref || return 1
}

prompt_pause() {
    # prompt_read assigns this output variable by name.
    # shellcheck disable=SC2034
    local ignored
    if [[ ! -t 0 ]]; then
        return 0
    fi
    prompt_read ignored $'\nPress Enter to return to the menu...' || true
    return 0
}

prompt_confirm_phrase() {
    local expected="$1" prompt_text="$2" response
    if [[ ! -t 0 || ! -t 1 ]]; then
        fail "This confirmation requires an interactive terminal."
        return 2
    fi
    prompt_read response "$prompt_text" || return 1
    [[ "$response" == "$expected" ]]
}

prompt_yes_no() {
    local prompt_text="$1" default_answer="${2:-no}" response suffix
    case "$default_answer" in
        yes) suffix='[Y/n]' ;;
        no) suffix='[y/N]' ;;
        *) fail "prompt_yes_no default must be 'yes' or 'no'."; return 2 ;;
    esac
    prompt_read response "$prompt_text $suffix " || return 1
    response="${response,,}"
    if [[ -z "$response" ]]; then
        [[ "$default_answer" == yes ]]
    else
        [[ "$response" == y || "$response" == yes ]]
    fi
}
