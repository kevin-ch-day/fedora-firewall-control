#!/usr/bin/env bash
# Prepare Fedora prerequisites and the starter workspace for the local FFC web dashboard.
# This script never starts a server or changes firewall, network, DNS, or SELinux state.
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
REPOSITORY_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly REQUIRED_PACKAGES=(nodejs24 nodejs24-bin nodejs24-npm nodejs24-npm-bin git jq curl)
readonly NATIVE_TOOL_PACKAGES=(gcc-c++ make python3 nodejs24-devel)
readonly WEB_TEMPLATE_DIR="$SCRIPT_DIR/templates/web"
readonly FFC_SNAPSHOT_TIMEOUT_SECONDS=20
readonly FFC_SNAPSHOT_FILE_BLOCK_LIMIT=2048
NODE_COMMAND_PATH=""
NPM_COMMAND_PATH=""

usage() {
    cat <<EOF
Usage: ./$SCRIPT_NAME
       ./$SCRIPT_NAME [--install | --check | --native-tools | --init-web | --deps | --audit | --verify | --all | --check-updates | --update-system | --help]

Prepare Fedora Node.js 24 LTS prerequisites and the repository-local starter
workspace for the future read-only FFC web dashboard. The script never starts
a web service.

Options:
  no option       Open the interactive setup menu.
  --install       Install missing required Fedora packages.
  --check         Report package, command, and Node 24 policy status; no changes.
  --native-tools  Install optional tools for npm modules requiring native builds.
  --init-web      Create web/ from the audited offline starter template. Refuses
                  to overwrite an existing path and does not contact a registry.
  --deps          Run locked local dependency installation with npm ci while
                  blocking all package lifecycle scripts.
  --audit         Explicitly contact the npm registry to run npm audit.
  --verify        Verify Fedora tools, workspace state, and FFC snapshot JSON; no changes.
  --all           As a normal user, install required/native packages, install
                  locked deps if present, then verify. Refuses entirely as root.
  --check-updates Contact Fedora repositories and report available system updates.
  --update-system Update installed Fedora packages after typed confirmation.
  --help          Show this help.

Required Fedora packages: ${REQUIRED_PACKAGES[*]}
Optional native-module tools: ${NATIVE_TOOL_PACKAGES[*]}

Network effects are explicit: Fedora repositories may be contacted by --install,
--native-tools, --all, --check-updates, and --update-system; the npm registry may
be contacted by --deps, --audit, and the dependency portion of --all. --check
and --verify do not install packages or contact npm. --init-web only copies the
repository-owned starter template. Dependencies remain local to the repository
and must have either clean committed manifests or the exact unmodified offline
starter manifests. Customized dependencies must be committed. This script never
uses sudo npm, global npm packages, firewall changes, network listeners, systemd,
or a web server.

Invoke the script with no option for the normal menu-driven workflow. Command
options remain available for automation. Run it as a normal user; it requests
sudo internally only for Fedora packages.
EOF
}

node_major() {
    local executable="${1:-node}" version
    version="$("$executable" --version)" || return 1
    [[ "$version" =~ ^v([0-9]+)(\.[0-9]+){1,2}$ ]] || return 1
    printf '%s\n' "${BASH_REMATCH[1]}"
}

report_command() {
    local command_name="$1" path version product release
    shift
    if ! path="$(command -v "$command_name" 2>/dev/null)"; then
        fail "$command_name command missing"
        return 1
    fi
    version="$("$path" "$@" 2>&1)" || {
        fail "$command_name at $path does not execute"
        return 1
    }
    version="${version%%$'\n'*}"
    if [[ "$command_name" == curl ]]; then
        read -r product release _ <<<"$version"
        version="$product $release"
    fi
    ok "$command_name: $path ($version)"
}

rpm_owner_for_path() {
    local path="$1" canonical owner
    owner="$(/usr/bin/rpm -qf -- "$path" 2>/dev/null || true)"
    if [[ -z "$owner" ]] && canonical="$(/usr/bin/realpath -e -- "$path" 2>/dev/null)"; then
        owner="$(/usr/bin/rpm -qf -- "$canonical" 2>/dev/null || true)"
    fi
    printf '%s\n' "$owner"
}

inspect_node_state() {
    local command_name path canonical owner version active_major packages package installed_major
    local package_count=0
    local -a installed_majors=()
    local -A seen_majors=()
    info "Current Node command selection:"
    for command_name in node npm; do
        if ! path="$(command -v "$command_name" 2>/dev/null)"; then
            warn "$command_name command is not currently available."
            continue
        fi
        canonical="$(/usr/bin/realpath -e -- "$path" 2>/dev/null || printf '%s' "$path")"
        version="$("$path" --version 2>&1 || true)"
        version="${version%%$'\n'*}"
        info "$command_name path: $path"
        info "$command_name resolved path: $canonical"
        info "$command_name version: ${version:-unavailable}"
        owner="$(rpm_owner_for_path "$path")"
        if [[ -n "$owner" ]]; then
            ok "$command_name RPM provider: $owner"
        else
            warn "$command_name is not RPM-owned; a version-manager shim or local install may shadow Fedora commands."
            case "$canonical" in
                /usr/bin/*|/usr/lib/*|/usr/lib64/*|/usr/libexec/*) ;;
                *) warn "$command_name resolves outside Fedora system command directories: $canonical" ;;
            esac
        fi
        case "$canonical" in
            */.nvm/*|*/.fnm/*|*/.volta/*|*/.asdf/*|*/.mise/*|*/.local/share/fnm/*)
                warn "$command_name appears to be supplied by a user-level Node version manager."
                ;;
        esac
    done
    if active_major="$(node_major 2>/dev/null)" && [[ "$active_major" != 24 ]]; then
        warn "The active Node.js major is $active_major; installing Fedora Node 24 command packages may change the active alternative."
    fi
    packages="$(/usr/bin/rpm -qa --qf '%{NAME}\n' 'nodejs*' 2>/dev/null | /usr/bin/sort -u || true)"
    if [[ -n "$packages" ]]; then
        while IFS= read -r package; do
            [[ -n "$package" ]] || continue
            package_count=$((package_count + 1))
            if [[ "$package" =~ ^nodejs([0-9]+)($|-) ]]; then
                installed_major="${BASH_REMATCH[1]}"
                if [[ -z "${seen_majors[$installed_major]:-}" ]]; then
                    seen_majors[$installed_major]=1
                    installed_majors+=("$installed_major")
                fi
            fi
        done <<<"$packages"
        info "Installed Fedora Node inventory: $package_count package(s); versioned majors: ${installed_majors[*]:-none}"
    fi
    [[ -x /usr/bin/node ]] || warn "/usr/bin/node is absent; Fedora runtime symlink was not found."
    [[ -x /usr/bin/npm ]] || warn "/usr/bin/npm is absent; Fedora npm symlink was not found."
}

check_environment() {
    local failed=0 major
    info "Fedora release: $FEDORA_RELEASE"
    info "Package manager: $PACKAGE_MANAGER"
    report_package_group "${REQUIRED_PACKAGES[@]}" || failed=1
    report_command node --version || failed=1
    report_command npm --version || failed=1
    report_command jq --version || failed=1
    report_command git --version || failed=1
    report_command curl --version || failed=1
    if major="$(node_major 2>/dev/null)" && [[ "$major" == 24 ]]; then
        ok "Node.js major version is 24"
    else
        fail "Node.js 24 LTS is required; detected: ${major:-unavailable}"
        failed=1
    fi
    inspect_node_state
    if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
        if resolve_fedora_node_commands; then
            ok "Active Node.js and npm commands satisfy the Fedora RPM policy"
        else
            failed=1
        fi
    fi
    return "$failed"
}

web_workspace_candidate() {
    if [[ -n "${FFC_WEB_DIR:-}" ]]; then
        [[ "$FFC_WEB_DIR" == /* ]] || die "FFC_WEB_DIR must be an absolute path."
        printf '%s\n' "$FFC_WEB_DIR"
    else
        printf '%s\n' "$REPOSITORY_ROOT/web"
    fi
}

validate_web_template() {
    local path owner mode
    [[ -d "$WEB_TEMPLATE_DIR" && ! -L "$WEB_TEMPLATE_DIR" ]] ||
        die "Web starter template is missing or unsafe: $WEB_TEMPLATE_DIR"
    [[ -f "$WEB_TEMPLATE_DIR/package.json" && ! -L "$WEB_TEMPLATE_DIR/package.json" ]] ||
        die "Web starter package.json is missing or unsafe."
    [[ -f "$WEB_TEMPLATE_DIR/package-lock.json" && ! -L "$WEB_TEMPLATE_DIR/package-lock.json" ]] ||
        die "Web starter package-lock.json is missing or unsafe."
    if /usr/bin/find "$WEB_TEMPLATE_DIR" -type l -print -quit | /usr/bin/grep -q .; then
        die "Web starter template must not contain symbolic links."
    fi
    while IFS= read -r -d '' path; do
        owner="$(/usr/bin/stat -c '%u' -- "$path")" || die "Cannot inspect web template ownership: $path"
        mode="$(/usr/bin/stat -c '%a' -- "$path")" || die "Cannot inspect web template permissions: $path"
        [[ "$owner" == 0 || "$owner" == "$EUID" ]] || die "Untrusted web template owner: $path"
        (((8#$mode & 022) == 0)) || die "Group/world-writable web template content is not trusted: $path"
    done < <(/usr/bin/find "$WEB_TEMPLATE_DIR" -print0)
    /usr/bin/jq -e 'type == "object" and .private == true' "$WEB_TEMPLATE_DIR/package.json" >/dev/null ||
        die "Web starter package.json is invalid or is not marked private."
    /usr/bin/jq -e 'type == "object" and .lockfileVersion == 3' "$WEB_TEMPLATE_DIR/package-lock.json" >/dev/null ||
        die "Web starter package-lock.json is invalid or does not use lockfile version 3."
}

initialize_web_workspace() {
    require_normal_user_for_npm "--init-web"
    local candidate staging
    candidate="$(web_workspace_candidate)" || return 1
    [[ "$candidate" == "$REPOSITORY_ROOT/web" ]] ||
        die "Workspace initialization is restricted to the repository path: $REPOSITORY_ROOT/web"
    [[ ! -e "$candidate" && ! -L "$candidate" ]] ||
        die "Refusing to overwrite the existing web workspace path: $candidate"
    validate_web_template
    staging="$(/usr/bin/mktemp -d "$REPOSITORY_ROOT/.web-init.XXXXXX")" ||
        die "Cannot create a temporary web workspace staging directory."
    if ! /usr/bin/cp -a -- "$WEB_TEMPLATE_DIR/." "$staging/"; then
        /usr/bin/rm -rf -- "$staging"
        die "Could not copy the web starter template."
    fi
    if ! /usr/bin/mv -- "$staging" "$candidate"; then
        /usr/bin/rm -rf -- "$staging"
        die "Could not publish the initialized web workspace."
    fi
    ok "Created the offline starter workspace at $candidate"
    info "The exact starter is approved for immediate npm checks; review and commit it before customization or deployment."
    info "On another machine, Git supplies the committed web application; run this initializer only when web/ is genuinely absent."
}

path_is_within_repository() {
    local path="$1"
    [[ "$path" == "$REPOSITORY_ROOT" || "$path" == "$REPOSITORY_ROOT/"* ]]
}

resolve_existing_workspace() {
    local candidate canonical
    candidate="$(web_workspace_candidate)" || return 1
    [[ -d "$candidate" ]] || die "Web workspace directory does not exist: $candidate"
    canonical="$(/usr/bin/realpath -e -- "$candidate")" || die "Cannot resolve web workspace: $candidate"
    if ! path_is_within_repository "$canonical"; then
        warn "FFC_WEB_DIR resolves outside the repository: $canonical"
    fi
    printf '%s\n' "$canonical"
}

require_safe_manifest_files() {
    local workspace="$1" file owner mode
    for file in package.json package-lock.json; do
        [[ ! -L "$workspace/$file" ]] || die "Unsafe manifest symlink is not allowed: $workspace/$file"
        [[ -f "$workspace/$file" ]] || die "Required regular file is missing: $workspace/$file"
        owner="$(/usr/bin/stat -c '%u' -- "$workspace/$file")" || die "Cannot inspect manifest ownership: $workspace/$file"
        mode="$(/usr/bin/stat -c '%a' -- "$workspace/$file")" || die "Cannot inspect manifest permissions: $workspace/$file"
        [[ "$owner" == 0 || "$owner" == "$EUID" ]] || die "Untrusted manifest owner: $workspace/$file"
        (((8#$mode & 022) == 0)) || die "Group/world-writable manifest is not trusted: $workspace/$file"
    done
}

require_safe_npm_policy_file() {
    local workspace="$1" owner mode required_setting setting_name setting_count
    local policy="$workspace/.npmrc"
    [[ -f "$policy" && ! -L "$policy" ]] || die "Required regular npm policy file is missing or unsafe: $policy"
    owner="$(/usr/bin/stat -c '%u' -- "$policy")" || die "Cannot inspect npm policy ownership: $policy"
    mode="$(/usr/bin/stat -c '%a' -- "$policy")" || die "Cannot inspect npm policy permissions: $policy"
    [[ "$owner" == 0 || "$owner" == "$EUID" ]] || die "Untrusted npm policy owner: $policy"
    (((8#$mode & 022) == 0)) || die "Group/world-writable npm policy is not trusted: $policy"
    for required_setting in audit=false engine-strict=true fund=false ignore-scripts=true save-exact=true; do
        setting_name="${required_setting%%=*}"
        setting_count="$(/usr/bin/grep -Eic "^[[:space:]]*${setting_name}[[:space:]]*=" "$policy" || true)"
        [[ "$setting_count" == 1 && "$(/usr/bin/grep -Fxc -- "$required_setting" "$policy")" == 1 ]] ||
            die "Required npm policy setting is missing, duplicated, or overridden: $required_setting"
    done
}

validate_workspace_manifest_contract() {
    local workspace="$1"
    /usr/bin/jq -e '
        type == "object" and
        (.name | type == "string" and length > 0) and
        (.version | type == "string" and length > 0) and
        .private == true and
        (.engines.node | type == "string" and length > 0) and
        (.engines.npm | type == "string" and length > 0) and
        ((.scripts // {}) | type == "object" and all(.[]; type == "string"))
    ' "$workspace/package.json" >/dev/null ||
        die "package.json violates the private Node workspace contract."
    /usr/bin/jq -e --slurpfile package "$workspace/package.json" '
        ($package[0]) as $p |
        type == "object" and
        .lockfileVersion == 3 and
        .requires == true and
        (.packages | type == "object") and
        (.packages[""] | type == "object") and
        .name == $p.name and
        .version == $p.version and
        .packages[""].name == $p.name and
        .packages[""].version == $p.version and
        ((.packages[""].dependencies // {}) == ($p.dependencies // {})) and
        ((.packages[""].devDependencies // {}) == ($p.devDependencies // {})) and
        ((.packages[""].optionalDependencies // {}) == ($p.optionalDependencies // {})) and
        ((.packages[""].peerDependencies // {}) == ($p.peerDependencies // {}))
    ' "$workspace/package-lock.json" >/dev/null ||
        die "package-lock.json is invalid or inconsistent with package.json."
}

require_writable_user_workspace() {
    local workspace="$1" path owner mode
    [[ -w "$workspace" ]] || die "Web workspace is not writable by the current user: $workspace"
    for path in "$workspace" "$workspace/package.json" "$workspace/package-lock.json"; do
        owner="$(/usr/bin/stat -c '%u' -- "$path")" || die "Cannot inspect workspace ownership: $path"
        mode="$(/usr/bin/stat -c '%a' -- "$path")" || die "Cannot inspect workspace permissions: $path"
        if [[ $EUID -ne 0 && "$owner" == 0 ]]; then
            die "Root-owned workspace content could create mixed npm ownership: $path"
        fi
        (((8#$mode & 022) == 0)) || die "Group/world-writable workspace content is not trusted: $path"
    done
    if [[ -e "$workspace/node_modules" ]]; then
        [[ -d "$workspace/node_modules" && ! -L "$workspace/node_modules" ]] ||
            die "node_modules must be a real directory rather than a symlink: $workspace/node_modules"
        owner="$(/usr/bin/stat -c '%u' -- "$workspace/node_modules")" ||
            die "Cannot inspect node_modules ownership: $workspace/node_modules"
        mode="$(/usr/bin/stat -c '%a' -- "$workspace/node_modules")" ||
            die "Cannot inspect node_modules permissions: $workspace/node_modules"
        [[ "$owner" != 0 || $EUID -eq 0 ]] ||
            die "Root-owned node_modules would create mixed npm ownership: $workspace/node_modules"
        (((8#$mode & 022) == 0)) ||
            die "Group/world-writable node_modules is not trusted: $workspace/node_modules"
    fi
}

manifest_files_are_committed_and_clean() {
    local workspace="$1" git_root relative file
    git_root="$(/usr/bin/git -C "$workspace" rev-parse --show-toplevel 2>/dev/null)" || return 1
    relative="$(/usr/bin/realpath --relative-to="$git_root" -- "$workspace")" ||
        return 1
    for file in package.json package-lock.json; do
        /usr/bin/git -C "$git_root" cat-file -e "HEAD:$relative/$file" 2>/dev/null || return 1
    done
    /usr/bin/git -C "$git_root" diff --quiet -- "$relative/package.json" "$relative/package-lock.json" || return 1
    /usr/bin/git -C "$git_root" diff --cached --quiet -- "$relative/package.json" "$relative/package-lock.json"
}

workspace_matches_offline_starter() {
    local workspace="$1" file
    [[ "$workspace" == "$REPOSITORY_ROOT/web" ]] || return 1
    for file in package.json package-lock.json .npmrc; do
        [[ -f "$workspace/$file" && ! -L "$workspace/$file" ]] || return 1
        [[ -f "$WEB_TEMPLATE_DIR/$file" && ! -L "$WEB_TEMPLATE_DIR/$file" ]] || return 1
        /usr/bin/cmp -s -- "$workspace/$file" "$WEB_TEMPLATE_DIR/$file" || return 1
    done
}

web_manifests_authorized_for_npm() {
    local workspace="${1:-${FFC_WEB_DIR:-$REPOSITORY_ROOT/web}}"
    manifest_files_are_committed_and_clean "$workspace" || workspace_matches_offline_starter "$workspace"
}

require_authorized_manifest_files() {
    local workspace="$1"
    if manifest_files_are_committed_and_clean "$workspace"; then
        return
    fi
    if workspace_matches_offline_starter "$workspace"; then
        info "Using the exact unmodified offline starter manifests; commit them before adding dependencies." >&2
        return
    fi
    die "Customized web manifests must be clean and committed before npm dependency operations."
}

require_workspace_for_npm() {
    local workspace
    workspace="$(resolve_existing_workspace)" || return 1
    require_safe_manifest_files "$workspace"
    require_safe_npm_policy_file "$workspace"
    require_writable_user_workspace "$workspace"
    validate_workspace_manifest_contract "$workspace"
    require_authorized_manifest_files "$workspace"
    printf '%s\n' "$workspace"
}

require_normal_user_for_npm() {
    [[ $EUID -ne 0 ]] || die "$1 refuses to run npm as root to avoid root-owned project files."
}

resolve_fedora_node_commands() {
    local node_owner npm_owner
    NODE_COMMAND_PATH="$(command -v node 2>/dev/null)" || {
        fail "Node.js is required before npm dependency operations."
        return 1
    }
    NPM_COMMAND_PATH="$(command -v npm 2>/dev/null)" || {
        fail "npm is required before npm dependency operations."
        return 1
    }
    [[ "$NODE_COMMAND_PATH" == /* && -f "$NODE_COMMAND_PATH" && -x "$NODE_COMMAND_PATH" ]] || {
        fail "The active node command is not a trusted absolute executable: $NODE_COMMAND_PATH"
        return 1
    }
    [[ "$NPM_COMMAND_PATH" == /* && -f "$NPM_COMMAND_PATH" && -x "$NPM_COMMAND_PATH" ]] || {
        fail "The active npm command is not a trusted absolute executable: $NPM_COMMAND_PATH"
        return 1
    }
    node_owner="$(rpm_owner_for_path "$NODE_COMMAND_PATH")"
    npm_owner="$(rpm_owner_for_path "$NPM_COMMAND_PATH")"
    [[ "$node_owner" == nodejs24-bin-* ]] || {
        fail "The active node command is not provided by Fedora nodejs24-bin: ${node_owner:-unowned}"
        return 1
    }
    [[ "$npm_owner" == nodejs24-npm-bin-* ]] || {
        fail "The active npm command is not provided by Fedora nodejs24-npm-bin: ${npm_owner:-unowned}"
        return 1
    }
}

require_node24_for_npm() {
    local major
    resolve_fedora_node_commands || return 1
    major="$(node_major "$NODE_COMMAND_PATH" 2>/dev/null)" || die "Cannot determine the active Node.js version."
    [[ "$major" == 24 ]] || die "Node.js 24 is required for npm dependency operations; active major is $major."
}

manifest_hashes() {
    local workspace="$1"
    /usr/bin/sha256sum -- "$workspace/package.json" "$workspace/package-lock.json"
}

manifest_git_state() {
    local workspace="$1" git_root relative
    if git_root="$(/usr/bin/git -C "$workspace" rev-parse --show-toplevel 2>/dev/null)"; then
        relative="$(/usr/bin/realpath --relative-to="$git_root" -- "$workspace")" || return 1
        /usr/bin/git -C "$git_root" status --porcelain=v1 -- "$relative/package.json" "$relative/package-lock.json"
    else
        printf '%s\n' '<not-in-a-git-work-tree>'
    fi
}

report_npm_script_policy() {
    if "$NPM_COMMAND_PATH" config ls -l 2>/dev/null | /usr/bin/grep -Eq '^allow-scripts[[:space:]]*='; then
        info "This npm version exposes project-level allow-scripts configuration."
    else
        info "No project-level allow-scripts capability was detected; --ignore-scripts remains enforced."
    fi
}

install_dependencies() {
    require_normal_user_for_npm "--deps"
    local workspace hashes_before hashes_after git_before git_after result
    workspace="$(require_workspace_for_npm)" || return 1
    require_node24_for_npm
    hashes_before="$(manifest_hashes "$workspace")" || return 1
    git_before="$(manifest_git_state "$workspace")" || return 1
    report_npm_script_policy
    info "Installing locked local dependencies with npm ci; lifecycle scripts, audit, and funding requests are disabled."
    set +e
    (cd -- "$workspace" && "$NPM_COMMAND_PATH" ci --ignore-scripts --fund=false --audit=false)
    result=$?
    set -e
    hashes_after="$(manifest_hashes "$workspace")" || return 1
    git_after="$(manifest_git_state "$workspace")" || return 1
    [[ "$hashes_before" == "$hashes_after" ]] ||
        die "npm ci changed package.json or package-lock.json; refusing modified manifests."
    [[ "$git_before" == "$git_after" ]] ||
        die "npm ci changed the Git state of package.json or package-lock.json."
    if ((result != 0)); then
        fail "npm ci failed with exit $result; both manifest files remained unchanged."
        return "$result"
    fi
    ok "Locked dependencies installed with lifecycle scripts blocked and both manifests unchanged"
}

audit_dependencies() {
    require_normal_user_for_npm "--audit"
    local workspace result audit_dir stdout_file stderr_file
    workspace="$(require_workspace_for_npm)" || return 1
    require_node24_for_npm
    [[ -x /usr/bin/jq ]] || die "jq is required to classify npm audit results."
    audit_dir="$(/usr/bin/mktemp -d)" || die "Cannot create temporary audit output directory."
    stdout_file="$audit_dir/stdout.json"
    stderr_file="$audit_dir/stderr.log"
    warn "npm audit contacts the configured npm registry and may report dependency vulnerabilities."
    set +e
    (cd -- "$workspace" && "$NPM_COMMAND_PATH" audit --audit-level=low --json >"$stdout_file" 2>"$stderr_file")
    result=$?
    set -e
    [[ ! -s "$stdout_file" ]] || /usr/bin/cat -- "$stdout_file"
    [[ ! -s "$stderr_file" ]] || /usr/bin/cat -- "$stderr_file" >&2
    if ((result == 0)); then
        ok "npm audit reported no vulnerabilities at the selected threshold."
    elif /usr/bin/jq -e '
        [(.metadata.vulnerabilities // {})[] | numbers] | add // 0 | . > 0
    ' "$stdout_file" >/dev/null 2>&1; then
        warn "npm audit completed and reported vulnerabilities at the selected threshold (exit $result)."
    elif /usr/bin/jq -e 'has("error")' "$stdout_file" >/dev/null 2>&1; then
        warn "npm audit could not complete; npm returned a registry, network, or configuration error (exit $result)."
    else
        warn "npm audit exited $result without a classifiable JSON result; review its diagnostics."
    fi
    if ! /usr/bin/rm -f -- "$stdout_file" "$stderr_file"; then
        warn "Could not remove temporary npm audit output files: $audit_dir"
    fi
    if ! /usr/bin/rmdir -- "$audit_dir"; then
        warn "Could not remove temporary npm audit directory: $audit_dir"
    fi
    return "$result"
}

verify_workspace() {
    local candidate workspace dependency_count engines
    candidate="$(web_workspace_candidate)" || return 1
    if [[ ! -e "$candidate" ]]; then
        warn "Web workspace is not present yet; dependency installation is intentionally skipped."
        return
    fi
    workspace="$(resolve_existing_workspace)" || return 1
    require_safe_manifest_files "$workspace"
    require_safe_npm_policy_file "$workspace"
    validate_workspace_manifest_contract "$workspace"
    ok "npm manifests and project security policy are structurally consistent"
    dependency_count="$(/usr/bin/jq -r '(.packages // {}) | keys | map(select(. != "")) | length' "$workspace/package-lock.json")" ||
        die "Cannot determine the locked dependency count."
    if [[ "$dependency_count" == 0 ]]; then
        ok "Lockfile contains no third-party dependencies; node_modules is not required"
    elif [[ -d "$workspace/node_modules" && ! -L "$workspace/node_modules" ]]; then
        ok "Local node_modules is present for $dependency_count locked package(s)"
    else
        warn "Local node_modules is absent; install $dependency_count locked package(s) with npm ci."
    fi
    engines="$(/usr/bin/jq -r 'if .engines.node == null then "" elif (.engines.node | type) == "string" then .engines.node else error("engines.node must be a string") end' "$workspace/package.json")" ||
        die "package.json has an invalid engines.node value."
    if [[ -n "$engines" ]]; then
        info "Declared Node engine range: $engines"
        info "npm will evaluate this semver range during dependency installation; the setup script does not implement a second semver parser."
    fi
}

path_has_world_writable_component() {
    local path="$1" component mode
    component="$(/usr/bin/dirname -- "$path")"
    while :; do
        mode="$(/usr/bin/stat -c '%a' -- "$component")" || return 0
        if (((8#$mode & 2) != 0)); then
            warn "World-writable executable parent directory is not trusted: $component"
            return 0
        fi
        [[ "$component" == / ]] && break
        component="$(/usr/bin/dirname -- "$component")"
    done
    return 1
}

resolve_ffc_binary() {
    local candidate canonical mode owner
    candidate="${FFC_BIN:-$REPOSITORY_ROOT/build/ffc}"
    if [[ -n "${FFC_BIN:-}" && "$candidate" != /* ]]; then
        die "FFC_BIN must be an absolute path with no command-line fragments."
    fi
    [[ -e "$candidate" ]] || return 1
    [[ -f "$candidate" && -x "$candidate" ]] || die "FFC_BIN must name a regular executable file: $candidate"
    canonical="$(/usr/bin/realpath -e -- "$candidate")" || die "Cannot resolve FFC_BIN: $candidate"
    [[ -f "$canonical" && -x "$canonical" ]] || die "Resolved FFC_BIN is not a regular executable: $canonical"
    mode="$(/usr/bin/stat -c '%a' -- "$canonical")" || die "Cannot inspect FFC_BIN permissions: $canonical"
    (((8#$mode & 2) == 0)) || die "World-writable FFC_BIN is not trusted: $canonical"
    ! path_has_world_writable_component "$canonical" || die "FFC_BIN has an unsafe parent directory."
    owner="$(/usr/bin/stat -c '%u' -- "$canonical")" || die "Cannot inspect FFC_BIN ownership: $canonical"
    [[ "$owner" == 0 || "$owner" == "$EUID" ]] ||
        die "FFC_BIN is owned by untrusted UID $owner rather than root or the current user."
    printf '%s\n' "$canonical"
}

run_bounded_ffc_snapshot() {
    local ffc_bin="$1" stdout_file="$2" stderr_file="$3"
    local timeout_seconds="${4:-$FFC_SNAPSHOT_TIMEOUT_SECONDS}"
    local file_block_limit="${5:-$FFC_SNAPSHOT_FILE_BLOCK_LIMIT}"
    [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || return 2
    [[ "$file_block_limit" =~ ^[1-9][0-9]*$ ]] || return 2
    (
        ulimit -f "$file_block_limit"
        /usr/bin/timeout --signal=TERM --kill-after=2s "${timeout_seconds}s" \
            "$ffc_bin" --snapshot-json
    ) >"$stdout_file" 2>"$stderr_file"
}

verify_ffc_snapshot() {
    local candidate ffc_bin output_dir stdout_file stderr_file status diagnostic diagnostic_size snapshot_size
    candidate="${FFC_BIN:-$REPOSITORY_ROOT/build/ffc}"
    if [[ ! -e "$candidate" ]]; then
        if [[ -n "${FFC_BIN:-}" ]]; then
            die "FFC_BIN does not exist: $candidate"
        else
            warn "FFC binary is absent at $candidate; build it with ./scripts/build.sh to verify snapshot JSON."
            return
        fi
    fi
    ffc_bin="$(resolve_ffc_binary)" || return 1
    output_dir="$(/usr/bin/mktemp -d)" || die "Cannot create temporary FFC verification directory."
    stdout_file="$output_dir/stdout.json"
    stderr_file="$output_dir/stderr.log"
    set +e
    run_bounded_ffc_snapshot "$ffc_bin" "$stdout_file" "$stderr_file"
    status=$?
    set -e
    diagnostic_size="$(/usr/bin/stat -c '%s' -- "$stderr_file" 2>/dev/null || printf 0)"
    diagnostic="$(/usr/bin/head -c 4096 -- "$stderr_file" | LC_ALL=C /usr/bin/tr -cd '\11\12\15\40-\176')"
    ((diagnostic_size <= 4096)) || diagnostic+=$'\n[diagnostic truncated]'
    if ((status != 0)); then
        [[ -z "$diagnostic" ]] || warn "FFC stderr: $diagnostic"
        if ((status == 124 || status == 137)); then
            /usr/bin/rm -f -- "$stdout_file" "$stderr_file"
            /usr/bin/rmdir -- "$output_dir" 2>/dev/null || true
            die "FFC snapshot collection exceeded the ${FFC_SNAPSHOT_TIMEOUT_SECONDS}-second limit."
        elif ((status == 153)); then
            /usr/bin/rm -f -- "$stdout_file" "$stderr_file"
            /usr/bin/rmdir -- "$output_dir" 2>/dev/null || true
            die "FFC snapshot output exceeded the configured file-size limit."
        fi
        /usr/bin/rm -f -- "$stdout_file" "$stderr_file"
        /usr/bin/rmdir -- "$output_dir" 2>/dev/null || true
        die "FFC could not produce snapshot JSON (exit $status)."
    fi
    snapshot_size="$(/usr/bin/stat -c '%s' -- "$stdout_file")" || snapshot_size=0
    if ! /usr/bin/jq -e '
        type == "object" and
        .schema == "ffc.dashboard.v1" and
        .schema_version == 1 and
        (.snapshot_id | type == "number") and
        (.collected_at | type == "string") and
        (.status == "available" or .status == "partial" or .status == "unavailable") and
        (.risk | type == "object") and
        (.firewall | type == "object") and
        (.network | type == "object") and
        (.evidence | type == "object")
    ' "$stdout_file" >/dev/null; then
        /usr/bin/rm -f -- "$stdout_file" "$stderr_file"
        /usr/bin/rmdir -- "$output_dir" 2>/dev/null || true
        die "FFC snapshot JSON violates the ffc.dashboard.v1 boundary contract."
    fi
    if ! /usr/bin/rm -f -- "$stdout_file" "$stderr_file"; then
        warn "Could not remove temporary FFC verification files: $output_dir"
    fi
    if ! /usr/bin/rmdir -- "$output_dir"; then
        warn "Could not remove temporary FFC verification directory: $output_dir"
    fi
    [[ -z "$diagnostic" ]] || warn "FFC produced stderr while snapshot JSON remained valid: $diagnostic"
    ok "FFC snapshot JSON validates as ffc.dashboard.v1 ($snapshot_size bytes; bounded collection)"
}

verify() {
    local failed=0
    check_environment || failed=1
    verify_workspace || failed=1
    verify_ffc_snapshot || failed=1
    return "$failed"
}

install_required_packages() {
    inspect_node_state
    install_missing_packages "${REQUIRED_PACKAGES[@]}"
    check_environment
}

run_all() {
    local candidate workspace=""
    candidate="$(web_workspace_candidate)" || return 1
    if [[ -e "$candidate" ]]; then
        workspace="$(require_workspace_for_npm)" || return 1
        info "Validated dependency workspace before system package changes: $workspace"
    elif [[ -n "${FFC_WEB_DIR:-}" ]]; then
        die "FFC_WEB_DIR does not exist; --all refuses before making system changes: $candidate"
    else
        warn "Web workspace is not initialized; --all will perform RPM setup only and skip npm ci."
    fi
    info "--all includes optional native-module build tools."
    inspect_node_state
    install_missing_packages "${REQUIRED_PACKAGES[@]}"
    install_missing_packages "${NATIVE_TOOL_PACKAGES[@]}"
    if [[ -n "$workspace" ]]; then
        install_dependencies
    fi
    verify
}

web_workspace_ready_for_menu() {
    local candidate="${FFC_WEB_DIR:-$REPOSITORY_ROOT/web}"
    [[ "$candidate" == /* && -d "$candidate" ]] || return 1
    [[ -f "$candidate/package.json" && ! -L "$candidate/package.json" ]] || return 1
    [[ -f "$candidate/package-lock.json" && ! -L "$candidate/package-lock.json" ]]
}

web_workspace_path_exists() {
    local candidate="${FFC_WEB_DIR:-$REPOSITORY_ROOT/web}"
    [[ -e "$candidate" || -L "$candidate" ]]
}

web_manifests_committed_for_menu() {
    local candidate="${FFC_WEB_DIR:-$REPOSITORY_ROOT/web}"
    web_workspace_ready_for_menu || return 1
    manifest_files_are_committed_and_clean "$candidate"
}

runtime_status_summary() {
    local node_path npm_path node_version npm_version node_owner npm_owner
    node_path="$(command -v node 2>/dev/null || true)"
    npm_path="$(command -v npm 2>/dev/null || true)"
    if [[ -z "$node_path" || -z "$npm_path" ]]; then
        printf '[ACTION] Node.js 24 or npm is unavailable'
        return
    fi
    node_version="$("$node_path" --version 2>/dev/null || true)"
    npm_version="$("$npm_path" --version 2>/dev/null || true)"
    node_owner="$(rpm_owner_for_path "$node_path")"
    npm_owner="$(rpm_owner_for_path "$npm_path")"
    if [[ "$node_version" == v24.* && "$node_owner" == nodejs24-bin-* && "$npm_owner" == nodejs24-npm-bin-* ]]; then
        printf '[READY] Node %s · npm %s · Fedora RPM managed' "$node_version" "${npm_version:-unknown}"
    else
        printf '[REVIEW] Node %s · npm %s · command-provider policy mismatch' "${node_version:-unknown}" "${npm_version:-unknown}"
    fi
}

workspace_status_summary() {
    local candidate="${FFC_WEB_DIR:-$REPOSITORY_ROOT/web}" dependency_count
    if [[ "$candidate" != /* ]]; then
        printf '[REVIEW] FFC_WEB_DIR override must be an absolute path'
    elif ! web_workspace_path_exists; then
        printf '[ACTION] absent · offline initializer ready'
    elif ! web_workspace_ready_for_menu; then
        printf '[REVIEW] existing path is incomplete or unsafe'
    elif workspace_matches_offline_starter "$candidate"; then
        dependency_count="$(/usr/bin/jq -r '(.packages // {}) | keys | map(select(. != "")) | length' "$candidate/package-lock.json" 2>/dev/null || printf '?')"
        if [[ "$dependency_count" == 0 ]]; then
            printf '[READY] trusted starter · no third-party dependencies'
        elif [[ -d "$candidate/node_modules" && ! -L "$candidate/node_modules" ]]; then
            printf '[READY] trusted starter · dependencies installed · %s locked package(s)' "$dependency_count"
        else
            printf '[ACTION] trusted starter · npm ci available · %s locked package(s)' "$dependency_count"
        fi
    elif ! web_manifests_committed_for_menu; then
        printf '[ACTION] initialized · review and commit npm manifests'
    elif [[ -d "$candidate/node_modules" && ! -L "$candidate/node_modules" ]]; then
        dependency_count="$(/usr/bin/jq -r '(.packages // {}) | keys | map(select(. != "")) | length' "$candidate/package-lock.json" 2>/dev/null || printf '?')"
        printf '[READY] committed · dependencies installed · %s locked package(s)' "$dependency_count"
    else
        dependency_count="$(/usr/bin/jq -r '(.packages // {}) | keys | map(select(. != "")) | length' "$candidate/package-lock.json" 2>/dev/null || printf '?')"
        if [[ "$dependency_count" == 0 ]]; then
            printf '[READY] committed · no third-party dependencies'
        else
            printf '[ACTION] committed · npm ci pending · %s locked package(s)' "$dependency_count"
        fi
    fi
}

package_status_summary() {
    local package required_missing=0 native_missing=0
    for package in "${REQUIRED_PACKAGES[@]}"; do
        package_installed "$package" || required_missing=$((required_missing + 1))
    done
    for package in "${NATIVE_TOOL_PACKAGES[@]}"; do
        package_installed "$package" || native_missing=$((native_missing + 1))
    done
    if ((required_missing == 0 && native_missing == 0)); then
        printf '[READY] required and native Fedora packages installed'
    elif ((required_missing > 0)); then
        printf '[ACTION] %d required · %d optional native package(s) missing' "$required_missing" "$native_missing"
    else
        printf '[INFO] required ready · %d optional native package(s) missing' "$native_missing"
    fi
}

native_status_summary() {
    local binary="${FFC_BIN:-$REPOSITORY_ROOT/build/ffc}" schema="$REPOSITORY_ROOT/schemas/dashboard-v1.schema.json"
    local canonical mode version='unknown'
    if [[ -n "${FFC_BIN:-}" && "$binary" != /* ]]; then
        printf '[REVIEW] FFC_BIN override must be an absolute path'
    elif [[ -f "$binary" && -x "$binary" && -f "$schema" ]]; then
        canonical="$(/usr/bin/realpath -e -- "$binary" 2>/dev/null || true)"
        mode="$(/usr/bin/stat -c '%a' -- "$canonical" 2>/dev/null || true)"
        if [[ -z "$canonical" || -z "$mode" || $((8#$mode & 2)) -ne 0 ]]; then
            printf '[REVIEW] executable path or permissions are unsafe'
            return
        fi
        if [[ -f "$REPOSITORY_ROOT/build/CMakeCache.txt" ]]; then
            version="$(/usr/bin/sed -n 's/^CMAKE_PROJECT_VERSION:STATIC=//p' "$REPOSITORY_ROOT/build/CMakeCache.txt" | /usr/bin/head -n 1)"
            [[ -n "$version" ]] || version='unknown'
        fi
        printf '[READY] v%s executable · dashboard-v1 schema present' "$version"
    elif [[ ! -f "$binary" || ! -x "$binary" ]]; then
        printf '[ACTION] FFC executable missing · run ./scripts/build.sh'
    else
        printf '[ACTION] dashboard-v1 schema missing'
    fi
}

repository_status_summary() {
    local branch state
    branch="$(/usr/bin/git -C "$REPOSITORY_ROOT" branch --show-current 2>/dev/null || true)"
    [[ -n "$branch" ]] || branch='detached/unavailable'
    if [[ -n "$(/usr/bin/git -C "$REPOSITORY_ROOT" status --porcelain=v1 --untracked-files=normal 2>/dev/null)" ]]; then
        state='changes present'
    else
        state='clean'
    fi
    printf '[INFO] %s · %s' "$branch" "$state"
}

show_current_status() {
    printf 'Current status (local checks only)\n'
    menu_status_item 'Host' "[READY] Fedora $FEDORA_RELEASE · ${PACKAGE_MANAGER##*/}"
    menu_status_item 'Runtime' "$(runtime_status_summary)"
    menu_status_item 'Packages' "$(package_status_summary)"
    menu_status_item 'Workspace' "$(workspace_status_summary)"
    menu_status_item 'Native FFC' "$(native_status_summary)"
    menu_status_item 'Repository' "$(repository_status_summary)"
    printf '%s\n\n' "$MENU_RULE"
}

show_menu() {
    local audit_note candidate dependency_count dependency_note complete_note init_note='available: offline' node_note='packages missing' native_note='packages missing'
    package_group_installed "${REQUIRED_PACKAGES[@]}" && node_note='installed'
    package_group_installed "${NATIVE_TOOL_PACKAGES[@]}" && native_note='installed'
    if web_workspace_ready_for_menu && web_manifests_authorized_for_npm; then
        candidate="${FFC_WEB_DIR:-$REPOSITORY_ROOT/web}"
        dependency_count="$(/usr/bin/jq -r '(.packages // {}) | keys | map(select(. != "")) | length' "$candidate/package-lock.json" 2>/dev/null || printf '?')"
        if [[ "$dependency_count" == 0 ]]; then
            dependency_note='ready: no third-party dependencies'
        else
            dependency_note='contacts npm registry'
        fi
        complete_note='RPM and locked npm setup'
        init_note='already initialized'
        audit_note='contacts npm registry'
    elif web_workspace_ready_for_menu; then
        dependency_note='unavailable: commit manifests first'
        audit_note='unavailable: commit manifests first'
        complete_note='unavailable: commit manifests first'
        init_note='already initialized'
    elif web_workspace_path_exists; then
        dependency_note='unavailable: incomplete workspace'
        audit_note='unavailable: incomplete workspace'
        complete_note='workspace needs review: RPM only'
        init_note='blocked: existing path needs review'
    else
        dependency_note='unavailable: initialize web/ first'
        audit_note='unavailable: initialize web/ first'
        complete_note='workspace absent: RPM only'
    fi
    menu_begin 'Fedora Firewall Control — web development setup'
    show_current_status
    menu_item '1)' 'Check prerequisites' 'read-only'
    menu_item '2)' 'Install Fedora Node.js 24 prerequisites' "$node_note"
    menu_item '3)' 'Install optional native build tools' "$native_note"
    menu_item '4)' 'Initialize web workspace' "$init_note"
    menu_item '5)' 'Verify environment, workspace, and FFC' 'read-only'
    menu_item '6)' 'Install locked web dependencies' "$dependency_note"
    menu_item '7)' 'Audit web dependencies' "$audit_note"
    menu_item '8)' 'Complete setup' "$complete_note"
    menu_item '9)' 'Check for Fedora system updates' 'contacts Fedora repositories'
    menu_item '10)' 'Update the Fedora system' 'confirmation; system-wide changes'
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
            1) menu_run_action "Prerequisite check" check_environment ;;
            2) menu_run_action "Node.js prerequisite installation" install_required_packages ;;
            3)
                menu_run_action "Native-tool installation" install_missing_packages "${NATIVE_TOOL_PACKAGES[@]}"
                ;;
            4)
                if web_workspace_ready_for_menu; then
                    menu_unavailable_action "Web workspace initialization" "web/ is already initialized; existing content will never be overwritten"
                elif web_workspace_path_exists; then
                    menu_unavailable_action "Web workspace initialization" "web/ already exists but is incomplete; review it manually because setup will not overwrite it"
                else
                    menu_run_action "Web workspace initialization" initialize_web_workspace
                fi
                ;;
            5) menu_run_action "Setup verification" verify ;;
            6)
                if web_workspace_ready_for_menu && web_manifests_authorized_for_npm; then
                    menu_run_action "Locked dependency installation" install_dependencies
                elif web_workspace_ready_for_menu; then
                    menu_unavailable_action "Locked dependency installation" "review and commit web/package.json and web/package-lock.json first"
                else
                    menu_unavailable_action "Locked dependency installation" "initialize and commit web/package.json and web/package-lock.json first"
                fi
                ;;
            7)
                if web_workspace_ready_for_menu && web_manifests_authorized_for_npm; then
                    menu_run_action "Dependency audit" audit_dependencies
                elif web_workspace_ready_for_menu; then
                    menu_unavailable_action "Dependency audit" "review and commit web/package.json and web/package-lock.json first"
                else
                    menu_unavailable_action "Dependency audit" "initialize and commit web/package.json and web/package-lock.json first"
                fi
                ;;
            8)
                if web_workspace_ready_for_menu && ! web_manifests_authorized_for_npm; then
                    menu_unavailable_action "Complete setup" "review and commit web/package.json and web/package-lock.json first"
                else
                    menu_run_action "Complete setup" run_all
                fi
                ;;
            9) menu_run_action "Fedora update check" check_fedora_updates ;;
            10) menu_run_action "Fedora system-update workflow" confirm_fedora_system_update ;;
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
        --install|--check|--native-tools|--init-web|--deps|--audit|--verify|--all|--check-updates|--update-system) ;;
        --help|-h) usage; return ;;
        *) usage >&2; exit 2 ;;
    esac
    if [[ $EUID -eq 0 ]]; then
        case "$action" in
            --init-web|--deps|--audit|--all)
                die "$action refuses to run as root; invoke this script as a normal user."
                ;;
        esac
    fi
    detect_fedora
    case "$action" in
        --install)
            install_required_packages
            ;;
        --check) check_environment ;;
        --native-tools)
            info "Native tools support npm packages that require local compilation; they are optional for pure JavaScript dependencies."
            install_missing_packages "${NATIVE_TOOL_PACKAGES[@]}" ;;
        --init-web) initialize_web_workspace ;;
        --deps) install_dependencies ;;
        --audit) audit_dependencies ;;
        --verify) verify ;;
        --all) run_all ;;
        --check-updates) check_fedora_updates ;;
        --update-system) confirm_fedora_system_update ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
