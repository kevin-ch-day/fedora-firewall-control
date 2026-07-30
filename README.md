# Fedora Firewall Control

`ffc` is a defensive, firewall-configuration read-only C++ terminal interface for inspecting Fedora's existing `firewalld` configuration. It does not replace firewalld, write nftables rules, reload the firewall, or change network configuration. It does write owner-only local logs, settings, and optional network history, and runs external diagnostics only when explicitly requested.

Version 0.1.2 reports service state, zones, interface and source bindings, services, ports, protocols, source ports, rich-rule counts, forwarding, masquerading, runtime/permanent drift, and a conservative readiness report. Its interactive dashboard uses ANSI color when attached to a terminal; the default `industrial` theme uses a high-contrast white, amber, and alarm-red console palette. Set `FFC_THEME=defcon` for the cyan DEF CON palette, `FFC_THEME=high-contrast` for a stronger blue/white palette, or `NO_COLOR=1` for plain text suitable for logs and accessibility tooling. The dashboard does not clear the terminal by default; set `FFC_CLEAR_SCREEN=1` if you prefer full-screen redraws. External display text is escaped before rendering, including control and bidi-format characters.

The interactive console is organized around operator workflows: **Readiness and current risk**, **Current signals and alerts** (`SNAPSHOT`), **Firewall and connections**, **Network and VPN**, **Incidents and evidence**, and **Settings and component status**. It uses compact breadcrumbs for submenus and keeps a detail view open until `B`, `R`, `H`, `!`, or `Q` is selected. The landing screen explicitly separates DEF CON readiness criteria, current posture, firewalld enforcement, FFC control, and isolation. Operating mode changes readiness criteria only; this release does not alter firewalld, NetworkManager, VPN, radios, or network connectivity. Monitoring, web, and emergency-isolation entries are visibly non-operational planning/status views, not hidden mutation paths.

The default home view is compact for an 80×24 terminal; press `?` to toggle the expanded evidence dashboard. `./build/ffc --snapshot-json` preserves the stable schema-versioned `ffc.dashboard.v1` summary consumed by the local web service. `./build/ffc --snapshot-json-v2` prints the parallel structured milestone with zone records, runtime/permanent drift, bounded listener bindings, and the complete finding inventory. Both commands are read-only and open no network listener. A schema-valid snapshot exits `0` even when evidence is partial or unavailable; the assessed risk and each evidence state are contained in JSON. The contracts are documented in [schemas/dashboard-v1.schema.json](schemas/dashboard-v1.schema.json) and [schemas/dashboard-v2.schema.json](schemas/dashboard-v2.schema.json). They exclude API keys, credentials, raw command output, journal contents, packet contents, process command lines, and saved network-history records.

The loopback web API serves both validated contracts at `/api/v1/snapshot` and
`/api/v2/snapshot`. The browser currently remains on v1 while structured v2
rendering is developed and tested.

## Build and run

```bash
sudo dnf install gcc-c++ cmake ninja-build firewalld
cmake -S . -B build -G Ninja -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
./build/ffc # short alias for ./build/fedora-firewall-control
```

On Fedora, install the minimal build/runtime dependencies with `./scripts/setup-firewall-dev.sh`, then build and test from any directory with `./scripts/build.sh`.

### CMake workflows

The traditional `cmake -S . -B build -G Ninja -DBUILD_TESTING=ON` workflow remains supported. `CMakePresets.json` also provides repeatable build trees. The sanitizer preset uses Clang so it has a self-contained sanitizer runtime on Fedora:

```bash
cmake --preset dev
cmake --build --preset dev
ctest --preset dev

cmake --preset sanitize
cmake --build --preset sanitize
ctest --preset sanitize

cmake --preset release
cmake --build --preset release
```

Development builds use `ccache` automatically when it is installed. Set `-DFFC_USE_CCACHE=OFF` to disable it. Additional CMake switches include `FFC_WARNINGS_AS_ERRORS`, `FFC_ENABLE_SANITIZERS`, `FFC_ENABLE_COVERAGE`, `FFC_EXPORT_COMPILE_COMMANDS`, and `FFC_ENABLE_RELEASE_HARDENING`. On Linux GCC/Clang release builds, the hardening option enables stack protection, `_FORTIFY_SOURCE=3`, PIE, full RELRO/BIND_NOW, and a non-executable stack.

For a non-interactive report, run `./build/ffc --status`. For automation or CI checks, `./build/ffc --readiness` returns `0` for a clean assessment, `1` when review warnings exist, and `2` on a failed readiness check. Read operations normally work unprivileged, though local PolicyKit policy can affect what firewalld exposes.

## Evidence coverage

Each security-relevant firewall observation is tracked as available, partial, or unavailable. A false or empty value is displayed as safe only when its query succeeded and its command-specific output is recognized; unavailable and partial evidence produces `UNKNOWN`, `WARN`, or a threat-assessment coverage gap instead. Applicable zones include interface-bound zones, source-bound zones, and the default zone for an unbound connected interface (or conservatively when NetworkManager classification is unavailable). Runtime/permanent drift compares both collections symmetrically, including a zone present on only one side.

Any rich rule in an applicable zone prevents a clean inbound-exposure result because its full semantics are not yet parsed. Active firewalld policy names are collected, but policy details are not yet modeled, so any active policy produces a readiness warning. Zone protocols and source ports are included in the assessed zone surface. Rich-rule semantics, ICMP controls, helpers, zone priorities, direct rules, and other firewalld surfaces remain explicitly unassessed; the resulting coverage note is informational rather than an automatic readiness warning. A zero readiness exit therefore means no modeled warning or failure, not complete firewalld policy verification. Journal counts at the 200-entry collection cap are lower bounds and produce a warning rather than a quiet result.

## Local application logs

`ffc` writes small, owner-only, structured local logs under `$XDG_STATE_HOME/fedora-firewall-control/` (or `~/.local/state/fedora-firewall-control/`). `operations.log` records lifecycle and dashboard refreshes, `audit.log` records requested actions, `security.log` records security-review actions, and `error.log` records failed actions and unavailable interactive dependencies. Entries use UTC timestamps and are capped at 512 KiB per file; logs are rotated in place when full. Control characters and ipify-style API keys are redacted before persistence. The logs intentionally exclude API-key values, raw command output, packet payloads, and firewall changes.

Run `./build/ffc --log-analysis` or select **Incidents and evidence → 4** in the dashboard to summarize retained activity, error counts, and repeated error event types. This is a local, explainable trend summary of `ffc`'s own records—not an intrusion-detection verdict or attacker-attribution system.

For an explicit connectivity check, `./build/ffc --network-diagnostics` sends two ICMP echo requests each to `1.1.1.1` and `8.8.8.8`, then runs a numeric traceroute to `1.1.1.1` with a maximum of eight hops and one query per hop. `--extended` compares the routes to four public resolvers. `--advanced` includes those routes, a five-sample MTR report to `1.1.1.1`, and one direct DNS lookup for `example.com` to each of Cloudflare, Google, and Quad9. These checks never run on a normal dashboard refresh. A missing reply or an intermediate router's MTR loss can be normal filtering or rate limiting; it is not evidence of an attack.

To review currently available security advisories affecting the local network and security stack, run `./build/ffc --security-advisories`. It performs an explicit, read-only DNF5 advisory query and lists CVE references when Fedora metadata provides them; it does not install updates. See [docs/HARDENING.md](docs/HARDENING.md) for the threat model and operational guidance.

## Safety model

The current 0.1.x release intentionally has no mutation path. Planned versions must follow `DISCOVER → SNAPSHOT → PLAN → CONFIRM → APPLY → VERIFY → COMMIT`, rolling back whenever verification fails. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/FIREWALL_POLICY.md](docs/FIREWALL_POLICY.md), and [docs/RECOVERY.md](docs/RECOVERY.md).

For multi-day defensive use, follow [docs/DEFCON_OPERATIONS.md](docs/DEFCON_OPERATIONS.md). It covers repeatable posture checks, runtime/permanent caveats, and panic-mode recovery.
