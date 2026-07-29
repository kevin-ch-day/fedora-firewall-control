# Fedora Firewall Control

`ffc` is a defensive, firewall-configuration read-only C++ terminal interface for inspecting Fedora's existing `firewalld` configuration. It does not replace firewalld, write nftables rules, reload the firewall, or change network configuration. It does write owner-only local logs, settings, and optional network history, and runs external diagnostics only when explicitly requested.

Version 0.1.1 reports service state, zones, interface and source bindings, services, ports, protocols, source ports, rich-rule counts, forwarding, masquerading, runtime/permanent drift, and a conservative readiness report. Its interactive dashboard uses ANSI color when attached to a terminal; the default `industrial` theme uses a high-contrast white, amber, and alarm-red console palette. Set `FFC_THEME=defcon` for the cyan DEF CON palette, `FFC_THEME=high-contrast` for a stronger blue/white palette, or `NO_COLOR=1` for plain text suitable for logs and accessibility tooling.

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

Development builds use `ccache` automatically when it is installed. Set `-DFFC_USE_CCACHE=OFF` to disable it. Additional CMake switches include `FFC_WARNINGS_AS_ERRORS`, `FFC_ENABLE_SANITIZERS`, `FFC_ENABLE_COVERAGE`, and `FFC_EXPORT_COMPILE_COMMANDS`.

For a non-interactive report, run `./build/ffc --status`. For automation or CI checks, `./build/ffc --readiness` returns `0` for a clean assessment, `1` when review warnings exist, and `2` on a failed readiness check. Read operations normally work unprivileged, though local PolicyKit policy can affect what firewalld exposes.

## Evidence coverage

Each security-relevant firewall observation is tracked as available, partial, or unavailable. A false or empty value is displayed as safe only when its query succeeded; unavailable and partial evidence produces `UNKNOWN`, `WARN`, or a threat-assessment coverage gap instead. A zone is active when it has either an interface binding or a source binding. Runtime/permanent drift compares both collections symmetrically, including a zone present on only one side.

Active firewalld policy names are collected, but policy details are not yet modeled, so any active policy produces a readiness warning. Zone protocols and source ports are included in the assessed zone surface. ICMP controls, helpers, zone priorities, direct rules, and other firewalld surfaces remain explicitly unassessed; a clean zone summary is not a claim of complete firewalld policy coverage.

## Local application logs

`ffc` writes small, owner-only, structured local logs under `$XDG_STATE_HOME/fedora-firewall-control/` (or `~/.local/state/fedora-firewall-control/`). `operations.log` records lifecycle and dashboard refreshes, `audit.log` records requested actions, `security.log` records security-review actions, and `error.log` records failed actions and unavailable interactive dependencies. Entries use UTC timestamps and are capped at 512 KiB per file; logs are rotated in place when full. Control characters and ipify-style API keys are redacted before persistence. The logs intentionally exclude API-key values, raw command output, packet payloads, and firewall changes.

Run `./build/ffc --log-analysis` or select **Security and local evidence → 4** in the dashboard to summarize retained activity, error counts, and repeated error event types. This is a local, explainable trend summary of `ffc`'s own records—not an intrusion-detection verdict or attacker-attribution system.

For an explicit connectivity check, `./build/ffc --network-diagnostics` sends two ICMP echo requests each to `1.1.1.1` and `8.8.8.8`, then runs a numeric traceroute to `1.1.1.1` with a maximum of eight hops and one query per hop. `--extended` compares the routes to four public resolvers. `--advanced` includes those routes, a five-sample MTR report to `1.1.1.1`, and one direct DNS lookup for `example.com` to each of Cloudflare, Google, and Quad9. These checks never run on a normal dashboard refresh. A missing reply or an intermediate router's MTR loss can be normal filtering or rate limiting; it is not evidence of an attack.

To review currently available security advisories affecting the local network and security stack, run `./build/ffc --security-advisories`. It performs an explicit, read-only DNF5 advisory query and lists CVE references when Fedora metadata provides them; it does not install updates. See [docs/HARDENING.md](docs/HARDENING.md) for the threat model and operational guidance.

## Safety model

The current 0.1.x release intentionally has no mutation path. Planned versions must follow `DISCOVER → SNAPSHOT → PLAN → CONFIRM → APPLY → VERIFY → COMMIT`, rolling back whenever verification fails. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/FIREWALL_POLICY.md](docs/FIREWALL_POLICY.md), and [docs/RECOVERY.md](docs/RECOVERY.md).

For multi-day defensive use, follow [docs/DEFCON_OPERATIONS.md](docs/DEFCON_OPERATIONS.md). It covers repeatable posture checks, runtime/permanent caveats, and panic-mode recovery.
