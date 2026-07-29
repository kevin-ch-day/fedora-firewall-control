# Fedora Firewall Control

`ffc` is a defensive, read-only C++ terminal interface for inspecting Fedora's existing `firewalld` configuration. It does not replace firewalld, write nftables rules, reload the firewall, or change network configuration.

Version 0.1.0 reports service state, zones, assigned interfaces, services, explicit ports, rich-rule counts, forwarding, masquerading, runtime/permanent drift, and a conservative readiness report. Its interactive dashboard uses ANSI color when attached to a terminal; set `NO_COLOR=1` for plain text, suitable for logs and accessibility tooling.

## Build and run

```bash
sudo dnf install gcc-c++ cmake ninja-build firewalld
cmake -S . -B build -G Ninja -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
./build/ffc # short alias for ./build/fedora-firewall-control
```

On Fedora, install the minimal build/runtime dependencies with `./scripts/setup-firewall-dev.sh`, then build and test from any directory with `./scripts/build.sh`.

For a non-interactive report, run `./build/ffc --status`. For automation or CI checks, `./build/ffc --readiness` returns `0` for a clean assessment, `1` when review warnings exist, and `2` on a failed readiness check. Read operations normally work unprivileged, though local PolicyKit policy can affect what firewalld exposes.

## Safety model

The current release intentionally has no mutation path. Planned versions must follow `DISCOVER → SNAPSHOT → PLAN → CONFIRM → APPLY → VERIFY → COMMIT`, rolling back whenever verification fails. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/FIREWALL_POLICY.md](docs/FIREWALL_POLICY.md), and [docs/RECOVERY.md](docs/RECOVERY.md).
