# Fedora Firewall Control

`ffc` is a defensive, read-only C++ terminal interface for inspecting Fedora's existing `firewalld` configuration. It does not replace firewalld, write nftables rules, reload the firewall, or change network configuration.

Version 0.1.0 reports service state, zones, assigned interfaces, services, explicit ports, rich-rule counts, forwarding, masquerading, runtime/permanent drift, and a conservative readiness report. Its interactive dashboard uses ANSI color when attached to a terminal; the default `industrial` theme uses a high-contrast white, amber, and alarm-red console palette. Set `FFC_THEME=defcon` for the cyan DEF CON palette, `FFC_THEME=high-contrast` for a stronger blue/white palette, or `NO_COLOR=1` for plain text suitable for logs and accessibility tooling.

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

For an explicit connectivity check, `./build/ffc --network-diagnostics` sends two ICMP echo requests each to `1.1.1.1` and `8.8.8.8`, then runs a numeric traceroute to `1.1.1.1` with a maximum of eight hops and one query per hop. `--extended` compares the routes to four public resolvers. `--advanced` includes those routes, a five-sample MTR report to `1.1.1.1`, and one direct DNS lookup for `example.com` to each of Cloudflare, Google, and Quad9. These checks never run on a normal dashboard refresh. A missing reply or an intermediate router's MTR loss can be normal filtering or rate limiting; it is not evidence of an attack.

To review currently available security advisories affecting the local network and security stack, run `./build/ffc --security-advisories`. It performs an explicit, read-only DNF5 advisory query and lists CVE references when Fedora metadata provides them; it does not install updates. See [docs/HARDENING.md](docs/HARDENING.md) for the threat model and operational guidance.

## Safety model

The current release intentionally has no mutation path. Planned versions must follow `DISCOVER → SNAPSHOT → PLAN → CONFIRM → APPLY → VERIFY → COMMIT`, rolling back whenever verification fails. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/FIREWALL_POLICY.md](docs/FIREWALL_POLICY.md), and [docs/RECOVERY.md](docs/RECOVERY.md).

For multi-day defensive use, follow [docs/DEFCON_OPERATIONS.md](docs/DEFCON_OPERATIONS.md). It covers repeatable posture checks, runtime/permanent caveats, and panic-mode recovery.
