# DEF CON operations

This release is intentionally read-only. Use it to observe, record, and review the Fedora firewall posture over multiple days without adding a new path that could lock you out of networking.

## Daily routine

Before joining an untrusted network, build the current source and save a terminal report outside the repository if you need an evidence trail:

```bash
./scripts/build.sh
NO_COLOR=1 ./build/ffc --status | tee "$HOME/ffc-status-$(date +%F-%H%M).txt"
NO_COLOR=1 ./build/ffc --readiness
```

To intentionally record the observed public IP, default interface, gateway, and VPN-active state, run `./build/ffc --network-metadata`. This contacts `api64.ipify.org`; the provider receives your public IP and request time. The local history is written with owner-only permissions under `$XDG_STATE_HOME/fedora-firewall-control/` or `~/.local/state/fedora-firewall-control/`. Review it with `./build/ffc --network-history`.

That explicit capture also records the active NetworkManager connection profile and, for an active Wi-Fi network, its SSID, BSSID, and advertised security. These fields are intentionally absent from the routine dashboard. SSIDs and BSSIDs are sensitive location and tracking data; only capture them when you want an evidence record.

For an explicit reachability and path test, run `./build/ffc --network-diagnostics`. It sends two ICMP echo requests to each of `1.1.1.1` and `8.8.8.8`, followed by a numeric traceroute to `1.1.1.1` limited to eight hops and one query per hop. This creates external traffic and is never part of the ordinary refresh. Timed-out probes or hops can be caused by normal filtering; they are evidence to compare across observations, not attacker attribution.

Before travel and before joining a high-risk network, run `./build/ffc --security-advisories`. It asks DNF5 for available security advisories affecting the installed firewall, NetworkManager, kernel, TLS, D-Bus, PolicyKit, and related network packages. It only queries metadata and does not install anything. Treat reported CVEs as patch-review items rather than proof that the host is exploitable; review the advisory and package scope before deciding when to update.

To enable Geo ipify enrichment, first run `./build/ffc --configure-ipify-key` and enter a replacement API key at the hidden terminal prompt. The app saves it in `$XDG_CONFIG_HOME/fedora-firewall-control/ipify.key` or `~/.config/fedora-firewall-control/ipify.key` with owner-only permissions; it is never printed or placed in the repository. An `FFC_IPIFY_API_KEY` environment variable takes precedence when a temporary or managed secret is preferred. Then `./build/ffc --network-metadata --enrich` spends one Geo ipify Country API credit to add country, timezone, ISP, and autonomous-system data. The key is passed to curl through standard input rather than a process argument. Do not use `--enrich` for routine refreshes.

## Assessment mode

Use `./build/ffc --mode hostile` before a DEF CON, hotel, conference, or other untrusted-network session. This does not alter firewalld, NetworkManager, VPN, routing, or radios. It makes the readiness report stricter: network-reachable listeners, configured inbound services/ports, forwarding, and masquerading become failures rather than review warnings. Return to the normal assessment with `./build/ffc --mode normal`.

Treat a readiness exit status of `1` as a review signal and `2` as a failed posture check. Re-run the report after changing networks, resuming from sleep, connecting a VPN, or returning from an event venue.

## What to review

- Active interfaces and zone assignments, rather than every configured zone.
- NetworkManager device state without printing connection names or Wi-Fi SSIDs. Recheck it after suspend, venue changes, and VPN transitions; a connected device without an active-zone binding deserves investigation.
- Any allowed service, explicit port, rich rule, or forward-port in an active zone.
- Network-reachable local listening sockets. This is intentionally a separate signal: a firewall exception without a listener has different risk from a listening process that becomes reachable after a zone or network change.
- An active zone with target `ACCEPT`; it accepts otherwise-unmatched traffic.
- Forwarding, masquerading, and source bindings, which can alter traffic flow or trust.
- Runtime/permanent drift. A firewalld reload replaces runtime configuration with permanent configuration, so do not assume a tested runtime posture will survive a reload.
- Permanent configuration validity, checked through `firewall-cmd --check-config`.

Do not automatically reassign a VPN or tunnel interface. Review it separately: firewalld and NetworkManager both participate in interface/connection zone handling, and an inappropriate reassignment can break the tunnel or weaken its intended traffic boundary. `ffc` detects the locally installed NordVPN client and common active tunnel interface names, but treats no installed or active VPN as normal rather than a readiness failure.

## Interpreting threat signals

`ffc` cannot identify a hotel, DEF CON, a red team, or a specific threat actor from local host state. A connected Wi-Fi interface is a cue to review zone assignment and exposure, not proof that a network is hostile. Kernel `DROP`/`REJECT` journal entries are likewise evidence to investigate, not attribution; their availability depends on local logging configuration and journal access. Keep denied-packet logging decisions explicit because more logging can create a large volume of local data.

## Emergency isolation

Do not use panic mode casually. Firewalld documents that `firewall-cmd --panic-on` drops incoming and outgoing traffic and expires active connections; it is runtime-only. Keep local console access and know the recovery command before invoking it:

```bash
sudo firewall-cmd --panic-off
```

## Change discipline for later releases

When mutation features are introduced, first snapshot state, present a plan, require a typed confirmation, apply runtime-only changes, verify the resulting state, and keep rollback local. Do not use `--runtime-to-permanent` or reload firewalld as an automatic follow-up: both can turn a recoverable runtime test into a lasting configuration change.

## References

- [firewall-cmd manual](https://firewalld.org/documentation/man-pages/firewall-cmd.html)
- [Runtime versus permanent configuration](https://firewalld.org/documentation/configuration/runtime-versus-permanent.html)
- [Zone targets](https://firewalld.org/documentation/zone/options.html)
- [Lockdown configuration](https://firewalld.org/documentation/configuration/firewalld-conf.html)
- [NetworkManager nmcli reference](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html)
