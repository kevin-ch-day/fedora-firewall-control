# Hardening and vulnerability operations

`ffc` is an inspection tool, not a patch manager or intrusion detector. It can identify available Fedora security advisories for the local network and security stack, but it cannot determine exploitability, whether a CVE is actively exploited, or whether a hostile network has compromised the host.

## Explicit advisory review

Run this before travel, after a long offline period, and before entering hostile-network mode:

```bash
./build/ffc --security-advisories
```

The command executes the read-only DNF5 advisory query for security advisories affecting `firewalld`, NetworkManager, nftables, the kernel, OpenSSL, curl, D-Bus, and PolicyKit. DNF5 can associate advisory references with CVE identifiers, but an identifier is not a local finding. Review the affected package, the vendor advisory, the installed version, and the operational impact before applying an update.

To independently inspect all available security updates, use:

```bash
dnf5 check-upgrade --security
dnf5 advisory list --security --with-cve
```

The DNF5 documentation specifies that `check-upgrade` exits `100` when updates are available and that the advisory command can list available security advisories and CVE references. [DNF5 check-upgrade documentation](https://dnf5.readthedocs.io/en/latest/commands/check-upgrade.8.html) and [DNF5 advisory documentation](https://dnf5.readthedocs.io/en/stable/commands/advisory.8.html)

## Threats worth reviewing

- **Unpatched privileged components.** Prior firewalld flaws have involved unauthorized firewall configuration through its control plane; for example, the historical CVE-2016-5410 was fixed by a vendor firewalld update. It is not evidence of a current Fedora vulnerability, but it is a reason to keep the firewall, D-Bus, PolicyKit, NetworkManager, kernel, and TLS stack patched. [Red Hat advisory for CVE-2016-5410](https://access.redhat.com/errata/RHSA-2016:2597)
- **Unauthorized runtime changes.** Firewalld exposes a D-Bus configuration interface, so the local PolicyKit/D-Bus authorization boundary matters. Historical firewalld documentation describes a lockdown whitelist, but current Fedora firewalld reports that the lockdown feature is deprecated and removed; do not build a new operating procedure around it without first checking the installed version. Review and test authorization policy separately, because a bad policy can block legitimate management tools. [firewalld D-Bus architecture](https://firewalld.org/documentation/architecture.html) and [historical lockdown configuration documentation](https://firewalld.org/documentation/configuration/firewalld-conf.html)
- **Configuration drift and competing rule managers.** Firewalld keeps runtime and permanent configuration separately, and direct rule management is deprecated. Do not mix independent firewall managers casually; firewalld specifically warns that direct iptables manipulation while it is running can lead to unexpected behavior. [firewalld runtime/permanent concepts](https://firewalld.org/documentation/concepts.html) and [firewalld enablement guidance](https://firewalld.org/documentation/howto/enable-and-disable-firewalld)
- **Hostile terminal and shell context.** `ffc` runs fixed argument vectors only. Its child processes use a restricted system `PATH` and `C` locale so a user-controlled `PATH` cannot redirect a tool and parsing remains stable across locales. Commands are also limited to 60 seconds and 1 MiB per captured stream to reduce hangs and memory pressure. Treat content from SSIDs, network metadata, and remote diagnostics as untrusted evidence.
- **Local evidence and credential tampering.** API credentials, operating mode, network-history records, and application logs are stored owner-only. The application rejects symlinks, hard-linked files, and non-regular files for these paths, bounds local reads, and normalizes history/log fields so untrusted SSID or provider data cannot inject extra TSV rows or log records.

## Safe response sequence

1. Save `--status` and `--readiness` output.
2. Run `--security-advisories`; inspect the advisory details for relevant items.
3. Apply updates through Fedora’s normal package workflow when you have power, connectivity, and a recovery window.
4. Reboot if a kernel or foundational service update requires it, then re-run the posture report.
5. Make firewall changes as separate, reviewed transactions; never combine an urgent package update with unreviewed zone changes on an untrusted network.

## Port intelligence

Listener and open-port views label ports as well-known (`0-1023`), registered (`1024-49151`), or dynamic/private (`49152-65535`). The built-in defensive catalogue covers more than 250 TCP, UDP, and SCTP assignments across management, identity, file sharing, databases, VPNs, discovery, routing, industrial control, container platforms, and web services; Fedora's local service database fills additional conventional-name gaps. Firewalld port ranges are identified as ranges rather than guessed as one service. The ranges follow the [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml).

The additional [port catalogue guide](PORT_CATALOG.md) describes the offline lookup order, the intentionally narrow conventional ranges, and the rules for adding entries.

These labels are triage aids only: an IANA registration or a conventional port number does not prove the process, protocol behavior, or remote reachability. Verify unusual listeners against the local process owner and actual traffic before making a firewall decision.
