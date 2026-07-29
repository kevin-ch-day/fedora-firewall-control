# Threat assessment and evidence limits

`ffc --threat-assessment` is a read-only, local evidence review. It does **not** claim to detect an attack, identify a threat actor, or establish the four confusion-matrix outcomes by itself.

## What the assessment means

| Outcome | Required evidence |
| --- | --- |
| True positive | A candidate alert corroborated as malicious by independent evidence. |
| False positive | A candidate alert explained by expected or benign activity. |
| True negative | No alert plus independent evidence that no relevant incident occurred. |
| False negative | No alert followed by later confirmation that a relevant incident occurred. |

This matters on conference, hotel, and other noisy networks: blocked traffic may be ordinary discovery or commodity scanning, while a quiet log may simply mean insufficient logging or an evasion technique. NIST notes that IDPS technologies cannot achieve completely accurate detection and inherently produce both false positives and false negatives. [NIST SP 800-94](https://csrc.nist.gov/pubs/sp/800/94/final)

## Evidence handled by `ffc`

- Bounded 24-hour counts of kernel `DROP`/`REJECT` journal events, plus only the number of distinct `SRC=` and `DPT=` values. It does not persist source addresses or raw log lines.
- Availability of local listener inventory and firewall/journal telemetry.
- TCP/UDP non-multicast protocol/port services, plus a separate multicast-only discovery count; best-effort local process names (never PIDs or command lines); and runtime/permanent firewall drift. The listener query does not establish absence of SCTP, DCCP, raw, or arbitrary protocol sockets. Raw IPv4/IPv6/interface bindings are shown separately so they do not inflate exposure findings.
- Broad port ranges and intra-zone forwarding configured on currently active firewalld zones. A broad configured range is a policy observation; it does not prove every port is listening or reachable. Intra-zone forwarding permits forwarding between interfaces or sources in the same zone; it does not by itself establish IP routing to another network.

Runtime interface membership is reported separately from policy drift because NetworkManager commonly binds a connected interface to a zone at runtime while the permanent zone has no interface listed. That expected dynamic binding is not presented as a suspicious configuration change. Likewise, configured intra-zone forwarding is informational when its active zone has only one interface/source member and therefore no current same-zone forwarding path.
- A bounded firewalld service-journal event count.
- Local time-synchronization and journald-service availability, because cross-source timestamp correlation is unreliable when either is missing.

The tool labels these as **candidate alert**, **exposure**, **coverage gap**, **scope limit**, or **no alert**. Scope limits explain telemetry the console deliberately does not collect and are not active warnings. “No alert” is deliberately never called “true negative.”

`ffc` does not detect outbound or lateral port scanning from a one-time listener view. MITRE's Network Service Discovery guidance describes detection that correlates process execution, socket connections, and sequential destination probing in a time window—telemetry this read-only console intentionally does not collect. [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)

The optional diagnostics view classifies traceroute hops as private/local, carrier-grade NAT/provider, link-local, multicast, or public. These scopes explain address ownership ranges; they do not identify a venue, ISP customer, or threat actor.

Use `ffc --network-diagnostics --extended` only when you intend to generate additional packets: it performs the regular probes plus one bounded traceroute each to Cloudflare, Google, Quad9, and Cisco/OpenDNS public resolvers. A destination or hop that does not respond is an incomplete route, not evidence of filtering or malicious activity.

`ffc --network-diagnostics --advanced` additionally runs a five-sample MTR report to Cloudflare and one direct `example.com` DNS query to each of Cloudflare, Google, and Quad9. The console distinguishes destination response loss from missing replies at intermediate routers: when the destination reports zero loss, intermediate MTR loss is commonly ICMP rate limiting or de-prioritization, not evidence of a degraded path. Direct DNS checks disclose the query and source address to the selected resolver, so the fixed low-sensitivity name is used rather than a user browsing name. [RFC 9076](https://www.rfc-editor.org/rfc/rfc9076.html) describes DNS privacy considerations.

## Safe analyst workflow

1. Preserve the time window and run `ffc --status`, `ffc --listeners`, and `ffc --threat-assessment`.
2. Correlate candidate events with local process ownership, firewall configuration, and, where authorized, network telemetry or packet capture.
3. Mark an alert benign only after documenting the expected source, service, and reason.
4. Treat unavailable logs, disabled denied-packet logging, and unavailable socket inventory as coverage gaps—not clean results.
5. If telemetry is needed, use a reviewed, rate-limited firewalld `log`, `nflog`, or `audit` rich rule. Firewalld documents rate limits for these actions; avoid unbounded logging on a noisy network. [firewalld rich-language documentation](https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html)

`ffc` never creates these rules automatically. A logging rule changes system behavior and may produce sensitive data or excessive log volume, so it requires an explicit reviewed change outside this read-only application.

NIST's log-management guidance emphasizes protecting log availability and integrity, and keeping clocks synchronized so records from multiple sources can be correlated. [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final)
