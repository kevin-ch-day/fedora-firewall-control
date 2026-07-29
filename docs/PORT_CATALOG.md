# Port intelligence catalogue

`ffc` uses a layered, offline port-intelligence lookup:

1. An exact built-in defensive catalogue for widely encountered TCP, UDP, and SCTP services.
2. A second built-in catalogue for modern observability, container, logging, and security-platform ports.
3. A small set of unambiguous conventional ranges: VNC displays (`5900-5999`), X11 displays (`6000-6063`), and the default Kubernetes NodePort range (`30000-32767`).
4. Fedora's local service database (`getservbyport`) for conventional names absent from the built-in lists.

The catalogue is intentionally offline: inspecting a listener never downloads a registry or submits local network metadata. The source reference for registered assignments is the [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml).

## Contribution rules

- Use a precise label and transport protocol. TCP and UDP use of the same number can differ.
- Prefer security-relevant, operationally common, or clearly assigned services.
- Use a range only where the convention is well established and narrow.
- Do not call a listener malicious solely from a port number. Port intelligence is a triage hint; validate the owning process, firewall reachability, and traffic before acting.
- Keep entries offline and deterministic; this view must work on a hostile or disconnected network.
