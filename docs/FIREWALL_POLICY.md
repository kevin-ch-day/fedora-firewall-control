# Firewall policy

`ffc` manages observability first. It does not consider a running daemon sufficient: enabled status, panic state, configured exposure, intra-zone forwarding, masquerading, and permanent/runtime drift are all reported.

Readiness warnings are deliberately conservative. A configured service or port is reported for review, not claimed malicious. VPN interfaces and NetworkManager bindings require separate, explicit classification in a later release.
