# Architecture

The application is a C++ terminal client with explicit read-only layers:

```text
Application
├── PostureInspector             composes a single firewall-posture snapshot
│   ├── FirewalldCommandBackend  firewalld state and permanent/runtime comparison
│   ├── NetworkManagerInspector  device state only; no profile names or Wi-Fi SSIDs
│   ├── VpnInspector             local provider/tunnel awareness; never connects or disconnects
│   ├── SocketInspector          local listening-socket awareness; no process metadata
│   └── SecuritySignalsInspector bounded local journal summaries; no attribution
├── NetworkEvidenceService       explicit metadata capture and local-history persistence
│   └── NetworkMetadataInspector public-IP lookup and local route metadata
├── NetworkDiagnosticsInspector  explicit bounded ping and traceroute checks
├── IpifyCredentialStore         local owner-only credential or environment override
├── readiness                   pure posture evaluation
└── Dashboard → TerminalUi       presentation only
```

`Application` owns command dispatch and terminal flow. `PostureInspector` owns snapshot composition and cross-inspector availability notices, while `NetworkEvidenceService` owns the explicit collect-and-persist workflow. This removes duplicate metadata persistence logic from the CLI and interactive paths, keeps `main.cpp` as object composition, and makes each responsibility independently testable.

The runner uses `execvp`; it never invokes a shell. Standard output and standard error are captured separately.

`FirewallBackend` deliberately contains only inspection in 0.1. Future mutation APIs will be introduced only with snapshots, plans, explicit confirmation, verification, audit records, and rollback.

The command backend is a transitional adapter for `firewall-cmd`. A future D-Bus implementation can satisfy the same backend interface without changing the menu or readiness logic.
