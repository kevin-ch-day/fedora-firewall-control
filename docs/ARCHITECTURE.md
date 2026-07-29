# Architecture

The application is a C++ terminal client with explicit read-only layers:

```text
OperationsConsole
├── CommandLine parser                 maps argv to a typed, validated command
├── CommandExecutor                    non-interactive command behavior and exit codes
├── InteractiveSession                 refreshable dashboard state and keyboard loop
├── DefensivePostureCollector          composes a single firewall-posture snapshot
│   ├── FirewalldCommandBackend  firewalld state and permanent/runtime comparison
│   ├── NetworkManagerInspector  device state only; no profile names or Wi-Fi SSIDs
│   ├── VpnInspector             local provider/tunnel awareness; never connects or disconnects
│   ├── SocketInspector          TCP/UDP listener awareness; best-effort process names only
│   └── SecuritySignalsInspector status-aware bounded local journal summaries; no attribution
├── NetworkEvidenceRecorder      explicit metadata capture and local-history persistence
│   └── NetworkMetadataInspector public-IP lookup and local route metadata
├── ConnectivityAssessment        explicit bounded active-probe orchestration
│   ├── NetworkRoute              route address scope and hop data model
│   ├── NetworkAddressClassifier  IPv4/IPv6 scope classification
│   └── NetworkPathParser         traceroute and MTR output parsing
├── VulnerabilityAdvisoryCollector explicit DNF5 query for available security advisories
├── IpifyCredentialStore         local owner-only credential or environment override
├── readiness                   pure posture evaluation
└── OperationsDashboard          menu/chrome façade
    ├── DashboardSnapshot         schema-versioned risk, evidence, recommendation, and freshness model
    ├── PostureRenderer          firewall, exposure, zone, and readiness views
    ├── NetworkRenderer          metadata, history, and advisory views
    │   └── NetworkDiagnosticsRenderer active-probe presentation
    └── TerminalUi               theme-aware terminal primitives
```

`OperationsConsole` is a thin router: it sends typed commands to `CommandExecutor` or starts `InteractiveSession`, but never interprets raw arguments or owns dashboard state. `InteractiveSession` converts each collected `FirewallState` into one schema-versioned `DashboardSnapshot`, which carries a monotonic collection time, conservative current-posture risk, separately labeled DEF CON readiness, per-component evidence status, typed findings, and destination-aware recommendations. It contains no terminal styling and is the future boundary for JSON output and a local read-only dashboard. `DefensivePostureCollector` owns snapshot composition and cross-inspector availability notices, while `NetworkEvidenceRecorder` owns the explicit collect-and-persist workflow. `OperationsDashboard` delegates feature-specific presentation to focused renderers. This separates CLI exit-code behavior, keyboard-loop behavior, and view rendering while keeping `main.cpp` as object composition.

Implementation files follow the same boundaries under `src/`: `app/`, `core/`, `firewall/`, `network/`, `security/`, and `ui/`. The network diagnostics area is intentionally split into `network_diagnostics.cpp` (probe orchestration), `network_address.cpp` (scope classification), and `network_path_parser.cpp` (untrusted tool-output parsing); their shared public model is `include/ffc/network_route.hpp`. Public interfaces remain under `include/ffc/` so callers do not depend on implementation layout.

The runner uses `execvp`; it never invokes a shell. Standard output and standard error are captured separately. Each command has a dedicated process group, a bounded execution deadline, and a bounded post-termination pipe-drain period so a descendant retaining an inherited pipe cannot hang the console indefinitely.

`FirewallBackend` deliberately contains only inspection in 0.1.x. Firewall observations carry available, partial, or unavailable collection status; command success alone is insufficient when its output does not match the expected shape. The applicable-zone resolver centralizes explicit interface/source bindings and default-zone fallback before readiness, threat assessment, and rendering use the policy model. Readiness renders unavailable policy evidence as a warning rather than a safe value. Future mutation APIs will be introduced only with snapshots, plans, explicit confirmation, verification, audit records, and rollback.

`TerminalUi` is the final display boundary. It escapes untrusted controls, malformed UTF-8, and Unicode bidi/format characters before color styling, preventing observed network or command output from issuing terminal-control actions.

The command backend is a transitional adapter for `firewall-cmd`. A future D-Bus implementation can satisfy the same backend interface without changing the menu or readiness logic.
