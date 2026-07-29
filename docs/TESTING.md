# Testing

Run the unit tests with:

```bash
ctest --test-dir build --output-on-failure
```

Tests cover firewalld parsing, command-specific malformed-output handling, available/partial/unavailable evidence handling, default-zone fallback, source-only active zones, rich-rule conservatism, readiness and drift classification, status-aware bounded journal evidence, TCP/UDP and multicast listener handling, threat assessment, atomic log rotation, bounded network-history retention, storage replacement safety, diagnostics parsing, terminal-output sanitization, and bounded process execution without invoking the system firewall. CTest also verifies a temporary-prefix install and the `ffc` alias. Process-runner fixtures include exec failure, ordinary timeout, output limits, closed input, and descendants retaining output pipes. Test manual inspection against a disposable Fedora VM before relying on a new firewalld version or policy change.
