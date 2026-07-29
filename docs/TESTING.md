# Testing

Run the unit tests with:

```bash
ctest --test-dir build --output-on-failure
```

Tests cover firewalld parsing, available/partial/unavailable evidence handling, readiness and drift classification, source-only active zones, threat assessment, logging, storage, diagnostics parsing, and bounded process execution without invoking the system firewall. Process-runner fixtures include exec failure, ordinary timeout, output limits, closed input, and descendants retaining output pipes. Test manual inspection against a disposable Fedora VM before relying on a new firewalld version or policy change.
