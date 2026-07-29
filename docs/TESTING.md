# Testing

Run the unit tests with:

```bash
ctest --test-dir build --output-on-failure
```

Tests cover firewalld output parsing and readiness classification without invoking the system firewall. Test manual inspection against a disposable Fedora VM before relying on a new firewalld version or policy change.
