# Fedora Firewall Control web workspace

This private Node.js 24 workspace is the starting point for the local, read-only
FFC dashboard. The native application remains the source of truth and exposes a
versioned snapshot with `ffc --snapshot-json`.

The starter intentionally has no third-party dependencies. Add reviewed,
exactly pinned dependencies to `package.json`, regenerate `package-lock.json`,
and commit both files before using the setup script's locked installation step.

The future HTTP service must bind only to loopback by default, execute the FFC
binary without a shell, validate `ffc.dashboard.v1`, and impose process timeout
and output-size limits.
