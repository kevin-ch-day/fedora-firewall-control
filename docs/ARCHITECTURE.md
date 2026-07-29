# Architecture

The application is a C++ terminal client layered as `Application → FirewallBackend → firewalld command adapter → fixed-argument process runner`. `Application` owns the inspection lifecycle, command dispatch, refresh behavior, and terminal presentation while receiving its backend as a dependency. This keeps `main.cpp` as simple object composition and makes mock-backed application testing possible.

The runner uses `execvp`; it never invokes a shell. Standard output and standard error are captured separately.

`FirewallBackend` deliberately contains only inspection in 0.1. Future mutation APIs will be introduced only with snapshots, plans, explicit confirmation, verification, audit records, and rollback.

The command backend is a transitional adapter for `firewall-cmd`. A future D-Bus implementation can satisfy the same backend interface without changing the menu or readiness logic.
