# Fedora Firewall Control web API

This workspace contains the first functional web milestone: a local, read-only
Node.js/TypeScript API in front of the authoritative native FFC snapshot. There
is no browser interface yet.

## Security boundary

The production server binds to `127.0.0.1:8787` only and refuses to run as root.
The host and port are fixed; no environment variable, argument, request, or
configuration file can enable LAN or wildcard binding. The server does not
enable CORS, open a firewall port, install a service, daemonize, or mutate
firewalld or NetworkManager.

Only these Host headers are accepted:

```text
127.0.0.1:8787
localhost:8787
```

Responses use a restrictive Content Security Policy, `nosniff`, no-referrer,
same-origin resource policy, and `Cache-Control: no-store`.

## Native snapshot adapter

The server executes exactly:

```text
<validated-ffc-binary> --snapshot-json
```

It uses Node's shell-free `execFile` API with a 10-second timeout, a 1 MiB stdout
limit, a separately enforced 64 KiB stderr policy, UTF-8 decoding, locale `C`,
and an allowlisted environment. Browser input cannot select the executable or
add arguments.

The default executable is `<repository-root>/build/ffc`. A local operator may
set `FFC_BIN` to one absolute executable path. The path is canonicalized and
must identify an existing, executable, non-world-writable regular file. The API
never returns that path or native stderr.

Output is parsed as unknown JSON and validated with Ajv against the repository's
JSON Schema 2020-12 document at `schemas/dashboard-v1.schema.json`. Only a valid
`ffc.dashboard.v1` object reaches an API response. The server keeps a successful
snapshot in memory for two seconds and coalesces simultaneous requests into one
native collection. It has no disk cache, database, or background polling loop.

## API

`GET /api/v1/health` reports the API boundary without executing FFC.

```bash
curl --fail --silent --show-error \
    http://127.0.0.1:8787/api/v1/health | jq
```

`GET /api/v1/snapshot` returns the validated native document unchanged.

```bash
curl --fail --silent --show-error \
    http://127.0.0.1:8787/api/v1/snapshot | jq
```

The `X-FFC-Snapshot-Source` response header is `fresh` or `cache`. Failures use
bounded error objects and deliberate 502, 503, or 504 status codes without raw
paths, stack traces, Ajv details, or native stderr.

## Development

Node.js 24 and npm 11 from Fedora RPM packages are required. Install the exact
lockfile with lifecycle scripts disabled:

```bash
npm ci --ignore-scripts --fund=false --audit=false
```

Available commands:

```bash
npm run dev       # TypeScript watch mode; still loopback-only
npm run typecheck # strict checking without output
npm test          # Node test runner through tsx
npm run build     # compile into web/dist/
npm start         # run compiled server
npm run check     # typecheck, tests, and production build
```

Tests use Fastify injection wherever possible. Native adapter tests create only
temporary local executable fixtures; they do not use sudo, probe external
networks, change firewall state, or bind to a LAN interface.

## Current limitations

- No browser dashboard or static assets exist.
- No authentication, sessions, cookies, state-changing routes, streaming, or
  remote access exist.
- Collection is request-driven and cached for only two seconds.
- Failed collection never returns expired data as if it were current.
- The service is intended for an interactive local user, not unattended or
  system-wide deployment.
