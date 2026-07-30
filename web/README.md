# Fedora Firewall Control web API

This workspace contains a local, read-only browser dashboard and TypeScript API
in front of the authoritative native FFC snapshot. Open
`http://127.0.0.1:8787/` after starting the server to view the dashboard.

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
Cross-site browser requests are rejected using Fetch Metadata and `Origin`
checks before they can trigger native collection. Requests without browser
metadata, such as local `curl` commands, remain supported.
The HTTP parser accepts at most 8 KiB of headers, uses five-second header and
connection timeouts, disables automatic `HEAD` routes, rejects request bodies,
and closes idle keep-alive connections during shutdown.

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
must identify an existing executable regular file owned by the current user or
root and not writable by group or other. The API never returns that path or
native stderr.

Output is parsed as unknown JSON and validated with Ajv against the repository's
JSON Schema 2020-12 document at `schemas/dashboard-v1.schema.json`. Only a valid
`ffc.dashboard.v1` object reaches an API response. The server keeps a successful
snapshot in memory for two seconds and coalesces simultaneous requests into one
native collection. Cache expiry uses Node's monotonic performance clock, so a
wall-clock correction cannot make old evidence appear fresh. It has no disk
cache, database, or background polling loop.

## API

`GET /` serves a dedicated local landing page and its same-origin assets. The
decision-oriented posture screen at `/overview` shows readiness, current risk,
operator guidance, and compact pivots into focused workflows. It refreshes
every 30 seconds while visible, pauses collection in background tabs, and also
offers an explicit manual refresh control.
Meaningful changes between refreshes are summarized in an in-memory session
watch. This comparison state exists only in the current browser tab and is
discarded when the page closes; it is not persisted or sent elsewhere. Press
`R` while the page is focused to request a manual refresh.

Operator guidance distinguishes an inactive hostile-network assessment from
collection failures and intentionally unimplemented coverage. When normal mode
leaves DEF CON readiness unevaluated, the page shows the supported local
`./build/ffc --mode hostile` command. That command changes FFC assessment
criteria only; the web application remains read-only and never runs it.
Evidence components needing attention are shown first. Successfully collected
components are grouped into a collapsed native disclosure control so the
default screen stays compact without hiding the underlying coverage inventory.

The read-only tool deck can pause or resume automatic collection, copy a
diagnostic-free posture summary, and export the currently validated JSON
snapshot. These actions remain entirely in the browser and do not invoke new
native commands. Firewall, network, and exposure cards include collapsed
technical details, and the section bar provides local anchor navigation.

## Information architecture

The console has seven pages, all backed by the same validated native snapshot:

- `/` — Home: workflow landing and boundary summary.
- `/overview` — Overview: risk, readiness, guidance, and investigation pivots.
- `/firewall` — Firewall: service state, zone trust, modeled rules, and policy
  evidence.
- `/network` — Network: interface, profile, tunnel, route, DNS, and kill-switch
  verification.
- `/exposure` — Exposure: listeners and configured ingress shown as distinct
  signals.
- `/evidence` — Evidence: collection coverage, failures, and limitations.
- `/session` — Session: browser-tab-local posture changes.

This separation follows firewalld's zone, policy, and runtime/permanent model
and the overview-to-drilldown workflow used by security operations consoles.
Design references are the official [firewalld concepts](https://firewalld.org/documentation/concepts.html),
[firewalld zone documentation](https://firewalld.org/documentation/zone/), and
[Security Onion SOC](https://docs.securityonion.net/en/2.4/soc.html) and
[Alerts](https://docs.securityonion.net/en/2.4/alerts.html) documentation.
Alerts, Hunt, PCAP, and Cases are intentionally not navigation destinations:
the current native contract does not collect IDS events, flows, packets, or
case data, so presenting those workflows would imply capabilities that do not
exist.

The bounded migration plan for structured zones, listener bindings, findings,
and evidence provenance is documented in
[`docs/WEB_DASHBOARD_V2.md`](../docs/WEB_DASHBOARD_V2.md). The existing v1
contract remains strict and is not extended in place. Native v2 serialization
and schema validation are available through `./build/ffc --snapshot-json-v2`;
the web adapter deliberately remains on v1 until v2 failure-path coverage is
complete.

Each page has a focused DOM, active navigation state, page-specific rendering,
and the same validated snapshot source. A persistent sidebar provides the same
primary navigation and loopback/read-only boundary cue across every page,
collapsing into a horizontal navigation strip on narrow screens. The overview
does not duplicate the full focused workflows.

`GET /api/v1/health` reports the API boundary without executing FFC. Its
`snapshot_provider` object reports whether the provider is configured, whether
the in-memory cache is `empty`, `fresh`, or `expired`, and whether collection is
currently in flight. The v2 health route reports `degraded` and an unavailable
provider if its independently configured collector is absent.
Snapshot endpoints share a dependency-free token bucket allowing a burst of 30
requests and refilling over one minute. Responses include rate-limit state;
excess requests receive `429` and `Retry-After` without invoking FFC. Health,
HTML, and static assets are not rate limited.

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

`GET /api/v2/health` and `GET /api/v2/snapshot` expose the parallel structured
`ffc.dashboard.v2` contract. V2 uses a separate strict validator, two-second
memory cache, and in-flight request coalescing. Its runner executes only the
fixed `--snapshot-json-v2` argument with the same shell-free process, timeout,
output-limit, environment, executable-trust, Host-header, and loopback
boundaries as v1. Both versions also enforce the same Fetch Metadata and
same-origin request checks.

```bash
curl --fail --silent --show-error \
    http://127.0.0.1:8787/api/v2/snapshot | jq
```

The browser UI remains on v1 during this compatibility milestone. V2 being
available through the API does not enable firewall mutation, remote access, or
browser-selected native commands.

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

- No authentication, sessions, cookies, state-changing routes, streaming, or
  remote access exist.
- Collection is request-driven and cached for only two seconds.
- Failed collection never returns expired data as if it were current.
- The service is intended for an interactive local user, not unattended or
  system-wide deployment.
