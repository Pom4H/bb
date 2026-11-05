# Office access for bb

A server-side authorization gateway that runs as a bb plugin or as an independent Node process. It does not modify bb core and has no runtime npm dependencies.

This is the first access-boundary implementation, not a claim that bb now has automatic per-thread tenancy. Its policy checks every incoming HTTP request and WebSocket upgrade before forwarding anything to the private bb server.

## Features

- Personal, randomly generated access keys; only SHA-256 digests are stored in the policy.
- Browser login with opaque HttpOnly, SameSite=Strict cookies, Secure cookies on HTTPS, logout, bounded session storage and expiring connections.
- Optional trusted SSO-proxy identity assertions, checked against both a shared secret and the proxy's actual socket IP. Roles always come from the server policy.
- Deny-by-default rules for role, method, path, query selectors and transport. Explicit deny overrides allow. HTTP GET never implicitly grants WebSocket access.
- Streaming HTTP/SSE and WebSocket relay, credential/header sanitization, Origin/Host checks, ambiguous-path rejection and JSON access audit without request bodies, query strings or tokens.
- Plugin settings, `bb office-access status`, `bb office-access check`, and a status HTTP endpoint. No database or host-daemon protocol changes.

## Required deployment boundary

```text
Browser or API client
    -> HTTPS ingress / optional SSO proxy
    -> Office access gateway (127.0.0.1:3070)
    -> private bb core (127.0.0.1:38886)
```

Only the gateway may be exposed through the office ingress. Keep bb core and its host-daemon ports private; block alternate bb connect tunnels, port shares and any other route around this gateway. Binding to loopback does not protect against untrusted processes on the same machine. Agent execution must be on appropriately isolated machines/containers without access to core loopback, policy files or credentials.

Set bb's public app origin to the external HTTPS origin, and restart the launcher with its server bound to loopback. The upstream default is 38886, not the gateway port. Changing `BB_SERVER_BIND_HOST` requires a full restart, not just `config refresh`.

```bash
npx bb-app config set BB_APP_URL https://bb.example.com
npx bb-app start --server-bind-host 127.0.0.1
```

The HTTPS ingress must preserve the public Host and Origin and support WebSocket upgrades. Do not trust arbitrary client forwarding headers. Add ingress request/login rate limits and appropriate upload limits. The gateway does not manage TLS certificates or perform an OIDC authorization-code flow itself.

## Prepare a private policy

From this directory:

```bash
umask 077
cp config.example.json /absolute/private/path/office-access.json
node credential.mjs administrator admin 30
node credential.mjs finance-user finance 30
```

The generator prints a user record to stdout and the plaintext key once to stderr. Replace the example user records with the generated records, deliver keys securely, and do not publish either the private policy or terminal logs. The sample hashes and thread ID are placeholders, not working credentials or production permissions.

Edit `publicOrigin`, `upstream` and rules. Restrict the file to the server operator with mode 0600 and keep it outside agent workspaces. Never commit a real policy. Validate it before enabling access:

```bash
node run.mjs --check /absolute/private/path/office-access.json
```

The example deliberately grants administrators broad access but gives `finance` only one exact thread read. It does not pretend to be a complete employee UI preset. A full unfiltered core event stream or terminal is an administrator capability until its downstream protocol/data is explicitly scoped.

## Run as a bb plugin

On the trusted server, install this directory:

```bash
bb plugin install /absolute/path/to/bb/extensions/office-access --yes
bb plugin list
```

Use the installed ID shown by `bb plugin list` as `<id>`:

```bash
bb plugin config <id> set configPath /absolute/private/path/office-access.json
bb plugin reload <id>
bb office-access check
bb office-access status
```

The same `configPath` field appears in Settings > Installed plugins > Office access. Changes to the file or its path take effect on plugin reload. Reloading closes gateway connections and revokes all browser sessions; it does not temporarily expose an unguarded listener. Missing or invalid configuration never opens the listener.

Status is also available through `GET /api/v1/plugins/<id>/http/status`. Access to it through the gateway still needs an explicit policy grant. The CLI commands above are local administrator operations; this extension does not change the existing bb CLI's remote credential transport.

## Run independently

Do not run this and the plugin on the same port at the same time.

```bash
node run.mjs /absolute/private/path/office-access.json
```

Audit events go to stdout; startup/error messages go to stderr. Supervise this process using your normal service manager. SIGINT/SIGTERM closes its listener and connections. Restart after changing the policy.

Users sign in at `/office/login` with their personal key. API clients send `Authorization: Bearer <key>` to the gateway. `/office/me` returns only the current identity and roles. `POST /office/logout` requires the same Origin and clears the current browser session; it does not revoke the underlying personal key. Remove/change that key in the policy and reload to revoke it everywhere.

## Policy contract

`version` must be 1. Unknown fields are rejected so misspelled restrictions cannot silently disappear.

| Field | Meaning |
| --- | --- |
| `publicOrigin` | Exact external HTTPS origin; HTTP is allowed only for local development. |
| `upstream` | HTTP(S) origin on 127.0.0.1, ::1 or localhost, without a path. |
| `listen` | IP address and port; default 127.0.0.1:3070. Port 0 is useful in tests only. |
| `sessionSeconds` | Session/connection lease, 1-86400 seconds; default 3600. |
| `users` | Unique id, server-owned roles, required expiry timestamp, optional personal-token digest. No digest is needed for an SSO-only identity. |
| `rules` | Explicit effect, roles, methods, transport, path and optional query selectors. |
| `authProxy` | Optional shared-secret digest and exact trusted peer IPs. |

A rule path is exact or ends in `/*`; `/api/v1/threads/*` does not match `/api/v1/threads` itself. To permit a list, grant it separately only after checking whether it reveals other users' data. All `/internal` requests are blocked even for administrators.

Allow rules without `query` accept no query parameters. An object such as `{"threadId":["approved-id"]}` requires exactly those keys and values; duplicate or extra parameters do not match. `"query":"any"` is an explicit broad grant. Deny rules omit `query` to deny all queries on their matching path. Bodies are not interpreted: granting POST to a general-purpose RPC dispatcher grants that endpoint's capabilities, not row-level authorization inside its JSON payload.

WebSocket rules must explicitly specify `"transport":"websocket"` and method GET. The gateway checks the upgrade and expires/revokes the connection; it does not inspect each frame, filter a global event stream, or infer resource IDs inside RPC messages. Keep global `/ws`, terminals, unrestricted plugin RPC, plugin installation, settings and shell execution admin-only. Limited office roles should use narrowly scoped plugin APIs that enforce their own object ACL using the verified `x-bb-office-subject` header. That header is trustworthy only on requests coming exclusively through this gateway.

## SSO-proxy integration

Optional policy fragment:

```json
{
  "authProxy": {
    "secretSha256": "REPLACE_WITH_64_HEX_SHA256_DIGEST",
    "trustedPeers": ["127.0.0.1"]
  }
}
```

After authenticating a user, the ingress overwrites `X-Auth-Request-User` with the policy user id and `X-BB-Auth-Proxy-Key` with a high-entropy shared secret. Strip client-supplied values first. The gateway checks the actual socket peer, not X-Forwarded-For. Include the exact IPv4/IPv6 form used by the ingress. Unknown/expired users and missing/incorrect secrets are denied. Client-supplied role headers are ignored and overwritten. Personal bearer credentials take precedence; an invalid bearer never falls back to a cookie or proxy assertion.

Use the credential generator to generate a secret and its digest; only its digest belongs in `authProxy`. Store the plaintext in the ingress secret store. Never expose it to browser JavaScript. Configure the ingress for both HTTP and WebSocket authentication. Revoking an IdP session must also terminate existing connections at the ingress or wait for the configured gateway connection lease; the gateway does not introspect the IdP mid-stream.

## Verification and remaining scope

```bash
node --experimental-strip-types --test test/*.test.mjs
node run.mjs --check config.example.json
```

The tests use real ephemeral HTTP servers and TCP WebSocket upgrades, plus a narrow plugin API facade for lifecycle tests. There are no mocked database tests. The extension is intentionally outside the pnpm workspace and does not add root dependencies or change its lockfile.

Verified with Node 22.16.0: 40 tests covering request/path/query denial, header spoofing, cookie login, CSRF, trusted-proxy authentication, credentials stripping, SSE, WebSocket policy, byte relay, expiry/logout/shutdown, invalid config and plugin lifecycle. Full bb installation, monorepo typecheck/build, browser UI integration and Bun compatibility have not been run in this environment. Complete those checks on the pinned bb version before production use.

This layer does not sandbox full-trust plugins or shell-capable agents, create per-record ownership in bb's database, filter search/list responses, or rewrite workflow/tool permissions. Those checks belong in scoped business services and isolated execution. Access audit records the gateway decision, not successful completion of a downstream action. Persist/export logs using the operator's existing logging infrastructure.
