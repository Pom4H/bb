# Office access: login reliability and reuse assessment

Review baseline: Pom4H/bb PR #1 at `da45153b4280f6558355aefceb86cd7fa7b67b08`, based on `fa30b0a7dcdf745f7baf8e41721f754b7d3198fe`. Checked on 2026-11-05. This change hardens the existing optional gateway; it does not turn unmodified bb into a multi-tenant server.

## Existing implementations reviewed before this follow-up

The upstream [Authentik/thread-access request #6317](https://github.com/get-bb/bb/issues/6317) links an implementation at [entin-hun/bb commit 286da1a](https://github.com/entin-hun/bb/commit/286da1a21e91008b8e89a79cce4d50dc1da11561). Its [thread-access.ts](https://github.com/entin-hun/bb/blob/286da1a21e91008b8e89a79cce4d50dc1da11561/apps/server/src/services/thread-access.ts) checks database-backed owner/maintainer/member/viewer roles. This is the relevant reuse candidate for per-thread permissions, unlike a path-only proxy. The issue explicitly excludes per-user machine ownership and provider credential isolation. The source was inspected; no claim is made that this fork was built or audited here.

Do not implement a second OIDC flow in this extension. Evaluate the existing fork against the current schema, routes, terminal operations, WebSocket subscriptions, file downloads and SDK before porting it. Its helper intentionally preserves the single-user path when no request user exists; porting that helper alone without the corresponding authenticated request boundary would not establish authorization.

The previously identified [Cloudflare Access plugin](https://github.com/MGrin/bb-plugin-cf-tunnel) is a separate remote-access alternative, not a thread-ownership solution. Its previously reviewed documentation describes Cloudflare JWT validation. It was not reinstalled, executed or imported by this change.

The [existing mobile client](https://github.com/Pom4H/bb/tree/fa30b0a7dcdf745f7baf8e41721f754b7d3198fe/apps/mobile) should be extended rather than replaced. Its [Direct URL probe](https://github.com/Pom4H/bb/blob/fa30b0a7dcdf745f7baf8e41721f754b7d3198fe/apps/mobile/src/lib/profiles/probe.ts) requests `/health` and `/api/v1/system/config` before opening the WebView, without gateway credentials. The gateway correctly refuses those anonymous requests. Making these routes public is not an authentication integration.

## Changed behavior

- A document navigation such as `/threads/thr_123?panel=files` receives a same-origin login redirect while unauthenticated. The login page retains the relative destination through `next`; after successful login the normal policy is evaluated on the destination. Signing in never grants an otherwise forbidden resource.
- Return targets must be bounded, unambiguous, relative page URLs. Other origins, protocol-relative URLs, backslashes, encoded path separators, dot segments, fragments, duplicate/unknown login parameters and API/internal/auth/WebSocket/install targets are refused. Targets embedded in the login script escape `<` and Unicode line separators.
- Cross-site top-level GET navigations may reach the public login page or its redirect only. They never forward a protected request, even if a cookie is supplied. Cross-site API calls, iframe loads, mutations and WebSocket upgrades remain forbidden. Explicit bearer/proxy authentication failures remain errors, never HTML login redirects.
- The login page has a narrow-screen layout, 16px input text, 48px controls, keyboard focus indicators and an announced status. Its form defaults to POST even without JavaScript. Login fetch uses same-origin mode and refuses redirects, clears the input immediately, prevents duplicate submission and permits retry after a network error. These behaviors have script/HTTP tests; they have not been visually verified on iOS or Android.
- Login records the access decision before issuing a cookie or replacing a live session. A synchronous audit failure returns 503 with no new cookie and leaves the previous session intact. The audit callback is synchronous; this does not claim durable remote log delivery.
- Successful replacement login revokes the prior browser session and closes its HTTP/WebSocket leases, including when switching accounts. Other devices' sessions are unaffected. Logout revokes the session even if its audit record fails; in that case the response is 503, not a false success.
- Upstream WebSocket 401/403 responses retain those statuses instead of being rewritten as 502, so clients can distinguish an authentication/permission failure from a transport failure. Unauthorized HTTP replies include a Bearer challenge. No credentials are accepted in URLs.

## Mobile acceptance boundary

| Surface | Status of this change |
| --- | --- |
| Mobile browser page entry / deep links | Implemented; HTTP/script regression tests pass |
| Gateway session expiry, replacement and logout | Tested with actual local HTTP/TCP connections |
| Official native Direct URL login | Still pending: requires a shared authenticated session for probe, native SDK, WebView and WebSocket |
| Physical iPhone / Android validation | Not run |
| Push payload visibility and recipient ACL | Not implemented or claimed |
| Per-thread tenancy, shared search and realtime filtering | Not implemented by this gateway |

Do not use a User-Agent or app-surface header as proof of identity. Do not exempt native clients from CSRF/origin checks. Do not make `/system/config`, global realtime or file APIs anonymous merely to get pairing through. A native login integration must verify both cookie stores/session propagation and credential revocation; entering a URL in the app is not sufficient evidence.

Existing bb browser caches, per-user data ownership and shell isolation remain outside this patch. Revoking a session is not a claim that local device storage was erased or an already-running agent task was stopped.

## Verification

```sh
node --experimental-strip-types --test extensions/office-access/test/*.test.mjs
node --check extensions/office-access/gateway.mjs
node --check extensions/office-access/login.mjs
git diff --check
```

On Node 22.16.0, all 40 pre-existing extension tests passed before changes. Adding the 12 HTTP/TCP regression tests to the original gateway produced 11 failures and one already-passing guard check. After the implementation, all 56 tests pass: the original 40, 12 HTTP/TCP cases and four tests executing the generated login script against a small DOM/fetch facade. These last tests are not a browser/device run. The tests use a local fixture backend, not a running bb instance; the original plugin lifecycle tests use a Plugin SDK facade, not installation in the full app.

The changed runtime source and existing tests were reconstructed from the pinned PR through GitHub reads and checked against these Git blob hashes before editing:

| File | Original Git blob |
| --- | --- |
| `gateway.mjs` | `093066b61bedf51716560a2f77923add68ddecc5` |
| `policy.mjs` | `6e2201ca4d1b253fd621a320e3c67a8cb11c1533` |
| `server.ts` | `04f98a42950f6b5a1aae6c86b56ccf583fb4ddbb` |
| `test/access.test.mjs` | `4ed5a2e01aba868ce007c1a654dd9f146814d162` |
| `test/plugin.test.mjs` | `a3e82af0dc84e15d1b7209b8639850e47efe3008` |

Full monorepo Turbo checks, the actual Authentik integration, native builds, Bun compatibility and end-to-end deployment were not run. This is not production sign-off. Keep the PR in draft until its intended deployment boundary and integration tests are established.

This is the historical 56-test follow-up record. The subsequent audit hardening and smoke tooling bring the suite to 71 tests; see [current handoff](office-access-handoff.md).
