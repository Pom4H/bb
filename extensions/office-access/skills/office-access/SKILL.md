---
name: office-access
description: Configure and verify the Office access server gateway for bb. Use for personal keys, SSO proxy assertions, request rules and access troubleshooting.
---

# Office access

Read `../../README.md` for the complete configuration, security boundary and deployment contract.

Local administrator commands:

```bash
bb office-access status
bb office-access check
bb plugin config <installed-id> set configPath /absolute/private/path/office-access.json
bb plugin reload <installed-id>
```

`configPath` is the plugin's only setting. It must be absolute. Invalid/missing configuration opens no listener. Reload after changing the path or policy; reload revokes sessions and closes active connections. Status is also exposed at the plugin's `/http/status` endpoint.

Generate a personal key with `node credential.mjs <user-id> <role> [days]` from the extension directory. Store only the emitted digest record in the private policy. The plaintext key is written once to stderr; never include it in chats, commits, shared logs or tool output sent to a model.

Check a file independently with `node run.mjs --check <policy-file>`; start independently with `node run.mjs <policy-file>`. Do not run plugin and standalone listeners on the same port.

Keep bb core on private loopback, prevent alternate tunnel/port access, and expose only the gateway through HTTPS. Never treat hiding controls as authorization. Rules are deny-by-default; review method, exact path, query and transport. A WebSocket grant is separate from an HTTP GET grant.

Do not grant limited users global `/ws`, arbitrary RPC, terminals or plugin/settings administration. Their payloads and responses are not automatically object-scoped by this gateway. Use limited business APIs with server-enforced object ACLs and isolated agent execution. Do not relax policies merely to make a failing test or UI call pass.

Run `node verify.mjs` from the extension directory for syntax, regression tests and sample-policy validation. On staging, run `node smoke.mjs <public-origin> <private-key-file>` with an operator key stored in a 0600 regular file; never pass the key itself on the command line. This script is read-only and is not a row-ACL or native-device acceptance test. Read `../../../../docs/office-access-handoff.md` before extending auth: it records the existing Authentik donor and the native session work still required.
