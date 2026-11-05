# Office access gateway

The optional [Office access extension](../extensions/office-access/README.md) adds a separate server-side authentication and authorization listener without changing bb core. It is not enabled automatically.

It can run as a local-path plugin or an independent Node process. The plugin has one setting, `configPath`, pointing to a private JSON policy. Its administrator CLI commands are `bb office-access status` and `bb office-access check`. The extension README is the configuration reference, including personal keys, browser sessions, trusted SSO-proxy headers, method/path/query/transport rules, audit and deployment restrictions.

Expose the gateway, not core. Keep core bound to 127.0.0.1:38886, disable alternate access paths, and use an HTTPS ingress to reach the gateway. Policy configuration is outside agent workspaces and outside Git. Role checks at this boundary do not automatically add row ownership, filter global event streams or sandbox agents/plugins.

See the extension's [operator skill](../extensions/office-access/skills/office-access/SKILL.md) and [tests](../extensions/office-access/test/).
