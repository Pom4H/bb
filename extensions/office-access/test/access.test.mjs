import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import http from "node:http";
import net from "node:net";
import { test } from "node:test";
import { createAccessGateway } from "../gateway.mjs";
import { authorize, canonicalPath, tokenDigest, validateConfig } from "../policy.mjs";

const ADMIN = randomBytes(32).toString("base64url");
const READER = randomBytes(32).toString("base64url");
const PROXY_KEY = randomBytes(32).toString("base64url");
const origin = "https://office.test";

function configuration(upstream = "http://127.0.0.1:3000") {
  return {
    version: 1,
    publicOrigin: origin,
    upstream,
    listen: { host: "127.0.0.1", port: 0 },
    sessionSeconds: 3600,
    users: [
      { id: "roman", roles: ["admin"], tokenSha256: tokenDigest(ADMIN), expiresAt: "2099-01-01T00:00:00Z" },
      { id: "sales", roles: ["reader"], tokenSha256: tokenDigest(READER), expiresAt: "2099-01-01T00:00:00Z" },
    ],
    rules: [
      { effect: "allow", roles: ["admin"], methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], transport: "http", path: "/*", query: "any" },
      { effect: "allow", roles: ["admin"], methods: ["GET"], transport: "websocket", path: "/*", query: "any" },
      { effect: "allow", roles: ["reader"], methods: ["GET"], transport: "http", path: "/api/v1/threads/owned" },
      { effect: "allow", roles: ["reader"], methods: ["GET"], transport: "http", path: "/api/v1/files/content", query: { fileId: ["owned"] } },
      { effect: "deny", roles: ["admin"], methods: ["GET"], transport: "http", path: "/secrets/*" },
    ],
  };
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(server.address().port); });
  });
}

async function fixture(t, edit = () => {}, options = {}) {
  const seen = [];
  const events = [];
  const sockets = new Set();
  const backend = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const entry = { url: request.url, method: request.method, headers: request.headers, body: Buffer.concat(chunks).toString("utf8") };
    seen.push(entry);
    if (request.url === "/sse") {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write("data: first\n\n");
      setTimeout(() => response.end("data: second\n\n"), 10);
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(entry));
  });
  backend.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  backend.on("upgrade", (request, socket, head) => {
    seen.push({ url: request.url, headers: request.headers, websocket: true });
    if (["/ws/reject/401", "/ws/reject/403"].includes(request.url)) {
      socket.end(`HTTP/1.1 ${request.url.split("/").at(-1)} Rejected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      return;
    }
    const accept = createHash("sha1").update(`${request.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    if (head.length) socket.write(head);
    socket.on("data", (chunk) => socket.write(chunk));
    socket.on("error", () => {});
  });
  const backendPort = await listen(backend);
  const raw = configuration(`http://127.0.0.1:${backendPort}`);
  edit(raw);
  const gateway = createAccessGateway(raw, { audit: (event) => { events.push(event); return options.audit?.(event); } });
  const port = await listen(gateway.server);
  t.after(async () => {
    await gateway.close();
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => backend.close(resolve));
  });
  function request(path, { method = "GET", token, headers = {}, body } = {}) {
    return new Promise((resolve, reject) => {
      const outgoing = http.request({ host: "127.0.0.1", port, path, method, headers: { host: "office.test", ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers } }, (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.once("error", reject);
        response.once("end", () => resolve({ status: response.statusCode, headers: response.headers, text: Buffer.concat(chunks).toString("utf8") }));
      });
      outgoing.on("error", reject);
      outgoing.end(body);
    });
  }
  async function login(token = ADMIN, cookie) {
    const response = await request("/office/login", { method: "POST", headers: { origin, "content-type": "application/json", ...(cookie ? { cookie } : {}) }, body: JSON.stringify({ token }) });
    assert.equal(response.status, 200);
    return response.headers["set-cookie"][0].split(";", 1)[0];
  }
  function upgrade(path, headers = {}, pending = "") {
    return new Promise((resolve, reject) => {
      const socket = net.connect(port, "127.0.0.1");
      socket.setTimeout(3000, () => socket.destroy(new Error("upgrade timeout")));
      socket.on("error", reject);
      socket.once("connect", () => socket.write(`GET ${path} HTTP/1.1\r\nHost: office.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n${Object.entries(headers).map(([key, value]) => `${key}: ${value}\r\n`).join("")}\r\n${pending}`));
      let text = "";
      const collect = (chunk) => {
        text += chunk.toString("utf8");
        if (text.includes("\r\n\r\n")) { socket.off("data", collect); socket.setTimeout(0); resolve({ status: Number(text.split(" ")[1]), socket, text }); }
      };
      socket.on("data", collect);
    });
  }
  return { request, login, upgrade, seen, events, gateway };
}

for (const path of ["//evil.test/a", "http://evil.test", "/a/../b", "/a/./b", "/a//b", "/%2e%2e/b", "/a%2fb", "/a%5cb", "/a%252fb", "/a%3fb", "/a%23b", "/%zz", "/a\\b", "/a\nb"]) {
  test(`reject ambiguous path ${JSON.stringify(path)}`, () => assert.throws(() => canonicalPath(path)));
}

test("configuration rejects unsafe origins and malformed grants", () => {
  const invalid = [
    { publicOrigin: "http://office.example" },
    { upstream: "https://remote.example" },
    { upstream: "http://user:secret@127.0.0.1:3000" },
    { sessionSeconds: 0 },
    { rules: [{ effect: "allow", roles: ["admin"], methods: ["CONNECT"], transport: "http", path: "/*" }] },
    { rules: [{ effect: "allow", roles: ["admin"], methods: ["GET"], transport: "websocket", path: "/a*b" }] },
    { users: [{ id: "x", roles: ["reader"], tokenSha256: "plaintext", expiresAt: "2099-01-01" }] },
  ];
  for (const value of invalid) assert.throws(() => validateConfig({ ...configuration(), ...value }));
});

test("deny overrides an allow even when query parameters are appended", () => {
  const config = validateConfig(configuration());
  const user = config.users.get("roman");
  assert.equal(authorize(config, user, "GET", "/secrets/key?ignore=true", "http"), false);
  assert.equal(authorize(config, user, "GET", "/internal/ws", "websocket"), false);
});

test("anonymous and spoofed identities never reach bb", async (t) => {
  const f = await fixture(t);
  for (const headers of [{}, { "x-bb-office-subject": "roman", "x-bb-office-roles": "admin" }, { "x-auth-request-user": "roman" }]) {
    assert.equal((await f.request("/api/v1/threads", { headers })).status, 401);
  }
  assert.equal(f.seen.length, 0);
});

test("resource paths, methods and query selectors are enforced", async (t) => {
  const f = await fixture(t);
  assert.equal((await f.request("/api/v1/threads/owned", { token: READER })).status, 200);
  for (const path of ["/api/v1/threads/other", "/api/v1/threads", "/api/v1/threads/owned?extra=1", "/api/v1/plugins/x/rpc/read", "/api/v1/system/config", "/new-endpoint"]) assert.equal((await f.request(path, { token: READER })).status, 403);
  assert.equal((await f.request("/api/v1/threads/owned", { token: READER, method: "DELETE" })).status, 403);
  assert.equal((await f.request("/api/v1/files/content?fileId=owned", { token: READER })).status, 200);
  for (const query of ["fileId=other", "fileId=owned&fileId=other", "fileId=owned&hostId=other", ""]) assert.equal((await f.request(`/api/v1/files/content?${query}`, { token: READER })).status, 403);
  assert.equal(f.seen.length, 2);
});

test("encoded route bypasses fail before upstream", async (t) => {
  const f = await fixture(t);
  for (const path of ["/api/v1/threads/%2e%2e/system", "/api%2fv1/threads/owned", "/api%252fv1/threads/owned", "/api//v1/threads/owned"]) assert.equal((await f.request(path, { token: ADMIN })).status, 400);
  assert.equal(f.seen.length, 0);
});

test("invalid host and foreign browser origin are denied even for administrators", async (t) => {
  const f = await fixture(t);
  assert.equal((await f.request("/api", { token: ADMIN, headers: { host: "evil.test" } })).status, 403);
  assert.equal((await f.request("/api", { token: ADMIN, headers: { origin: "https://evil.test" } })).status, 403);
  assert.equal((await f.request("/api", { token: ADMIN, headers: { "sec-fetch-site": "cross-site" } })).status, 403);
  assert.equal(f.seen.length, 0);
});

test("login creates an HttpOnly Secure strict cookie and accepts it on reads", async (t) => {
  const f = await fixture(t);
  const page = await f.request("/office/login");
  assert.equal(page.status, 200);
  assert.match(page.headers["content-security-policy"], /nonce-/u);
  const response = await f.request("/office/login", { method: "POST", headers: { origin, "content-type": "application/json" }, body: JSON.stringify({ token: ADMIN }) });
  const setCookie = response.headers["set-cookie"][0];
  for (const attribute of ["__Host-", "HttpOnly", "Secure", "SameSite=Strict"]) assert.ok(setCookie.includes(attribute));
  const cookie = setCookie.split(";", 1)[0];
  const me = await f.request("/office/me", { headers: { cookie } });
  assert.equal(JSON.parse(me.text).subject, "roman");
  assert.equal(me.headers["cache-control"], "no-store");
  assert.equal(f.seen.length, 0);
});

test("login requires JSON, same origin, a valid token and bounded input", async (t) => {
  const f = await fixture(t);
  const body = JSON.stringify({ token: ADMIN });
  assert.equal((await f.request("/office/login", { method: "POST", body, headers: { "content-type": "application/json" } })).status, 403);
  assert.equal((await f.request("/office/login", { method: "POST", body, headers: { origin, "content-type": "text/plain" } })).status, 415);
  assert.equal((await f.request("/office/login", { method: "POST", body: "{}", headers: { origin, "content-type": "application/json" } })).status, 401);
  assert.equal((await f.request("/office/login", { method: "POST", body: "x".repeat(5000), headers: { origin, "content-type": "application/json" } })).status, 413);
  assert.equal((await f.request(`/api?token=${ADMIN}`)).status, 401);
});

test("cookie mutations require Origin and invalid bearer cannot fall back to cookie", async (t) => {
  const f = await fixture(t);
  const cookie = await f.login();
  assert.equal((await f.request("/api", { method: "POST", headers: { cookie } })).status, 403);
  assert.equal((await f.request("/api", { method: "POST", headers: { cookie, origin }, body: "payload" })).status, 200);
  assert.equal((await f.request("/api", { headers: { cookie, authorization: "Bearer invalid" } })).status, 401);
  assert.equal(f.seen.length, 1);
});

test("logout revokes its session", async (t) => {
  const f = await fixture(t);
  const cookie = await f.login();
  assert.equal((await f.request("/office/logout", { method: "POST", headers: { cookie, origin } })).status, 200);
  assert.equal((await f.request("/office/me", { headers: { cookie } })).status, 401);
});

test("tokens, session cookies and spoofed proxy identity never reach upstream", async (t) => {
  const f = await fixture(t);
  const cookie = await f.login();
  const response = await f.request("/api", { headers: { cookie: `${cookie}; other=ok`, origin, "x-bb-office-subject": "forged", "x-forwarded-for": "evil", "x-bb-auth-proxy-key": "forged" }, token: ADMIN });
  assert.equal(response.status, 200);
  const headers = f.seen[0].headers;
  assert.equal(headers.authorization, undefined);
  assert.equal(headers["x-bb-auth-proxy-key"], undefined);
  assert.equal(headers["x-forwarded-for"], undefined);
  assert.equal(headers["x-bb-office-subject"], "roman");
  assert.equal(headers.cookie, "other=ok");
  assert.notEqual(headers.origin, origin);
  const logs = JSON.stringify(f.events);
  assert.ok(!logs.includes(ADMIN) && !logs.includes(cookie));
});

test("SSO assertions require both a trusted peer and shared-secret proof", async (t) => {
  const f = await fixture(t, (config) => { config.authProxy = { secretSha256: tokenDigest(PROXY_KEY), trustedPeers: ["127.0.0.1"] }; });
  const headers = { "x-bb-auth-proxy-key": PROXY_KEY, "x-auth-request-user": "sales" };
  assert.equal((await f.request("/office/me", { headers })).status, 200);
  assert.equal((await f.request("/api/v1/threads/other", { headers })).status, 403);
  assert.equal((await f.request("/office/me", { headers: { ...headers, "x-auth-request-user": "unknown" } })).status, 401);
  assert.equal((await f.request("/office/me", { headers: { ...headers, "x-bb-auth-proxy-key": "x".repeat(43) } })).status, 401);
});

test("untrusted SSO network peer is rejected despite knowing the secret", async (t) => {
  const f = await fixture(t, (config) => { config.authProxy = { secretSha256: tokenDigest(PROXY_KEY), trustedPeers: ["192.0.2.1"] }; });
  assert.equal((await f.request("/office/me", { headers: { "x-bb-auth-proxy-key": PROXY_KEY, "x-auth-request-user": "roman" } })).status, 401);
});

test("expired principal cannot authenticate", async (t) => {
  const f = await fixture(t, (config) => { config.users[0].expiresAt = "2020-01-01T00:00:00Z"; });
  assert.equal((await f.request("/office/me", { token: ADMIN })).status, 401);
});

test("WebSocket authorization is independent of HTTP GET grants", async (t) => {
  const f = await fixture(t);
  for (const [headers, expected] of [[{}, 401], [{ authorization: `Bearer ${READER}` }, 403]]) {
    const result = await f.upgrade("/api/v1/threads/owned", headers);
    assert.equal(result.status, expected);
    result.socket.destroy();
  }
  assert.equal(f.seen.length, 0);
});

test("WebSocket upgrade forwards bytes and strips bearer credentials", async (t) => {
  const f = await fixture(t);
  const result = await f.upgrade("/ws", { authorization: `Bearer ${ADMIN}` });
  assert.equal(result.status, 101);
  const echoed = new Promise((resolve) => result.socket.once("data", (data) => resolve(data.toString())));
  result.socket.write("opaque-frame");
  assert.equal(await echoed, "opaque-frame");
  assert.equal(f.seen[0].headers.authorization, undefined);
  result.socket.destroy();
});

test("browser WebSockets need a same-origin session and close on logout", async (t) => {
  const f = await fixture(t);
  const cookie = await f.login();
  const denied = await f.upgrade("/ws", { cookie });
  assert.equal(denied.status, 403);
  denied.socket.destroy();
  const allowed = await f.upgrade("/ws", { cookie, origin });
  assert.equal(allowed.status, 101);
  const closed = new Promise((resolve) => allowed.socket.once("close", resolve));
  await f.request("/office/logout", { method: "POST", headers: { cookie, origin } });
  await closed;
});

test("long-lived sockets close at their authorization lease expiry", async (t) => {
  const f = await fixture(t, (config) => { config.sessionSeconds = 1; });
  const result = await f.upgrade("/ws", { authorization: `Bearer ${ADMIN}` });
  assert.equal(result.status, 101);
  const closed = new Promise((resolve) => result.socket.once("close", resolve));
  await closed;
});

test("SSE remains streaming and is not cached", async (t) => {
  const f = await fixture(t);
  const response = await f.request("/sse", { token: ADMIN });
  assert.equal(response.text, "data: first\n\ndata: second\n\n");
  assert.equal(response.headers["content-type"], "text/event-stream");
  assert.equal(response.headers["cache-control"], "private, no-store");
});

test("plugin shutdown closes existing WebSockets", async (t) => {
  const f = await fixture(t);
  const result = await f.upgrade("/ws", { authorization: `Bearer ${ADMIN}` });
  const closed = new Promise((resolve) => result.socket.once("close", resolve));
  await f.gateway.close();
  await closed;
});

test("unknown policy fields fail closed instead of silently disabling a condition", () => {
  assert.throws(() => validateConfig({ ...configuration(), enableAnonymous: true }));
  const config = configuration();
  config.rules[0].resource = "secret";
  assert.throws(() => validateConfig(config));
});

test("browser root redirects to login rather than exposing the app anonymously", async (t) => {
  const f = await fixture(t);
  const result = await f.request("/", { headers: { accept: "text/html" } });
  assert.equal(result.status, 303);
  assert.equal(result.headers.location, "/office/login");
  assert.equal(f.seen.length, 0);
});


test("mobile browser deep links survive login without exposing the target", async (t) => {
  const f = await fixture(t);
  const target = "/threads/thr_123?panel=files";
  const redirected = await f.request(target, { headers: { accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" } });
  assert.equal(redirected.status, 303);
  const loginUrl = new URL(redirected.headers.location, origin);
  assert.equal(loginUrl.pathname, "/office/login");
  assert.equal(loginUrl.searchParams.get("next"), target);
  const page = await f.request(`${loginUrl.pathname}${loginUrl.search}`);
  assert.equal(page.status, 200);
  assert.match(page.text, /method="post"/u);
  assert.ok(page.text.includes(JSON.stringify(target)));
  assert.equal(page.headers["referrer-policy"], "no-referrer");
  assert.equal(f.seen.length, 0);
  const cookie = await f.login();
  assert.equal((await f.request(target, { headers: { cookie } })).status, 200);
  assert.equal(f.seen[0].url, target);
});

test("external notification navigations reach only the public login page", async (t) => {
  const f = await fixture(t);
  const cookie = await f.login();
  const headers = { accept: "text/html", "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", cookie };
  const redirected = await f.request("/threads/shared", { headers });
  assert.equal(redirected.status, 303);
  assert.equal((await f.request(redirected.headers.location, { headers })).status, 200);
  assert.equal(f.seen.length, 0);
  for (const override of [{ "sec-fetch-mode": "cors" }, { "sec-fetch-dest": "iframe" }]) {
    assert.equal((await f.request("/threads/shared", { headers: { ...headers, ...override } })).status, 403);
  }
});

test("login return targets reject other origins, API paths and ambiguous input", async (t) => {
  const f = await fixture(t);
  const targets = ["https://evil.test", "//evil.test", "/\\evil.test", "/a/../b", "/%2f/evil.test", "/%252f/evil.test", "/api/v1/threads", "/internal/ws", "/ws", "/office/logout", "/health", "/install.sh", "/threads/a#fragment", "/threads/a\nheader"];
  for (const target of targets) {
    const response = await f.request(`/office/login?next=${encodeURIComponent(target)}`);
    assert.equal(response.status, 400, target);
  }
  for (const query of ["next=/&next=/threads/a", "next=/&other=x", "other=x"]) {
    assert.equal((await f.request(`/office/login?${query}`)).status, 400, query);
  }
  assert.equal(f.seen.length, 0);
});

test("login return target cannot break out of its inline script", async (t) => {
  const f = await fixture(t);
  const target = "/threads/test?value=</script><script>alert(1)</script>";
  const response = await f.request(`/office/login?next=${encodeURIComponent(target)}`);
  assert.equal(response.status, 200);
  assert.equal((response.text.match(/<script[ >]/gu) ?? []).length, 1);
  assert.ok(!response.text.includes("</script><script>"));
  assert.match(response.text, /\\u003c\/script>/u);
});

test("API, native probes and bad bearer credentials never become HTML redirects", async (t) => {
  const f = await fixture(t);
  for (const path of ["/api/v1/threads", "/api/v1/system/config", "/health", "/ws"]) {
    const response = await f.request(path, { headers: { accept: "text/html" } });
    assert.equal(response.status, 401, path);
    assert.equal(response.headers.location, undefined);
    assert.match(response.headers["content-type"], /application\/json/u);
    assert.equal(response.headers["www-authenticate"], 'Bearer realm="bb-office"');
  }
  const bad = await f.request("/threads/a", { headers: { accept: "text/html", authorization: "Bearer invalid" } });
  assert.equal(bad.status, 401);
  assert.equal(bad.headers.location, undefined);
  assert.equal(f.seen.length, 0);
});

test("successful login does not weaken the destination's role policy", async (t) => {
  const f = await fixture(t);
  const cookie = await f.login(READER);
  assert.equal((await f.request("/threads/other", { headers: { cookie, accept: "text/html" } })).status, 403);
  assert.equal((await f.request("/api/v1/threads/other", { headers: { cookie } })).status, 403);
  assert.equal(f.seen.length, 0);
});

test("a failed audit sink prevents issuing a login cookie", async (t) => {
  const f = await fixture(t, () => {}, { audit: () => { throw new Error("audit disk is unavailable"); } });
  const response = await f.request("/office/login", { method: "POST", headers: { origin, "content-type": "application/json" }, body: JSON.stringify({ token: ADMIN }) });
  assert.equal(response.status, 503);
  assert.equal(JSON.parse(response.text).code, "audit_unavailable");
  assert.equal(response.headers["set-cookie"], undefined);
  assert.equal(f.seen.length, 0);
});

test("switching identity revokes the old browser session and its socket only", async (t) => {
  const f = await fixture(t);
  const oldCookie = await f.login();
  const otherDevice = await f.login();
  const opened = await f.upgrade("/ws", { cookie: oldCookie, origin });
  assert.equal(opened.status, 101);
  let closed = false;
  opened.socket.once("close", () => { closed = true; });
  const newCookie = await f.login(READER, oldCookie);
  assert.notEqual(oldCookie, newCookie);
  assert.equal((await f.request("/office/me", { headers: { cookie: oldCookie } })).status, 401);
  assert.equal(JSON.parse((await f.request("/office/me", { headers: { cookie: newCookie } })).text).subject, "sales");
  assert.equal(JSON.parse((await f.request("/office/me", { headers: { cookie: otherDevice } })).text).subject, "roman");
  for (let i = 0; i < 20 && !closed; i++) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(closed, true);
});

test("failed replacement login keeps the existing session", async (t) => {
  let failAudit = false;
  const f = await fixture(t, () => {}, { audit: (event) => { if (failAudit && event.code === "login") throw new Error("offline"); } });
  const cookie = await f.login();
  failAudit = true;
  const rejected = await f.request("/office/login", { method: "POST", headers: { cookie, origin, "content-type": "application/json" }, body: JSON.stringify({ token: READER }) });
  assert.equal(rejected.status, 503);
  assert.equal(rejected.headers["set-cookie"], undefined);
  failAudit = false;
  assert.equal(JSON.parse((await f.request("/office/me", { headers: { cookie } })).text).subject, "roman");
});

test("logout revokes access even when recording the audit fails", async (t) => {
  let failAudit = false;
  const f = await fixture(t, () => {}, { audit: (event) => { if (failAudit && event.code === "logout") throw new Error("offline"); } });
  const cookie = await f.login();
  failAudit = true;
  const response = await f.request("/office/logout", { method: "POST", headers: { cookie, origin } });
  assert.equal(response.status, 503);
  assert.equal((await f.request("/office/me", { headers: { cookie } })).status, 401);
});

for (const status of [401, 403]) {
  test(`upstream WebSocket ${status} remains visible to reconnecting clients`, async (t) => {
    const f = await fixture(t);
    const rejected = await f.upgrade(`/ws/reject/${status}`, { authorization: `Bearer ${ADMIN}` });
    assert.equal(rejected.status, status);
    rejected.socket.destroy();
  });
}

for (const rejects of [false, true]) {
  test(`async audit callback fails closed (rejects=${rejects})`, async (t) => {
    const f = await fixture(t, () => {}, { audit: async () => { if (rejects) throw new Error("sink unavailable"); } });
    const response = await f.request("/office/login", { method: "POST", headers: { origin, "content-type": "application/json" }, body: JSON.stringify({ token: ADMIN }) });
    assert.equal(response.status, 503);
    assert.equal(response.headers["set-cookie"], undefined);
    assert.equal((await f.request("/api/v1/threads", { token: ADMIN })).status, 503);
    assert.equal(f.seen.length, 0);
    await new Promise((resolve) => setImmediate(resolve));
  });
}

test("audit records do not retain invitation tokens, arbitrary paths or query secrets", async (t) => {
  const f = await fixture(t);
  for (const path of [`/thread-invites/${ADMIN}`, `/api/v1/thread-invites/${ADMIN}/accept`, `/anything/${ADMIN}?token=${ADMIN}`, `/api/v1/threads/private-${ADMIN}`]) {
    assert.equal((await f.request(path, { token: ADMIN })).status, 200);
  }
  assert.equal(f.events.length, 4);
  assert.deepEqual(f.events.map((event) => event.path), ["/thread-invites/*", "/api/v1/thread-invites/*", "/other", "/api/v1/threads/*"]);
  assert.ok(!JSON.stringify(f.events).includes(ADMIN));
});

test("rejected malformed paths are not copied into audit", async (t) => {
  const f = await fixture(t);
  assert.equal((await f.request(`/a%2fb/${ADMIN}`, { token: ADMIN })).status, 400);
  assert.equal(f.events[0].path, "/invalid-path");
  assert.ok(!JSON.stringify(f.events).includes(ADMIN));
});

test("duplicate security headers are rejected before WebSocket forwarding", async (t) => {
  const f = await fixture(t);
  for (const headers of [
    { Authorization: `Bearer ${ADMIN}`, authorization: `Bearer ${ADMIN}` },
    { Cookie: "one=1", cookie: "two=2", authorization: `Bearer ${ADMIN}` },
    { Origin: origin, origin, authorization: `Bearer ${ADMIN}` },
  ]) {
    const result = await f.upgrade("/ws", headers);
    assert.equal(result.status, 400);
    result.socket.destroy();
  }
  assert.equal(f.seen.length, 0);
});

test("HEAD is not silently granted by a GET policy", async (t) => {
  const f = await fixture(t);
  assert.equal((await f.request("/api/v1/threads/owned", { token: READER, method: "HEAD" })).status, 403);
  assert.equal(f.seen.length, 0);
});

test("session capacity evicts only the oldest session of the same user", async (t) => {
  const f = await fixture(t);
  const other = await f.login(READER);
  const first = await f.login();
  const socket = await f.upgrade("/ws", { cookie: first, origin });
  const closed = new Promise((resolve) => socket.socket.once("close", resolve));
  const latest = [];
  for (let index = 0; index < 8; index++) latest.push(await f.login());
  await closed;
  assert.equal((await f.request("/office/me", { headers: { cookie: first } })).status, 401);
  for (const cookie of [...latest, other]) assert.equal((await f.request("/office/me", { headers: { cookie } })).status, 200);
});

test("native client headers do not bypass authentication or CSRF", async (t) => {
  const f = await fixture(t);
  const headers = { "x-bb-app-surface": "mobile", "user-agent": "bb iOS" };
  for (const path of ["/health", "/api/v1/system/config", "/api/v1/threads"]) assert.equal((await f.request(path, { headers })).status, 401);
  const cookie = await f.login();
  assert.equal((await f.request("/api/v1/threads", { method: "POST", headers: { ...headers, cookie } })).status, 403);
  assert.equal(f.seen.length, 0);
});
