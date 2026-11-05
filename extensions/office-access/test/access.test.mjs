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

async function fixture(t, edit = () => {}) {
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
    const accept = createHash("sha1").update(`${request.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    if (head.length) socket.write(head);
    socket.on("data", (chunk) => socket.write(chunk));
    socket.on("error", () => {});
  });
  const backendPort = await listen(backend);
  const raw = configuration(`http://127.0.0.1:${backendPort}`);
  edit(raw);
  const gateway = createAccessGateway(raw, { audit: (event) => events.push(event) });
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
  async function login(token = ADMIN) {
    const response = await request("/office/login", { method: "POST", headers: { origin, "content-type": "application/json" }, body: JSON.stringify({ token }) });
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
