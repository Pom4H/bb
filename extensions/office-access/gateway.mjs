import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { canonicalPath, tokenDigest, validateConfig } from "./policy.mjs";
import { authorize } from "./policy.mjs";
import { auditMethod, auditPath, writeAudit } from "./audit.mjs";
import { isDocumentNavigation, isPagePath, loginDestination, loginLocation, renderLogin } from "./login.mjs";

const HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"]);
const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);

class AccessError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function fail(status, code) {
  throw new AccessError(status, code);
}

function equalDigest(left, right) {
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function cookieValue(header, name) {
  const values = String(header ?? "").split(";").map((part) => part.trim()).filter((part) => part.startsWith(`${name}=`));
  if (values.length > 1) fail(400, "ambiguous_cookie");
  return values[0]?.slice(name.length + 1);
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    if (request.headers["content-type"]?.split(";", 1)[0] !== "application/json") return reject(new AccessError(415, "json_required"));
    let length = 0;
    const chunks = [];
    request.on("data", (chunk) => {
      length += chunk.length;
      if (length > 4096) {
        chunks.length = 0;
        reject(new AccessError(413, "body_too_large"));
      } else chunks.push(chunk);
    });
    request.once("error", reject);
    request.once("aborted", () => reject(new AccessError(400, "request_aborted")));
    request.once("end", () => {
      if (length > 4096) return;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { reject(new AccessError(400, "invalid_json")); }
    });
  });
}

function responseHeaders(headers, cookieName) {
  const blocked = new Set([...HOP, ...String(headers.connection ?? "").toLowerCase().split(",").map((part) => part.trim())]);
  const result = {};
  for (const [key, value] of Object.entries(headers)) {
    if (blocked.has(key) || key.startsWith("access-control-") || value === undefined) continue;
    if (key === "set-cookie") result[key] = (Array.isArray(value) ? value : [value]).filter((cookie) => !cookie.trimStart().startsWith(`${cookieName}=`));
    else result[key] = value;
  }
  result["cache-control"] = "private, no-store";
  result["x-content-type-options"] = "nosniff";
  return result;
}

export function createAccessGateway(rawConfig, { audit = () => {} } = {}) {
  const config = validateConfig(rawConfig);
  const upstream = new URL(config.upstream);
  const publicUrl = new URL(config.publicOrigin);
  const secure = publicUrl.protocol === "https:";
  const cookieName = secure ? "__Host-bb_office_session" : "bb_office_local_session";
  const sessions = new Map();
  const connections = new Set();
  const leases = new Set();
  const transport = upstream.protocol === "https:" ? https : http;
  const agent = new transport.Agent({ keepAlive: true, maxSockets: 64 });
  let closing = false;

  function log(request, status, code, auth, kind = "http") {
    try { writeAudit(audit, { time: new Date().toISOString(), event: "office.access", requestId: randomUUID(), subject: auth?.user.id ?? null, method: auditMethod(request.method), path: auditPath(request.url), transport: kind, status, code }); }
    catch { throw new AccessError(503, "audit_unavailable"); }
  }

  function checkRequest(request) {
    const unique = new Set(["host", "authorization", "cookie", "origin", "x-bb-auth-proxy-key", "x-auth-request-user"]);
    const seen = new Set();
    for (let i = 0; i < request.rawHeaders.length; i += 2) {
      const key = request.rawHeaders[i].toLowerCase();
      if (unique.has(key) && seen.has(key)) fail(400, "ambiguous_headers");
      seen.add(key);
    }
    if (closing) fail(503, "shutting_down");
    if (request.headers.host?.toLowerCase() !== publicUrl.host.toLowerCase()) fail(403, "forbidden_host");
    if (request.headers.origin !== undefined && request.headers.origin !== config.publicOrigin) fail(403, "forbidden_origin");
    let path;
    try { path = canonicalPath(request.url); }
    catch { fail(400, "invalid_path"); }
    if (request.headers["sec-fetch-site"] === "cross-site" && !(isDocumentNavigation(request) && (isPagePath(path) || path === "/office/login"))) fail(403, "cross_site_request");
    return path;
  }

  function userForToken(token) {
    if (typeof token !== "string" || !/^[A-Za-z0-9_-]{43,128}$/u.test(token)) fail(401, "unauthorized");
    const user = config.tokens.get(tokenDigest(token));
    if (!user || user.expiresAt <= Date.now()) fail(401, "unauthorized");
    return user;
  }

  function authenticate(request, websocket = false) {
    let auth;
    if (request.headers.authorization !== undefined) {
      const match = /^Bearer ([A-Za-z0-9_-]{43,128})$/u.exec(request.headers.authorization);
      if (!match) fail(401, "unauthorized");
      const user = userForToken(match[1]);
      auth = { user, expiresAt: Math.min(user.expiresAt, Date.now() + config.sessionSeconds * 1000), session: null, kind: "bearer" };
    } else if (request.headers["x-bb-auth-proxy-key"] !== undefined || request.headers["x-auth-request-user"] !== undefined) {
      const proxy = config.authProxy;
      const key = request.headers["x-bb-auth-proxy-key"];
      if (!proxy || !proxy.trustedPeers.includes(request.socket.remoteAddress) || typeof key !== "string" || key.length < 43 || !equalDigest(tokenDigest(key), proxy.secretSha256)) fail(401, "unauthorized");
      const user = config.users.get(request.headers["x-auth-request-user"]);
      if (!user || user.expiresAt <= Date.now()) fail(401, "unauthorized");
      auth = { user, expiresAt: Math.min(user.expiresAt, Date.now() + config.sessionSeconds * 1000), session: null, kind: "proxy" };
    } else {
      const cookie = cookieValue(request.headers.cookie, cookieName);
      const digest = typeof cookie === "string" ? tokenDigest(cookie) : "";
      const session = sessions.get(digest);
      const user = session && config.users.get(session.userId);
      if (!session || !user || Math.min(session.expiresAt, user.expiresAt) <= Date.now()) {
        sessions.delete(digest);
        fail(401, "unauthorized");
      }
      auth = { user, expiresAt: Math.min(session.expiresAt, user.expiresAt), session: digest, kind: "cookie" };
    }
    if (auth.kind !== "bearer" && (websocket || !SAFE.has(request.method)) && request.headers.origin !== config.publicOrigin) fail(403, "origin_required");
    return auth;
  }

  function cookie(value, seconds) {
    return `${cookieName}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${seconds}${secure ? "; Secure" : ""}`;
  }

  function json(response, status, value, headers = {}) {
    response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", ...headers });
    response.end(JSON.stringify(value));
  }

  function revokeSession(key) {
    if (!key) return;
    sessions.delete(key);
    for (const active of [...leases]) if (active.session === key) active.destroy();
  }

  function redirectToLogin(request, response) {
    let location;
    try { location = loginLocation(request.url); }
    catch { fail(400, "invalid_return_target"); }
    response.writeHead(303, { location, "cache-control": "no-store", "referrer-policy": "no-referrer" });
    response.end();
  }

  function lease(auth, destroy) {
    const record = { session: auth.session, destroy, timer: setTimeout(destroy, Math.max(1, auth.expiresAt - Date.now())) };
    record.timer.unref();
    leases.add(record);
    return () => { clearTimeout(record.timer); leases.delete(record); };
  }

  function proxyHeaders(request, auth, websocket) {
    const blocked = new Set([...HOP, ...String(request.headers.connection ?? "").toLowerCase().split(",").map((part) => part.trim()), "authorization", "forwarded", "referer", "x-http-method-override", "x-method-override", "x-http-method"]);
    const headers = {};
    for (const [key, value] of Object.entries(request.headers)) {
      if (value === undefined || blocked.has(key) || key.startsWith("x-forwarded-") || key.startsWith("x-original-") || key.startsWith("x-auth-request-") || key.startsWith("x-bb-office-") || key.startsWith("x-bb-auth-proxy-") || key.startsWith("sec-fetch-")) continue;
      headers[key] = value;
    }
    headers.host = upstream.host;
    if (request.headers.origin) headers.origin = upstream.origin;
    headers["x-bb-office-subject"] = auth.user.id;
    headers["x-bb-office-roles"] = auth.user.roles.join(",");
    const remainingCookies = String(request.headers.cookie ?? "").split(";").map((part) => part.trim()).filter((part) => part && !part.startsWith(`${cookieName}=`)).join("; ");
    if (remainingCookies) headers.cookie = remainingCookies;
    else delete headers.cookie;
    if (websocket) { headers.connection = "Upgrade"; headers.upgrade = "websocket"; }
    return headers;
  }

  function proxy(request, response, socket, head, auth) {
    const websocket = socket !== null;
    const outbound = transport.request({ hostname: upstream.hostname.replace(/^\[|\]$/gu, ""), port: upstream.port || (upstream.protocol === "https:" ? 443 : 80), method: request.method, path: request.url, headers: proxyHeaders(request, auth, websocket), agent });
    let upstreamSocket;
    let upgraded = false;
    const destroy = () => { outbound.destroy(); upstreamSocket?.destroy(); socket?.destroy(); response?.destroy(); };
    const release = lease(auth, destroy);
    const wait = setTimeout(() => outbound.destroy(new Error("upstream_timeout")), 120000);
    wait.unref();
    const downstream = socket ?? response;
    downstream.once("close", () => { clearTimeout(wait); release(); outbound.destroy(); upstreamSocket?.destroy(); });
    request.once("aborted", destroy);
    outbound.once("error", () => {
      clearTimeout(wait);
      release();
      if (websocket) {
        if (!upgraded && !socket.destroyed) socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        else socket.destroy();
      } else if (!response.headersSent) json(response, 502, { code: "upstream_unavailable" });
      else response.destroy();
    });
    outbound.once("response", (incoming) => {
      clearTimeout(wait);
      if (websocket) {
        const status = [401, 403].includes(incoming.statusCode) ? incoming.statusCode : 502;
        incoming.resume();
        socket.end(`HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n`);
        return;
      }
      response.writeHead(incoming.statusCode ?? 502, responseHeaders(incoming.headers, cookieName));
      incoming.once("error", destroy);
      incoming.once("aborted", destroy);
      incoming.pipe(response);
    });
    outbound.once("upgrade", (incoming, connected, pending) => {
      clearTimeout(wait);
      if (!websocket || auth.expiresAt <= Date.now() || closing || socket.destroyed) { connected.destroy(); destroy(); return; }
      upstreamSocket = connected;
      upgraded = true;
      const headers = responseHeaders(incoming.headers, cookieName);
      headers.connection = "Upgrade";
      headers.upgrade = "websocket";
      const lines = ["HTTP/1.1 101 Switching Protocols"];
      for (const [key, value] of Object.entries(headers)) for (const item of Array.isArray(value) ? value : [value]) lines.push(`${key}: ${item}`);
      socket.write(`${lines.join("\r\n")}\r\n\r\n`);
      if (pending.length) socket.write(pending);
      if (head.length) connected.write(head);
      socket.on("error", destroy);
      connected.on("error", destroy);
      connected.once("close", () => { release(); socket.destroy(); });
      connected.pipe(socket);
      socket.pipe(connected);
    });
    if (websocket) outbound.end();
    else request.pipe(outbound);
  }

  const server = http.createServer({ maxHeaderSize: 16384, headersTimeout: 15000, requestTimeout: 300000 }, async (request, response) => {
    let auth;
    try {
      const path = checkRequest(request);
      if (path === "/office/login" && request.method === "GET") {
        let next;
        try { next = loginDestination(request.url); }
        catch { fail(400, "invalid_return_target"); }
        const nonce = randomBytes(24).toString("base64url");
        response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer", "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, "x-content-type-options": "nosniff" });
        response.end(renderLogin(nonce, next));
        return;
      }
      if (request.headers["sec-fetch-site"] === "cross-site" && isDocumentNavigation(request) && isPagePath(path)) {
        log(request, 303, "login_required", null);
        redirectToLogin(request, response);
        return;
      }
      if (path === "/office/login" && request.method === "POST" && !request.url.includes("?")) {
        if (request.headers.origin !== config.publicOrigin) fail(403, "origin_required");
        const body = await readJson(request);
        const user = userForToken(body?.token);
        const previousCookie = cookieValue(request.headers.cookie, cookieName);
        const previousSession = previousCookie ? tokenDigest(previousCookie) : null;
        const now = Date.now();
        const expired = [...sessions.entries()].filter(([, session]) => session.expiresAt <= now).map(([key]) => key);
        const retained = [...sessions.entries()].filter(([key, session]) => key !== previousSession && session.expiresAt > now);
        const owned = retained.filter(([, session]) => session.userId === user.id);
        const evicted = owned.slice(0, Math.max(0, owned.length - 7)).map(([key]) => key);
        if (retained.length - evicted.length >= 10000) fail(503, "session_capacity");
        const token = randomBytes(32).toString("base64url");
        const expiresAt = Math.min(user.expiresAt, now + config.sessionSeconds * 1000);
        auth = { user };
        log(request, 200, "login", auth);
        for (const key of [...expired, ...evicted, previousSession]) revokeSession(key);
        sessions.set(tokenDigest(token), { userId: user.id, expiresAt });
        json(response, 200, { ok: true }, { "set-cookie": cookie(token, Math.max(1, Math.floor((expiresAt - now) / 1000))) });
        return;
      }
      auth = authenticate(request);
      if (path === "/office/me" && request.method === "GET" && !request.url.includes("?")) {
        json(response, 200, { subject: auth.user.id, roles: auth.user.roles, expiresAt: new Date(auth.expiresAt).toISOString() });
        return;
      }
      if (path === "/office/logout" && request.method === "POST" && !request.url.includes("?")) {
        if (request.headers.origin !== config.publicOrigin) fail(403, "origin_required");
        revokeSession(auth.session);
        log(request, 200, "logout", auth);
        json(response, 200, { ok: true }, { "set-cookie": cookie("", 0) });
        return;
      }
      if (path === "/office" || path.startsWith("/office/")) fail(404, "not_found");
      if (!authorize(config, auth.user, request.method, request.url, "http")) fail(403, "forbidden");
      log(request, 200, "allowed", auth);
      proxy(request, response, null, null, auth);
    } catch (error) {
      const status = error instanceof AccessError ? error.status : 500;
      const code = error instanceof AccessError ? error.code : "access_gateway_error";
      try { log(request, status, code, auth); } catch {}
      if (status === 401 && isDocumentNavigation(request) && isPagePath(canonicalPath(request.url))) {
        try { redirectToLogin(request, response); }
        catch { json(response, 400, { code: "invalid_return_target" }); }
        return;
      }
      if (!response.headersSent) json(response, status, { code }, status === 401 ? { "www-authenticate": 'Bearer realm="bb-office"' } : {});
      else response.destroy();
      request.resume();
    }
  });

  server.once("listening", () => { if (closing) server.close(); });
  server.on("connection", (socket) => { connections.add(socket); socket.on("error", () => {}); socket.once("close", () => connections.delete(socket)); });
  server.on("upgrade", (request, socket, head) => {
    let auth;
    try {
      const path = checkRequest(request);
      if (request.headers.upgrade?.toLowerCase() !== "websocket" || request.method !== "GET") fail(400, "invalid_upgrade");
      auth = authenticate(request, true);
      if (path === "/office" || path.startsWith("/office/") || !authorize(config, auth.user, request.method, request.url, "websocket")) fail(403, "forbidden");
      log(request, 101, "allowed", auth, "websocket");
      proxy(request, null, socket, head, auth);
    } catch (error) {
      const status = error instanceof AccessError ? error.status : 500;
      try { log(request, status, error instanceof AccessError ? error.code : "access_gateway_error", auth, "websocket"); } catch {}
      socket.end(`HTTP/1.1 ${status} Rejected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    }
  });
  server.on("connect", (_request, socket) => socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"));
  server.on("clientError", (_error, socket) => { if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); });

  return {
    server,
    config,
    async close() {
      if (closing) return;
      closing = true;
      for (const active of [...leases]) { clearTimeout(active.timer); active.destroy(); }
      for (const socket of connections) socket.destroy();
      sessions.clear();
      agent.destroy();
      if (server.listening) await new Promise((resolve) => server.close(resolve));
    },
  };
}
