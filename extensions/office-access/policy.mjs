import { createHash } from "node:crypto";
import { isIP } from "node:net";

const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const ID = /^[a-zA-Z0-9@._+-]{1,128}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;

function requireValue(condition, message) {
  if (!condition) throw new Error(`Invalid office access configuration: ${message}`);
}

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function knownKeys(value, allowed, name) {
  requireValue(object(value) && Object.keys(value).every((key) => allowed.includes(key)), `unknown field in ${name}`);
}

function origin(value, name, loopbackOnly = false) {
  requireValue(typeof value === "string", `${name} must be an origin`);
  const url = new URL(value);
  requireValue(["http:", "https:"].includes(url.protocol) && !url.username && !url.password && url.pathname === "/" && !url.search && !url.hash, `${name} must be an HTTP(S) origin without credentials or a path`);
  const local = ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname);
  requireValue(!loopbackOnly || local, `${name} must use a loopback address`);
  requireValue(name !== "publicOrigin" || url.protocol === "https:" || local, "publicOrigin requires HTTPS outside localhost");
  return url.origin;
}

export function tokenDigest(token) {
  return createHash("sha256").update(token).digest("hex");
}

export function canonicalPath(target) {
  if (typeof target !== "string" || !target.startsWith("/") || target.startsWith("//") || target.length > 8192 || /[\x00-\x20\x7f\\#]/u.test(target)) throw new Error("Invalid request target");
  const raw = target.split("?", 1)[0];
  if (/%(?:2f|5c|00)/iu.test(raw)) throw new Error("Encoded path separator");
  const path = decodeURIComponent(raw);
  if (/[\x00-\x1f\x7f%\\?#]/u.test(path) || path.includes("//") || path.split("/").some((part) => part === "." || part === "..")) throw new Error("Ambiguous path");
  return path;
}

export function validateConfig(input) {
  requireValue(object(input) && input.version === 1, "version must be 1");
  knownKeys(input, ["version", "publicOrigin", "upstream", "listen", "sessionSeconds", "users", "rules", "authProxy"], "policy");
  const publicOrigin = origin(input.publicOrigin, "publicOrigin");
  const upstream = origin(input.upstream, "upstream", true);
  requireValue(publicOrigin !== upstream, "publicOrigin and upstream must differ");
  const listen = input.listen ?? { host: "127.0.0.1", port: 3070 };
  requireValue(object(listen) && isIP(listen.host) !== 0 && Number.isInteger(listen.port) && listen.port >= 0 && listen.port <= 65535, "listen must contain an IP address and a valid port");
  knownKeys(listen, ["host", "port"], "listen");
  const sessionSeconds = input.sessionSeconds ?? 3600;
  requireValue(Number.isInteger(sessionSeconds) && sessionSeconds >= 1 && sessionSeconds <= 86400, "sessionSeconds must be between 1 and 86400");
  requireValue(Array.isArray(input.users) && input.users.length > 0, "users must be a nonempty array");
  const users = new Map();
  const tokens = new Map();
  for (const value of input.users) {
    knownKeys(value, ["id", "roles", "tokenSha256", "expiresAt"], "user");
    requireValue(object(value) && typeof value.id === "string" && ID.test(value.id) && !users.has(value.id), "user ids must be unique and valid");
    requireValue(Array.isArray(value.roles) && value.roles.length > 0 && value.roles.every((role) => typeof role === "string" && ID.test(role)), `invalid roles for ${value.id}`);
    requireValue(typeof value.expiresAt === "string", `expiresAt must be a timestamp string for ${value.id}`);
    const expiresAt = Date.parse(value.expiresAt);
    requireValue(Number.isFinite(expiresAt), `expiresAt is required for ${value.id}`);
    const user = Object.freeze({ id: value.id, roles: Object.freeze([...new Set(value.roles)]), expiresAt });
    users.set(user.id, user);
    if (value.tokenSha256 !== undefined) {
      requireValue(typeof value.tokenSha256 === "string" && DIGEST.test(value.tokenSha256) && !tokens.has(value.tokenSha256), `invalid or duplicate token digest for ${value.id}`);
      tokens.set(value.tokenSha256, user);
    }
  }
  requireValue(Array.isArray(input.rules), "rules must be an array");
  const rules = input.rules.map((rule) => {
    knownKeys(rule, ["effect", "roles", "methods", "transport", "path", "query"], "rule");
    requireValue(object(rule) && ["allow", "deny"].includes(rule.effect), "rule effect must be allow or deny");
    requireValue(Array.isArray(rule.roles) && rule.roles.length > 0 && rule.roles.every((role) => typeof role === "string" && ID.test(role)), "rule roles must be valid");
    requireValue(Array.isArray(rule.methods) && rule.methods.length > 0 && rule.methods.every((method) => METHODS.has(method)), "rule methods must be explicit HTTP methods");
    requireValue(["http", "websocket"].includes(rule.transport), "rule transport must be http or websocket");
    requireValue(rule.transport !== "websocket" || (rule.methods.length === 1 && rule.methods[0] === "GET"), "WebSocket rules must use GET");
    requireValue(typeof rule.path === "string" && (rule.path === "/*" || canonicalPath(rule.path) === rule.path), "invalid rule path");
    requireValue(!rule.path.includes("*") || (rule.path.endsWith("/*") && rule.path.indexOf("*") === rule.path.length - 1), "only a trailing /* wildcard is supported");
    const query = rule.query ?? (rule.effect === "deny" ? "any" : {});
    requireValue(query === "any" || object(query), "query must be any or an exact selector object");
    if (query !== "any") {
      requireValue(Object.entries(query).every(([key, values]) => key.length > 0 && Array.isArray(values) && values.length > 0 && values.every((value) => typeof value === "string")), "query selectors must be nonempty string arrays");
    }
    return Object.freeze({ effect: rule.effect, roles: [...rule.roles], methods: [...rule.methods], transport: rule.transport, path: rule.path, query });
  });
  let authProxy = null;
  if (input.authProxy !== undefined) {
    const proxy = input.authProxy;
    knownKeys(proxy, ["secretSha256", "trustedPeers"], "authProxy");
    requireValue(object(proxy) && typeof proxy.secretSha256 === "string" && DIGEST.test(proxy.secretSha256), "authProxy requires a SHA-256 shared-secret digest");
    requireValue(Array.isArray(proxy.trustedPeers) && proxy.trustedPeers.length > 0 && proxy.trustedPeers.every((peer) => isIP(peer) !== 0), "authProxy requires explicit trusted IP addresses");
    authProxy = { secretSha256: proxy.secretSha256, trustedPeers: [...proxy.trustedPeers] };
  }
  return { version: 1, publicOrigin, upstream, listen: { ...listen }, sessionSeconds, users, tokens, rules, authProxy };
}

function matchesPath(pattern, path) {
  return pattern.endsWith("/*") ? path.startsWith(pattern.slice(0, -1)) : pattern === path;
}

function matchesQuery(selector, params) {
  if (selector === "any") return true;
  const entries = [...params.entries()];
  if (new Set(entries.map(([key]) => key)).size !== entries.length) return false;
  if (entries.length !== Object.keys(selector).length) return false;
  return entries.every(([key, value]) => Object.hasOwn(selector, key) && selector[key].includes(value));
}

export function authorize(config, user, method, target, transport, now = Date.now()) {
  const path = canonicalPath(target);
  if (!METHODS.has(method) || user.expiresAt <= now || path === "/internal" || path.startsWith("/internal/")) return false;
  const params = new URL(target, config.publicOrigin).searchParams;
  let allowed = false;
  for (const rule of config.rules) {
    if (rule.transport !== transport || !rule.methods.includes(method) || !rule.roles.some((role) => user.roles.includes(role)) || !matchesPath(rule.path, path) || !matchesQuery(rule.query, params)) continue;
    if (rule.effect === "deny") return false;
    allowed = true;
  }
  return allowed;
}
