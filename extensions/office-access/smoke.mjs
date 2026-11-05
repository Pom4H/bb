import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

function validateOrigin(value) {
  const url = new URL(value);
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(local && url.protocol === "http:")) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new Error("Use an HTTPS origin without a path or credentials; HTTP is allowed only on loopback");
  return url.origin;
}

export async function readOperatorKey(path) {
  const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size > 4096 || (process.platform !== "win32" && (info.mode & 0o077) !== 0)) throw new Error("Key file must be a small regular file with permissions 0600 or stricter");
    const key = (await file.readFile("utf8")).trim();
    if (!/^[A-Za-z0-9_-]{43,128}$/u.test(key)) throw new Error("Key file must contain only a personal access key, not its digest or the generator log");
    return key;
  } finally {
    await file.close();
  }
}

async function boundedJson(response) {
  if (!response.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new Error("Expected JSON");
  if (!response.body) throw new Error("Missing response body");
  const reader = response.body.getReader();
  let size = 0;
  const chunks = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 262144) throw new Error("Response exceeds smoke-check size limit");
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export async function checkDeployment(value, key, fetchImpl = fetch) {
  const origin = validateOrigin(value);
  if (!/^[A-Za-z0-9_-]{43,128}$/u.test(key)) throw new Error("Invalid personal access key format");
  const signed = { authorization: `Bearer ${key}` };
  const checks = [
    { name: "anonymous identity is denied", path: "/office/me", status: 401 },
    { name: "anonymous native configuration probe is denied", path: "/api/v1/system/config", status: 401 },
    { name: "invalid bearer is denied", path: "/office/me", status: 401, headers: { authorization: "Bearer invalid" } },
    { name: "operator identity is valid JSON", path: "/office/me", status: 200, headers: signed, validate: (body) => typeof body?.subject === "string" && Array.isArray(body.roles) && body.roles.every((role) => typeof role === "string") && Number.isFinite(Date.parse(body.expiresAt)) },
    { name: "authenticated bb health", path: "/health", status: 200, headers: signed, validate: (body) => body?.ok === true },
    { name: "authenticated bb configuration", path: "/api/v1/system/config", status: 200, headers: signed, validate: (body) => typeof body?.serverUrl === "string" && (body.primaryHostId === null || typeof body.primaryHostId === "string") },
    { name: "foreign browser origin is denied", path: "/office/me", status: 403, headers: { ...signed, origin: "https://foreign-origin.invalid" } },
    { name: "core internal namespace is denied", path: "/internal/ws", status: 403, headers: signed },
    { name: "browser deep link redirects only to local login", path: "/threads/office-smoke-check", status: 303, headers: { accept: "text/html" }, location: "/office/login?next=%2Fthreads%2Foffice-smoke-check" },
  ];
  const results = [];
  for (const check of checks) {
    let response;
    try {
      response = await fetchImpl(`${origin}${check.path}`, { method: "GET", redirect: "manual", headers: { accept: "application/json", ...check.headers }, signal: AbortSignal.timeout(8000) });
      if (response.status !== check.status) throw new Error(`Expected HTTP ${check.status}`);
      if (check.location && response.headers.get("location") !== check.location) throw new Error("Unexpected login destination");
      if (check.validate && !check.validate(await boundedJson(response))) throw new Error("Unexpected JSON shape");
      results.push({ name: check.name, ok: true, status: response.status });
    } catch (error) {
      const reason = error?.name === "TimeoutError" || error?.name === "AbortError" ? "Request timed out" : "Unexpected status, response or connection failure";
      results.push({ name: check.name, ok: false, status: response?.status ?? null, reason });
    } finally {
      if (response?.body && !response.bodyUsed) await response.body.cancel().catch(() => {});
    }
  }
  return { ok: results.every((result) => result.ok), checks: results, scope: "Read-only HTTP smoke check; not native mobile, OIDC, row-level ACL or WebSocket verification" };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [origin, path, ...extra] = process.argv.slice(2);
  if (!origin || !path || extra.length) {
    console.error("Usage: node smoke.mjs <public-origin> <private-key-file>");
    process.exitCode = 2;
  } else {
    try {
      const result = await checkDeployment(origin, await readOperatorKey(path));
      console.log(JSON.stringify(result, null, 2));
      process.exitCode = result.ok ? 0 : 1;
    } catch {
      console.error("Cannot start smoke check. Check the origin, key file format and file permissions. No credentials are printed.");
      process.exitCode = 2;
    }
  }
}
