import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { checkDeployment, readOperatorKey } from "../smoke.mjs";

const key = randomBytes(32).toString("base64url");

function responseFor(url, options) {
  const path = new URL(url).pathname;
  assert.equal(options.method, "GET");
  assert.equal(options.redirect, "manual");
  if (path === "/threads/office-smoke-check") return new Response(null, { status: 303, headers: { location: "/office/login?next=%2Fthreads%2Foffice-smoke-check" } });
  if (options.headers.authorization !== `Bearer ${key}`) return Response.json({ code: "unauthorized" }, { status: 401 });
  if (options.headers.origin || path.startsWith("/internal/")) return Response.json({ code: "forbidden" }, { status: 403 });
  if (path === "/office/me") return Response.json({ subject: "operator", roles: ["admin"], expiresAt: "2099-01-01T00:00:00Z" });
  if (path === "/health") return Response.json({ ok: true });
  return Response.json({ serverUrl: "https://office.test", primaryHostId: null });
}

test("smoke checks exact HTTP statuses and structured responses", async () => {
  const result = await checkDeployment("https://office.test", key, async (...args) => responseFor(...args));
  assert.equal(result.ok, true);
  assert.equal(result.checks.length, 9);
  assert.ok(!JSON.stringify(result).includes(key));
});

test("smoke check refuses unsafe origins and URL credentials", async () => {
  for (const origin of ["http://office.test", "https://user:secret@office.test", "https://office.test/path", "https://office.test/?token=x", "file:///tmp/key"]) {
    await assert.rejects(checkDeployment(origin, key, () => { throw new Error("must not fetch"); }));
  }
});

test("unexpected redirects fail without following them with credentials", async () => {
  let calls = 0;
  const result = await checkDeployment("https://office.test", key, async (url, options) => {
    calls++;
    assert.ok(url.startsWith("https://office.test/"));
    assert.equal(options.redirect, "manual");
    return new Response(null, { status: 302, headers: { location: "https://other.invalid/steal" } });
  });
  assert.equal(result.ok, false);
  assert.equal(calls, 9);
});

test("HTTP 200 login HTML is not a successful health/configuration probe", async () => {
  const result = await checkDeployment("https://office.test", key, async (url, options) => options.headers.authorization === `Bearer ${key}` && !options.headers.origin && !url.includes("/internal/")
    ? new Response("<html>sign in</html>", { headers: { "content-type": "text/html" } }) : responseFor(url, options));
  assert.equal(result.ok, false);
  assert.equal(result.checks.filter((check) => !check.ok).length, 3);
});

test("smoke report cannot echo tokens from thrown errors or server response bodies", async () => {
  const result = await checkDeployment("https://office.test", key, async () => { throw new Error(`secret ${key}`); });
  assert.equal(result.ok, false);
  assert.ok(!JSON.stringify(result).includes(key));
});

test("smoke reader bounds JSON payload size", async () => {
  const result = await checkDeployment("https://office.test", key, async (url, options) => url.endsWith("/health") && options.headers.authorization === `Bearer ${key}`
    ? Response.json({ ok: true, data: "x".repeat(262144) }) : responseFor(url, options));
  assert.equal(result.ok, false);
  assert.equal(result.checks.filter((check) => !check.ok).length, 1);
});

test("operator key loader accepts only a private regular key file", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "bb-office-key-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "key");
  await writeFile(path, `${key}\n`, { mode: 0o600 });
  assert.equal(await readOperatorKey(path), key);
  await writeFile(path, "Personal access token: " + key);
  await assert.rejects(readOperatorKey(path));
  await writeFile(path, key);
  if (process.platform !== "win32") {
    await chmod(path, 0o644);
    await assert.rejects(readOperatorKey(path));
    await chmod(path, 0o600);
    await symlink(path, join(directory, "link"));
    await assert.rejects(readOperatorKey(join(directory, "link")));
  }
});
