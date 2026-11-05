import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import officeAccess from "../server.ts";

function harness(configPath) {
  const registered = { routes: new Map(), logs: [], dispose: [] };
  officeAccess({
    settings: { define: () => ({ get: async () => ({ configPath }) }) },
    http: { route: (method, path, handler) => registered.routes.set(`${method} ${path}`, handler) },
    cli: { register: (cli) => { registered.cli = cli; } },
    background: { service: (_name, service) => { registered.service = service; } },
    log: { info: (message) => registered.logs.push(message) },
    onDispose: (fn) => registered.dispose.push(fn),
  });
  return registered;
}

async function policyFile(t) {
  const directory = await mkdtemp(join(tmpdir(), "bb-office-access-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const value = JSON.parse(await readFile(new URL("../config.example.json", import.meta.url), "utf8"));
  value.listen.port = 0;
  const path = join(directory, "policy.json");
  await writeFile(path, JSON.stringify(value));
  return path;
}

test("plugin reports missing configuration without opening a port", async () => {
  const api = harness(undefined);
  await assert.rejects(api.service.start(new AbortController().signal), { name: "NeedsConfigurationError" });
  const result = await api.cli.run(["check"]);
  assert.equal(result.exitCode, 1);
  assert.equal(JSON.parse((await api.cli.run(["status"])).stdout).listening, false);
});

test("plugin check validates policy and stays offline", async (t) => {
  const api = harness(await policyFile(t));
  assert.equal((await api.cli.run(["check"])).exitCode, 0);
  assert.equal(JSON.parse((await api.cli.run(["status"])).stdout).listening, false);
  assert.equal((await api.cli.run(["unknown"])).exitCode, 2);
});

test("plugin background service starts, exposes status and closes on abort", async (t) => {
  const api = harness(await policyFile(t));
  const controller = new AbortController();
  const started = api.service.start(controller.signal);
  t.after(async () => { controller.abort(); await started; });
  let status;
  for (let attempt = 0; attempt < 100; attempt++) {
    status = JSON.parse((await api.cli.run(["status"])).stdout);
    if (status.listening) break;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(status.listening, true);
  const route = api.routes.get("GET /status");
  assert.equal(route({ json: (value) => value }).listening, true);
  controller.abort();
  await started;
  assert.equal(JSON.parse((await api.cli.run(["status"])).stdout).listening, false);
});

test("already-aborted plugin service never leaves a listener", async (t) => {
  const api = harness(await policyFile(t));
  const controller = new AbortController();
  controller.abort();
  await api.service.start(controller.signal);
  assert.equal(JSON.parse((await api.cli.run(["status"])).stdout).listening, false);
});
