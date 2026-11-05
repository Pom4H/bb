import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import type { BbPluginApi } from "@get-bb/plugin-sdk";
import { createAccessGateway, type AccessGateway } from "./gateway.mjs";

export default function officeAccess(bb: BbPluginApi): void {
  const settings = bb.settings.define({
    configPath: {
      type: "string",
      label: "Access policy file",
      description: "Absolute path to a private office-access JSON file. Reload this plugin after changing the file or its path.",
    },
  });
  let running: AccessGateway | null = null;

  async function load(): Promise<AccessGateway> {
    const { configPath } = await settings.get();
    if (!configPath || !isAbsolute(configPath)) {
      throw Object.assign(new Error("Set configPath to an absolute path, then reload Office access."), { name: "NeedsConfigurationError" });
    }
    try {
      const value: unknown = JSON.parse(await readFile(configPath, "utf8"));
      return createAccessGateway(value, { audit: (event) => bb.log.info(JSON.stringify(event)) });
    } catch {
      throw Object.assign(new Error("Office access policy could not be read or validated. Run the standalone policy check for details."), { name: "NeedsConfigurationError" });
    }
  }

  function status() {
    return {
      listening: running?.server.listening ?? false,
      publicOrigin: running?.config.publicOrigin ?? null,
      address: running?.server.address() ?? null,
      users: running?.config.users.size ?? 0,
      rules: running?.config.rules.length ?? 0,
    };
  }

  bb.http.route("GET", "/status", (context) => context.json(status()));
  bb.cli.register({
    name: "office-access",
    summary: "Check the office access policy and gateway status",
    commands: [
      { name: "status", summary: "Show gateway listener status", usage: "bb office-access status" },
      { name: "check", summary: "Validate the configured policy without opening a listener", usage: "bb office-access check" },
    ],
    async run(argv) {
      if (argv.length === 1 && argv[0] === "status") return { exitCode: 0, stdout: `${JSON.stringify(status(), null, 2)}\n` };
      if (argv.length !== 1 || argv[0] !== "check") return { exitCode: 2, stderr: "Usage: bb office-access <status|check>\n" };
      try {
        const gateway = await load();
        await gateway.close();
        return { exitCode: 0, stdout: "Office access policy is valid.\n" };
      } catch (error) {
        return { exitCode: 1, stderr: `${error instanceof Error ? error.message : "Policy check failed"}\n` };
      }
    },
  });

  bb.background.service("access-gateway", {
    async start(signal) {
      const gateway = await load();
      running = gateway;
      let abort = () => {};
      try {
        await new Promise<void>((resolve, reject) => {
          abort = () => { void gateway.close().then(resolve, reject); };
          signal.addEventListener("abort", abort, { once: true });
          gateway.server.once("error", reject);
          if (signal.aborted) { abort(); return; }
          gateway.server.listen({ port: gateway.config.listen.port, host: gateway.config.listen.host, signal }, () => {
            bb.log.info(`Office access gateway ready at ${gateway.config.publicOrigin}`);
          });
        });
      } finally {
        signal.removeEventListener("abort", abort);
        await gateway.close();
        if (running === gateway) running = null;
      }
    },
  });
  bb.onDispose(async () => { await running?.close(); });
}
