import { readFile } from "node:fs/promises";
import { createAccessGateway } from "./gateway.mjs";

const args = process.argv.slice(2);
if (args.length < 1 || args.length > 2 || (args.length === 2 && args[0] !== "--check")) {
  console.error("Usage: node run.mjs [--check] <policy-file>");
  process.exitCode = 2;
} else {
  try {
    const config = JSON.parse(await readFile(args.at(-1), "utf8"));
    const gateway = createAccessGateway(config, { audit: (event) => console.log(JSON.stringify(event)) });
    if (args[0] === "--check") {
      await gateway.close();
      console.log("Office access policy is valid.");
    } else {
      gateway.server.on("error", (error) => { console.error(error.message); process.exitCode = 1; void gateway.close(); });
      gateway.server.listen(gateway.config.listen.port, gateway.config.listen.host, () => console.error(`Office access gateway listening for ${gateway.config.publicOrigin}`));
      for (const signal of ["SIGTERM", "SIGINT"]) process.once(signal, () => { void gateway.close(); });
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Gateway startup failed");
    process.exitCode = 1;
  }
}
