import { readdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const directory = fileURLToPath(new URL(".", import.meta.url));
const tests = (await readdir(new URL("./test/", import.meta.url))).filter((file) => file.endsWith(".test.mjs")).sort().map((file) => `test/${file}`);
const sources = (await readdir(new URL(".", import.meta.url))).filter((file) => file.endsWith(".mjs") || file === "server.ts").sort();
const commands = [
  ...sources.map((file) => ["--experimental-strip-types", "--check", file]),
  ["--experimental-strip-types", "--test", ...tests],
  ["run.mjs", "--check", "config.example.json"],
];
console.log(`Office access verification on ${process.version} (${process.platform}/${process.arch})`);
for (const args of commands) {
  const result = spawnSync(process.execPath, args, { cwd: directory, stdio: "inherit", timeout: 60000, shell: false });
  if (result.error || result.status !== 0) {
    console.error(`Verification failed: node ${args.join(" ")}`);
    process.exitCode = 1;
    break;
  }
}
