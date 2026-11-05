import { randomBytes } from "node:crypto";
import { tokenDigest } from "./policy.mjs";

const [id, role, daysText = "30", ...extra] = process.argv.slice(2);
const days = Number(daysText);
if (extra.length || !/^[a-zA-Z0-9@._+-]{1,128}$/u.test(id ?? "") || !/^[a-zA-Z0-9@._+-]{1,128}$/u.test(role ?? "") || !Number.isInteger(days) || days < 1 || days > 365) {
  console.error("Usage: node credential.mjs <user-id> <role> [days:1..365]");
  process.exitCode = 2;
} else {
  const token = randomBytes(32).toString("base64url");
  console.log(JSON.stringify({ id, roles: [role], tokenSha256: tokenDigest(token), expiresAt: new Date(Date.now() + days * 86400000).toISOString() }, null, 2));
  console.error(`Personal access token (store securely; shown once): ${token}`);
}
