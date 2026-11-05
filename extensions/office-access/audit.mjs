import { canonicalPath } from "./policy.mjs";

const EXACT = new Set(["/", "/health", "/office/login", "/office/logout", "/office/me", "/api/v1/system/config", "/install.sh", "/install.ps1"]);
const PREFIXES = ["/api/v1/thread-invites", "/api/v1/threads", "/api/v1/projects", "/api/v1/terminals", "/api/v1/files", "/api/v1/plugins", "/api/v1/system", "/thread-invites", "/threads", "/projects", "/internal", "/install", "/office", "/ws", "/api"];
const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"]);

export function auditPath(target) {
  let path;
  try { path = canonicalPath(target); }
  catch { return "/invalid-path"; }
  if (EXACT.has(path)) return path;
  for (const prefix of PREFIXES) {
    if (path === prefix) return prefix;
    if (path.startsWith(`${prefix}/`)) return `${prefix}/*`;
  }
  return "/other";
}

export function auditMethod(method) {
  return METHODS.has(method) ? method : "OTHER";
}

export function writeAudit(audit, event) {
  const result = audit(event);
  if (result !== null && (typeof result === "object" || typeof result === "function") && typeof result.then === "function") {
    void Promise.resolve(result).catch(() => {});
    throw new Error("Office access audit callback must be synchronous");
  }
}
