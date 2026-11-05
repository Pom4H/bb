import type { Server } from "node:http";

export interface AccessEvent {
  time: string;
  event: "office.access";
  requestId: string;
  subject: string | null;
  method: string;
  path: string;
  transport: string;
  status: number;
  code: string;
}

export interface AccessGateway {
  server: Server;
  config: {
    publicOrigin: string;
    upstream: string;
    listen: { host: string; port: number };
    users: ReadonlyMap<string, { id: string; roles: readonly string[]; expiresAt: number }>;
    rules: readonly unknown[];
  };
  close(): Promise<void>;
}

export function createAccessGateway(
  config: unknown,
  options?: { audit?: (event: AccessEvent) => void },
): AccessGateway;
