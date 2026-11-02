// Calls the real MCP handler (the SDK, with the Worker's tools) the way a
// legacy-era client would, and reads the reply whether the SDK sent it as JSON
// or as one SSE message. Auth, Origin and the OAuth metadata are index.ts's
// job and are covered by the transport tests; this is for the tools.

import { handleMcp } from "../src/mcp";
import type { Env } from "../src/env";

const AUTH = { token: "test", clientId: "test", scopes: [] as string[] };

export async function rpc(
  body: Record<string, unknown>,
  env: Env = {} as Env,
): Promise<{ status: number; body: any }> {
  const res = await handleMcp(
    new Request("https://github.shamwari.ai/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, ...body }),
    }),
    env,
    AUTH,
  );
  return { status: res.status, body: parse(await res.text()) };
}

/** A JSON body, or the `data:` line of a single SSE message. */
export function parse(text: string): any {
  if (!text) return null;
  const data = text
    .split("\n")
    .find((l) => l.startsWith("data:"))
    ?.slice(5)
    .trim();
  return JSON.parse(data ?? text);
}

export async function listTools(env: Env = {} as Env) {
  const r = await rpc({ method: "tools/list" }, env);
  return r.body.result.tools as Array<{
    name: string;
    annotations: Record<string, boolean>;
    inputSchema: Record<string, unknown>;
  }>;
}
