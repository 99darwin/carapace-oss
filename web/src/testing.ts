import type { Fetch } from "./api";

export interface Call {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: unknown;
}

export type Handler = (call: Call) => Response | Promise<Response>;

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** A fetch that routes "METHOD /path" (query string ignored) to handlers. */
export function fakeFetch(routes: Record<string, Handler>): {
  fetch: Fetch;
  calls: Call[];
} {
  const calls: Call[] = [];
  const fetch: Fetch = async (url, init) => {
    const method = init.method ?? "GET";
    const headers = (init.headers ?? {}) as Record<string, string>;
    const body: unknown =
      typeof init.body === "string" ? JSON.parse(init.body) : undefined;
    const call = { method, url, headers, body };
    calls.push(call);
    const handler = routes[`${method} ${url.split("?")[0] ?? url}`];
    return handler ? handler(call) : json({ detail: "Not found" }, 404);
  };
  return { fetch, calls };
}

export const tokens = (n: number) => ({
  user_id: "u",
  access_token: `access-${String(n)}`,
  refresh_token: `refresh-${String(n)}`,
  token_type: "bearer",
  expires_in: 900,
});
