import { describe, expect, it } from "vitest";
import { ApiClient, ApiError } from "./api";
import { type Call, fakeFetch, json, tokens } from "./testing";
import { isRecord } from "./types";

const authorized = (call: Call, token: string) =>
  call.headers["Authorization"] === `Bearer ${token}`;

async function loggedIn(routes: Parameters<typeof fakeFetch>[0]) {
  const fake = fakeFetch({
    "POST /v1/auth/login": () => json(tokens(1)),
    ...routes,
  });
  const client = new ApiClient(fake.fetch);
  await client.login("a@example.com", "pw");
  return { client, calls: fake.calls };
}

describe("ApiClient", () => {
  it("shares one refresh across concurrent 401s", async () => {
    let refreshes = 0;
    const { client, calls } = await loggedIn({
      "GET /v1/secrets": (call) =>
        authorized(call, "access-2") ? json([]) : json({}, 401),
      "POST /v1/auth/refresh": async () => {
        refreshes += 1;
        await new Promise((resolve) => setTimeout(resolve, 10));
        return json(tokens(2));
      },
    });
    const results = await Promise.all(
      [1, 2, 3].map(() => client.get("/v1/secrets", Array.isArray)),
    );
    expect(results).toEqual([[], [], []]);
    expect(refreshes).toBe(1);
    const refresh = calls.find((c) => c.url === "/v1/auth/refresh");
    expect(refresh?.body).toEqual({ refresh_token: "refresh-1" });
  });

  it("ends the session when the refresh token is rejected", async () => {
    const { client } = await loggedIn({
      "GET /v1/secrets": () => json({}, 401),
      "POST /v1/auth/refresh": () => json({ detail: "no" }, 401),
    });
    let ended = 0;
    client.onSessionEnd(() => {
      ended += 1;
    });
    await expect(client.get("/v1/secrets", Array.isArray)).rejects.toThrow(
      ApiError,
    );
    expect(client.isLoggedIn).toBe(false);
    expect(ended).toBe(1);
  });

  it("rejects a response that fails its guard", async () => {
    const { client } = await loggedIn({
      "GET /v1/secrets": () => json({ not: "a list" }),
    });
    await expect(client.get("/v1/secrets", Array.isArray)).rejects.toThrow(
      "Unexpected response",
    );
  });

  it("logs out with both tokens and forgets them", async () => {
    const { client, calls } = await loggedIn({
      "POST /v1/auth/logout": () => new Response(null, { status: 204 }),
    });
    await client.logout();
    expect(client.isLoggedIn).toBe(false);
    expect(calls.at(-1)?.body).toEqual({
      refresh_token: "refresh-1",
      access_token: "access-1",
    });
    await expect(client.get("/v1/secrets", isRecord)).rejects.toThrow(ApiError);
  });

  it("revokes tokens minted by a refresh that a logout overtook", async () => {
    const { client, calls } = await loggedIn({
      "GET /v1/secrets": () => json({}, 401),
      "POST /v1/auth/refresh": async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        return json(tokens(2));
      },
      "POST /v1/auth/logout": () => new Response(null, { status: 204 }),
    });
    const pending = client.get("/v1/secrets", Array.isArray);
    await new Promise((resolve) => setTimeout(resolve, 0));
    await client.logout();
    await expect(pending).rejects.toThrow("session has ended");
    expect(client.isLoggedIn).toBe(false);
    const revoked = calls
      .filter((c) => c.url === "/v1/auth/logout")
      .map((c) => c.body);
    expect(revoked).toEqual([
      { refresh_token: "refresh-1", access_token: "access-1" },
      { refresh_token: "refresh-2", access_token: "access-2" },
    ]);
  });

  it("does not let a stale refresh answer for a newer login", async () => {
    let logins = 0;
    const fake = fakeFetch({
      "POST /v1/auth/login": () => json(tokens((logins += 2) - 1)),
      "GET /v1/secrets": (call) =>
        authorized(call, "access-4") ? json([]) : json({}, 401),
      "POST /v1/auth/refresh": async (call) => {
        const body = call.body as { refresh_token: string };
        if (body.refresh_token === "refresh-3") return json(tokens(4));
        await new Promise((resolve) => setTimeout(resolve, 20));
        return json(tokens(2));
      },
      "POST /v1/auth/logout": () => new Response(null, { status: 204 }),
    });
    const client = new ApiClient(fake.fetch);
    await client.login("a@example.com", "pw");
    const first = client.get("/v1/secrets", Array.isArray);
    await new Promise((resolve) => setTimeout(resolve, 0));
    await client.logout();
    await client.login("a@example.com", "pw");
    await expect(client.get("/v1/secrets", Array.isArray)).resolves.toEqual([]);
    expect(client.isLoggedIn).toBe(true);
    await expect(first).rejects.toThrow("session has ended");
  });

  it("reports bad credentials without a session", async () => {
    const { fetch } = fakeFetch({
      "POST /v1/auth/login": () => json({ detail: "Invalid" }, 401),
    });
    const client = new ApiClient(fetch);
    await expect(client.login("a@example.com", "x")).rejects.toThrow(
      "Invalid email or password",
    );
    expect(client.isLoggedIn).toBe(false);
  });
});
