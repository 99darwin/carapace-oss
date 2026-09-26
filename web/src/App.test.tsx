import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ApiClient } from "./api";
import { App } from "./App";
import { type Handler, fakeFetch, json, tokens } from "./testing";

const SECRET = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "github",
  policy: { v: 1, hosts: [{ match: "exact", value: "api.github.com" }] },
  version: 3,
  owner_fingerprint: "ab".repeat(16),
  kms_key_version: null,
  created_at: "2026-09-01T00:00:00Z",
  updated_at: "2026-09-01T00:00:00Z",
};

const KEY = {
  id: "22222222-2222-4222-8222-222222222222",
  name: "ci-agent",
  key_prefix: "cpk_abababab",
  owner_fingerprint: "ab".repeat(16),
  secret_ids: [SECRET.id],
  grant: {},
  grant_iat: 1_790_000_000,
  grant_exp: 1_792_000_000,
  last_used_at: null,
  revoked_at: null,
  created_at: "2026-09-01T00:00:00Z",
};

function receipt(seq: number) {
  return {
    boot_id: "cd".repeat(32),
    seq,
    prev_hash: "0".repeat(64),
    hash: "e".repeat(64),
    payload: { secret_id: SECRET.id, decision: "allow" },
    signature: "sig",
  };
}

async function renderApp(
  hash: string,
  routes: Record<string, Handler>,
): Promise<{ calls: ReturnType<typeof fakeFetch>["calls"] }> {
  window.location.hash = hash;
  const fake = fakeFetch({
    "POST /v1/auth/login": () => json(tokens(1)),
    "GET /v1/auth/me": () => json({ email: "alice@example.com" }),
    ...routes,
  });
  render(<App client={new ApiClient(fake.fetch)} />);
  fireEvent.change(screen.getByLabelText("Email"), {
    target: { value: "alice@example.com" },
  });
  fireEvent.change(screen.getByLabelText("Password"), {
    target: { value: "Correct-Horse-9" },
  });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Log in" }));
    await Promise.resolve();
  });
  return { calls: fake.calls };
}

afterEach(cleanup);

describe("App", () => {
  it("logs in and lists secrets with their allowed hosts", async () => {
    await renderApp("#/secrets", {
      "GET /v1/secrets": () =>
        json([SECRET, { ...SECRET, id: "x", name: "odd", policy: [] }]),
    });
    expect(await screen.findByText("api.github.com")).toBeTruthy();
    expect(screen.getByText("unrecognized policy")).toBeTruthy();
    expect(await screen.findByText("alice@example.com")).toBeTruthy();
  });

  it("shows a login error and stays on the form", async () => {
    await renderApp("#/secrets", {
      "POST /v1/auth/login": () => json({ detail: "x" }, 401),
    });
    expect((await screen.findByRole("alert")).textContent).toBe(
      "Invalid email or password",
    );
  });

  it("explains and confirms a server-side revoke", async () => {
    let revoked = false;
    const { calls } = await renderApp("#/keys", {
      // The server lists live keys only.
      "GET /v1/api-keys": () => json(revoked ? [] : [KEY]),
      [`POST /v1/api-keys/${KEY.id}/revoke`]: () => {
        revoked = true;
        return new Response(null, { status: 204 });
      },
    });
    // The wording tracks docs/THREAT_MODEL.md R2.
    const note = screen.getByRole("note").textContent;
    expect(note).toContain("carapace key revoke");
    expect(note).toContain("helps only partially against a malicious server");
    expect(note).toContain(
      "The only hard cutoff is rotating the credential at its provider",
    );
    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    fireEvent.click(
      screen.getByRole("button", { name: "Confirm revoke of ci-agent" }),
    );
    expect((await screen.findByRole("status")).textContent).toContain(
      "Revoked ci-agent on the server",
    );
    expect(await screen.findByText(/No API keys yet/)).toBeTruthy();
    const revoke = calls.find((c) => c.url.endsWith("/revoke"));
    expect(revoke?.method).toBe("POST");
    expect(revoke?.body).toBeUndefined();
  });

  it("pages receipts with next_cursor", async () => {
    const { calls } = await renderApp("#/receipts", {
      "GET /v1/receipts": (call) =>
        call.url.includes("cursor=")
          ? json({ boots: [], receipts: [receipt(1)], next_cursor: null })
          : json({ boots: [], receipts: [receipt(0)], next_cursor: "c:0" }),
    });
    fireEvent.click(await screen.findByRole("button", { name: "Load more" }));
    expect(await screen.findByText("1")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
    expect(calls.some((c) => c.url.includes("cursor=c%3A0"))).toBe(true);
  });

  it("labels decoded attestation claims as unverified", async () => {
    const claims = btoa(JSON.stringify({ hwmodel: "GCP_AMD_SEV", iat: 1 }));
    await renderApp("#/attestation", {
      "GET /v1/receipts/boots": () =>
        json([
          {
            boot_id: "cd".repeat(32),
            attestation_token: `e30.${claims.replace(/=+$/, "")}.sig`,
            receipt_pubkey: "pk",
            tls_cert_pem: "pem",
            image_digest: "sha256:ab",
            first_seen: "2026-09-01T00:00:00Z",
          },
        ]),
    });
    expect(await screen.findByText("GCP_AMD_SEV")).toBeTruthy();
    expect(screen.getByText(/unverified — verify with/).textContent).toBe(
      "unverified — verify with carapace verify",
    );
  });

  it("returns to the login form when the session ends", async () => {
    await renderApp("#/secrets", {
      "GET /v1/secrets": () => json({}, 401),
      "POST /v1/auth/refresh": () => json({}, 401),
    });
    expect(await screen.findByRole("button", { name: "Log in" })).toBeTruthy();
  });
});
