import { describe, expect, it } from "vitest";
import { claimAt, decodeJwtClaims } from "./jwt";
import { policyHosts } from "./types";

function jwt(claims: unknown): string {
  const part = btoa(JSON.stringify(claims))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `e30.${part}.sig`;
}

describe("decodeJwtClaims", () => {
  it("decodes base64url claims without verifying", () => {
    const claims = decodeJwtClaims(
      jwt({ iss: "x", submods: { container: { image_digest: "sha256:ab" } } }),
    );
    expect(claims?.["iss"]).toBe("x");
    expect(claimAt(claims ?? {}, "submods.container.image_digest")).toBe(
      "sha256:ab",
    );
    expect(claimAt(claims ?? {}, "submods.gce.project_id")).toBeUndefined();
  });

  it.each(["", "a.b", "a.!!!.c", `a.${btoa("[1]")}.c`, `a.${btoa("{")}.c`])(
    "returns null for %j",
    (token) => {
      expect(decodeJwtClaims(token)).toBeNull();
    },
  );
});

describe("policyHosts", () => {
  it("reads well-formed hosts", () => {
    const hosts = [{ match: "exact", value: "api.github.com" }];
    expect(policyHosts({ v: 1, hosts })).toEqual(hosts);
  });

  it.each([null, [], "x", { hosts: "api" }, { hosts: [{ value: 1 }] }])(
    "rejects malformed policy %j",
    (policy) => {
      expect(policyHosts(policy)).toBeNull();
    },
  );
});
