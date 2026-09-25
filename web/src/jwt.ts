import { isRecord } from "./types";

// Decodes a JWT's claims for display only. Nothing here checks the
// signature, issuer or expiry: `carapace verify` does that.

export function decodeJwtClaims(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  const payload = parts[1];
  if (parts.length !== 3 || payload === undefined) return null;
  try {
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const claims: unknown = JSON.parse(text);
    return isRecord(claims) ? claims : null;
  } catch {
    return null;
  }
}

/** The claim at a dotted path, e.g. "submods.container.image_digest". */
export function claimAt(
  claims: Record<string, unknown>,
  path: string,
): unknown {
  let value: unknown = claims;
  for (const key of path.split(".")) {
    if (!isRecord(value)) return undefined;
    value = value[key];
  }
  return value;
}
