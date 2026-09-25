import { useCallback } from "react";
import type { ApiClient } from "./api";
import { useResource } from "./hooks";
import { claimAt, decodeJwtClaims } from "./jwt";
import { arrayOf, type Boot, isBoot } from "./types";
import { formatTime, Loaded } from "./ui";

const SHOWN_CLAIMS = [
  "iss",
  "hwmodel",
  "swname",
  "dbgstat",
  "secboot",
  "submods.container.image_digest",
  "submods.gce.project_id",
  "eat_nonce",
] as const;

function claimText(value: unknown): string {
  if (value === undefined) return "—";
  return typeof value === "string" ? value : JSON.stringify(value);
}

function BootCard({ boot }: { boot: Boot }) {
  const claims = decodeJwtClaims(boot.attestation_token);
  return (
    <article className="card">
      <h3>
        Boot <code>{boot.boot_id}</code>
      </h3>
      <p className="muted">First seen {formatTime(boot.first_seen)}</p>
      <p className="warning">
        unverified — verify with <code>carapace verify</code>
      </p>
      {claims === null ? (
        <p className="error">The attestation token could not be decoded.</p>
      ) : (
        <>
          <dl>
            {SHOWN_CLAIMS.map((path) => (
              <div key={path}>
                <dt>{path}</dt>
                <dd>
                  <code>{claimText(claimAt(claims, path))}</code>
                </dd>
              </div>
            ))}
            <div>
              <dt>issued / expires</dt>
              <dd>
                {formatTime(asSeconds(claims["iat"]))} /{" "}
                {formatTime(asSeconds(claims["exp"]))}
              </dd>
            </div>
          </dl>
          <details>
            <summary>All claims</summary>
            <pre>{JSON.stringify(claims, null, 2)}</pre>
          </details>
        </>
      )}
    </article>
  );
}

function asSeconds(value: unknown): number | null {
  return typeof value === "number" ? value : null;
}

export function Attestation({ client }: { client: ApiClient }) {
  const load = useCallback(
    () => client.get("/v1/receipts/boots", arrayOf(isBoot)),
    [client],
  );
  const [boots] = useResource(load);
  return (
    <section>
      <h2>Attestation</h2>
      <p className="muted">
        Enclave boots that signed your receipts, with the attestation claims the
        server stored for each. The browser decodes the claims but checks no
        signature, audience or expiry, so treat them as unverified.
      </p>
      <Loaded resource={boots}>
        {(rows) =>
          rows.length === 0 ? (
            <p>No enclave boots have signed receipts for you yet.</p>
          ) : (
            rows.map((boot) => <BootCard key={boot.boot_id} boot={boot} />)
          )
        }
      </Loaded>
    </section>
  );
}
