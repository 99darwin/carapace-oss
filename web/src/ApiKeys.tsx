import { useCallback, useState } from "react";
import type { ApiClient } from "./api";
import { errorMessage, useResource } from "./hooks";
import { type ApiKey, arrayOf, isApiKey } from "./types";
import { formatTime, Loaded } from "./ui";

function RevokeButton({
  client,
  apiKey,
  onRevoked,
}: {
  client: ApiClient;
  apiKey: ApiKey;
  onRevoked: (apiKey: ApiKey) => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    setBusy(true);
    setError(null);
    try {
      await client.post(`/v1/api-keys/${encodeURIComponent(apiKey.id)}/revoke`);
      onRevoked(apiKey);
    } catch (caught: unknown) {
      setError(errorMessage(caught));
      setBusy(false);
    }
  }

  if (!confirming) {
    return (
      <button
        type="button"
        onClick={() => {
          setConfirming(true);
        }}
      >
        Revoke
      </button>
    );
  }
  return (
    <span className="confirm">
      <button
        type="button"
        className="danger"
        disabled={busy}
        onClick={() => void handleConfirm()}
      >
        Confirm revoke of {apiKey.name}
      </button>
      <button
        type="button"
        disabled={busy}
        onClick={() => {
          setConfirming(false);
        }}
      >
        Cancel
      </button>
      {error && (
        <span role="alert" className="error">
          {error}
        </span>
      )}
    </span>
  );
}

function RevokedNotice({ apiKey }: { apiKey: ApiKey }) {
  return (
    <p role="status" className="warning">
      Revoked {apiKey.name} on the server. An honest server enforces this within
      60 seconds; a malicious one can keep serving the last grant until{" "}
      {formatTime(apiKey.grant_exp)}. Run <code>carapace key revoke</code> for
      the owner-signed tombstone, and rotate the credential at its provider:
      that is the only hard cutoff.
    </p>
  );
}

export function ApiKeys({ client }: { client: ApiClient }) {
  const load = useCallback(
    () => client.get("/v1/api-keys", arrayOf(isApiKey)),
    [client],
  );
  const [keys, reload] = useResource(load);
  const [revoked, setRevoked] = useState<ApiKey | null>(null);
  const handleRevoked = useCallback(
    (apiKey: ApiKey) => {
      setRevoked(apiKey);
      reload();
    },
    [reload],
  );
  return (
    <section>
      <h2>API keys</h2>
      <div className="callout" role="note">
        <p>
          <strong>What revoking here does.</strong> The server marks the key
          revoked and stops serving its grant. An honest server enforces this
          right away (the enclave refuses the key on its next fetch, within 60
          seconds). A malicious or compromised server can keep serving the last
          grant until it expires, shown below.
        </p>
        <p>
          The browser cannot sign. <code>carapace key revoke</code> also uploads
          an owner-signed tombstone, which helps only partially against a
          malicious server: once an enclave has seen it, that boot refuses the
          older grant, but a server that never serves it goes undetected. The
          only hard cutoff is rotating the credential at its provider.
        </p>
      </div>
      {revoked && <RevokedNotice apiKey={revoked} />}
      <Loaded resource={keys}>
        {(rows) =>
          rows.length === 0 ? (
            <p>No API keys yet. Mint them with the CLI.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Key</th>
                  <th>Secrets</th>
                  <th>Grant expires</th>
                  <th>Last used</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((apiKey) => (
                  <tr key={apiKey.id}>
                    <td>{apiKey.name}</td>
                    <td>
                      <code>{apiKey.key_prefix}…</code>
                    </td>
                    <td>{apiKey.secret_ids.length}</td>
                    <td>{formatTime(apiKey.grant_exp)}</td>
                    <td>{formatTime(apiKey.last_used_at)}</td>
                    <td>
                      <RevokeButton
                        client={client}
                        apiKey={apiKey}
                        onRevoked={handleRevoked}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        }
      </Loaded>
    </section>
  );
}
