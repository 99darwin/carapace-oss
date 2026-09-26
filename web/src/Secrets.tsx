import { useCallback } from "react";
import type { ApiClient } from "./api";
import { useResource } from "./hooks";
import { arrayOf, isSecret, policyHosts } from "./types";
import { formatTime, Loaded, Short } from "./ui";

function Hosts({ policy }: { policy: unknown }) {
  const hosts = policyHosts(policy);
  if (hosts === null) return <em>unrecognized policy</em>;
  if (hosts.length === 0) return <em>none</em>;
  return (
    <ul className="plain">
      {hosts.map((host) => (
        <li key={`${host.match}:${host.value}`}>
          <code>{host.value}</code>
          {host.match !== "exact" && (
            <span className="muted"> ({host.match})</span>
          )}
        </li>
      ))}
    </ul>
  );
}

export function Secrets({ client }: { client: ApiClient }) {
  const load = useCallback(
    () => client.get("/v1/secrets", arrayOf(isSecret)),
    [client],
  );
  const [secrets] = useResource(load);
  return (
    <section>
      <h2>Secrets</h2>
      <p className="muted">
        The server holds only ciphertext. Add, rotate and delete secrets with
        the CLI (<code>carapace secret add</code>), which seals them on your
        device.
      </p>
      <Loaded resource={secrets}>
        {(rows) =>
          rows.length === 0 ? (
            <p>No secrets yet.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Allowed hosts</th>
                  <th>Version</th>
                  <th>Owner key</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((secret) => (
                  <tr key={secret.id}>
                    <td>
                      {secret.name}
                      <br />
                      <Short value={secret.id} />
                    </td>
                    <td>
                      <Hosts policy={secret.policy} />
                    </td>
                    <td>{secret.version}</td>
                    <td>
                      <Short value={secret.owner_fingerprint} />
                    </td>
                    <td>{formatTime(secret.updated_at)}</td>
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
