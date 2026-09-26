import { useEffect, useState } from "react";
import type { ApiClient } from "./api";
import { errorMessage } from "./hooks";
import { isReceiptPage, type Receipt } from "./types";
import { Short } from "./ui";

const PAGE_SIZE = 50;

function receiptsPath(cursor: string | null): string {
  const params = new URLSearchParams({ limit: String(PAGE_SIZE) });
  if (cursor !== null) params.set("cursor", cursor);
  return `/v1/receipts?${params.toString()}`;
}

function payloadField(receipt: Receipt, key: string): string {
  const value = receipt.payload[key];
  return typeof value === "string" ? value : "—";
}

export function Receipts({ client }: { client: ApiClient }) {
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    client.get(receiptsPath(null), isReceiptPage).then(
      (page) => {
        if (!active) return;
        setReceipts(page.receipts);
        setCursor(page.next_cursor);
        setLoading(false);
      },
      (caught: unknown) => {
        if (!active) return;
        setError(errorMessage(caught));
        setLoading(false);
      },
    );
    return () => {
      active = false;
    };
  }, [client]);

  async function handleLoadMore() {
    setLoading(true);
    setError(null);
    try {
      const page = await client.get(receiptsPath(cursor), isReceiptPage);
      setReceipts((previous) => [...previous, ...page.receipts]);
      setCursor(page.next_cursor);
    } catch (caught: unknown) {
      setError(errorMessage(caught));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section>
      <h2>Receipts</h2>
      <p className="muted">
        Shown as stored by the server; signatures and chains are not checked in
        the browser. Verify them with <code>carapace audit verify</code>.
      </p>
      {receipts.length === 0 && !loading && !error && <p>No receipts yet.</p>}
      {receipts.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Boot</th>
              <th>Seq</th>
              <th>Secret</th>
              <th>Payload</th>
            </tr>
          </thead>
          <tbody>
            {receipts.map((receipt) => (
              <tr key={`${receipt.boot_id}:${String(receipt.seq)}`}>
                <td>
                  <Short value={receipt.boot_id} />
                </td>
                <td>{receipt.seq}</td>
                <td>
                  <Short value={payloadField(receipt, "secret_id")} />
                </td>
                <td>
                  <pre>{JSON.stringify(receipt.payload, null, 1)}</pre>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {loading && <p className="muted">Loading…</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {cursor !== null && !loading && (
        <button type="button" onClick={() => void handleLoadMore()}>
          Load more
        </button>
      )}
    </section>
  );
}
