import { type SubmitEvent, useState } from "react";
import type { ApiClient } from "./api";
import { errorMessage } from "./hooks";

function field(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === "string" ? value : "";
}

export function Login({
  client,
  onLogin,
}: {
  client: ApiClient;
  onLogin: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError(null);
    try {
      await client.login(field(form, "email"), field(form, "password"));
      onLogin();
    } catch (caught: unknown) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <h1>Carapace</h1>
      <form onSubmit={(event) => void handleSubmit(event)}>
        <label>
          Email
          <input name="email" type="email" autoComplete="username" required />
        </label>
        <label>
          Password
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            required
          />
        </label>
        <button type="submit" disabled={busy}>
          {busy ? "Logging in…" : "Log in"}
        </button>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
      </form>
      <p className="muted">
        Sessions are kept in memory only: reloading the page logs you out.
      </p>
    </main>
  );
}
