import { useCallback, useEffect, useState } from "react";
import type { ApiClient } from "./api";
import { ApiKeys } from "./ApiKeys";
import { Attestation } from "./Attestation";
import { useHashRoute, useResource } from "./hooks";
import { Login } from "./Login";
import { Receipts } from "./Receipts";
import { Secrets } from "./Secrets";
import { isMe } from "./types";

const PAGES = {
  "#/secrets": { title: "Secrets", Page: Secrets },
  "#/keys": { title: "API keys", Page: ApiKeys },
  "#/receipts": { title: "Receipts", Page: Receipts },
  "#/attestation": { title: "Attestation", Page: Attestation },
} as const;

type Route = keyof typeof PAGES;
const DEFAULT_ROUTE: Route = "#/secrets";

function isRoute(hash: string): hash is Route {
  return Object.hasOwn(PAGES, hash);
}

function Shell({ client }: { client: ApiClient }) {
  const hash = useHashRoute();
  const route = isRoute(hash) ? hash : DEFAULT_ROUTE;
  const { Page } = PAGES[route];
  const loadMe = useCallback(() => client.get("/v1/auth/me", isMe), [client]);
  const [me] = useResource(loadMe);
  return (
    <>
      <header>
        <strong>Carapace</strong>
        <nav>
          {Object.entries(PAGES).map(([href, { title }]) => (
            <a
              key={href}
              href={href}
              aria-current={href === route ? "page" : undefined}
            >
              {title}
            </a>
          ))}
        </nav>
        <span className="muted">{me.status === "ok" ? me.data.email : ""}</span>
        <button type="button" onClick={() => void client.logout()}>
          Log out
        </button>
      </header>
      <main>
        <Page key={route} client={client} />
      </main>
    </>
  );
}

export function App({ client }: { client: ApiClient }) {
  const [loggedIn, setLoggedIn] = useState(client.isLoggedIn);
  useEffect(
    () =>
      client.onSessionEnd(() => {
        setLoggedIn(false);
      }),
    [client],
  );
  if (!loggedIn) {
    return (
      <Login
        client={client}
        onLogin={() => {
          setLoggedIn(true);
        }}
      />
    );
  }
  return <Shell client={client} />;
}
