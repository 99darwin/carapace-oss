import { type Guard, isRecord, isTokenResponse } from "./types";

// A thin client for the server's JSON API.
//
// Tokens live only in this object's private fields: never in storage or
// cookies, so a reload logs the user out. Refresh tokens are single use and
// the server revokes the whole family on reuse, so concurrent 401s share one
// in-flight refresh instead of each spending the same token.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export type Fetch = (url: string, init: RequestInit) => Promise<Response>;

interface Session {
  readonly accessToken: string;
  readonly refreshToken: string;
}

type Method = "GET" | "POST";

const SESSION_EXPIRED = "Your session has ended. Log in again.";

async function errorDetail(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (isRecord(body) && typeof body["detail"] === "string") {
      return body["detail"];
    }
  } catch {
    // Not JSON; fall through to the status line.
  }
  return `Request failed (${String(response.status)})`;
}

async function readJson<T>(response: Response, guard: Guard<T>): Promise<T> {
  if (!response.ok) {
    throw new ApiError(response.status, await errorDetail(response));
  }
  const body: unknown = await response.json();
  if (!guard(body)) {
    throw new ApiError(response.status, "Unexpected response from the server");
  }
  return body;
}

export class ApiClient {
  #session: Session | null = null;
  #refreshing: Promise<boolean> | null = null;
  readonly #listeners = new Set<() => void>();
  readonly #fetch: Fetch;

  constructor(fetchFn: Fetch = (url, init) => fetch(url, init)) {
    this.#fetch = fetchFn;
  }

  get isLoggedIn(): boolean {
    return this.#session !== null;
  }

  /** Called when the session ends for any reason. Returns an unsubscribe. */
  onSessionEnd(listener: () => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  async login(email: string, password: string): Promise<void> {
    const response = await this.#send("POST", "/v1/auth/login", {
      email,
      password,
    });
    if (response.status === 401) {
      throw new ApiError(401, "Invalid email or password");
    }
    const tokens = await readJson(response, isTokenResponse);
    this.#session = {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
    };
  }

  /** Revoke the session server-side (best effort) and forget it here. */
  async logout(): Promise<void> {
    const session = this.#session;
    if (session === null) return;
    this.#endSession();
    try {
      await this.#send("POST", "/v1/auth/logout", {
        refresh_token: session.refreshToken,
        access_token: session.accessToken,
      });
    } catch {
      // Tokens are already gone from memory; they expire on their own.
    }
  }

  async get<T>(path: string, guard: Guard<T>): Promise<T> {
    return readJson(await this.#authorized("GET", path), guard);
  }

  async post(path: string): Promise<void> {
    const response = await this.#authorized("POST", path);
    if (!response.ok) {
      throw new ApiError(response.status, await errorDetail(response));
    }
  }

  async #authorized(method: Method, path: string): Promise<Response> {
    const session = this.#session;
    if (session === null) throw new ApiError(401, SESSION_EXPIRED);
    const response = await this.#send(method, path, undefined, session);
    if (response.status !== 401) return response;
    if (!(await this.#refresh(session)) || this.#session === null) {
      throw new ApiError(401, SESSION_EXPIRED);
    }
    const retry = await this.#send(method, path, undefined, this.#session);
    if (retry.status === 401) {
      this.#endSession();
      throw new ApiError(401, SESSION_EXPIRED);
    }
    return retry;
  }

  /** Swap `stale` for a fresh session, sharing one refresh among callers. */
  #refresh(stale: Session): Promise<boolean> {
    if (this.#session !== stale) {
      // Someone else already refreshed (or logged out) since we sent.
      return Promise.resolve(this.#session !== null);
    }
    this.#refreshing ??= this.#rotate(stale).finally(() => {
      this.#refreshing = null;
    });
    return this.#refreshing;
  }

  async #rotate(stale: Session): Promise<boolean> {
    let tokens;
    try {
      const response = await this.#send("POST", "/v1/auth/refresh", {
        refresh_token: stale.refreshToken,
      });
      tokens = await readJson(response, isTokenResponse);
    } catch {
      if (this.#session === stale) this.#endSession();
      return false;
    }
    if (this.#session !== stale) return false; // logged out meanwhile
    this.#session = {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
    };
    return true;
  }

  #endSession(): void {
    this.#session = null;
    for (const listener of this.#listeners) listener();
  }

  #send(
    method: Method,
    path: string,
    body?: Record<string, string>,
    session?: Session,
  ): Promise<Response> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (session) headers["Authorization"] = `Bearer ${session.accessToken}`;
    const init: RequestInit = {
      method,
      headers,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return this.#fetch(path, init);
  }
}
