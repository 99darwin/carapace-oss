import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { ApiError } from "./api";

export type Resource<T> =
  | { status: "loading" }
  | { status: "ok"; data: T }
  | { status: "error"; message: string };

export function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed";
}

/** Runs `load` on mount and whenever `reload` is called. */
export function useResource<T>(
  load: () => Promise<T>,
): [Resource<T>, () => void] {
  const [state, setState] = useState<Resource<T>>({ status: "loading" });
  const [generation, setGeneration] = useState(0);
  useEffect(() => {
    let active = true;
    load().then(
      (data) => {
        if (active) setState({ status: "ok", data });
      },
      (error: unknown) => {
        if (active) setState({ status: "error", message: errorMessage(error) });
      },
    );
    return () => {
      active = false;
    };
  }, [load, generation]);
  const reload = useCallback(() => {
    setGeneration((g) => g + 1);
  }, []);
  return [state, reload];
}

function subscribeHash(onChange: () => void): () => void {
  window.addEventListener("hashchange", onChange);
  return () => {
    window.removeEventListener("hashchange", onChange);
  };
}

export function useHashRoute(): string {
  return useSyncExternalStore(subscribeHash, () => window.location.hash);
}
