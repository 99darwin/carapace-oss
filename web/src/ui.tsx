import type { ReactNode } from "react";
import type { Resource } from "./hooks";

export function Loaded<T>({
  resource,
  children,
}: {
  resource: Resource<T>;
  children: (data: T) => ReactNode;
}): ReactNode {
  if (resource.status === "loading") return <p className="muted">Loading…</p>;
  if (resource.status === "error") {
    return (
      <p role="alert" className="error">
        {resource.message}
      </p>
    );
  }
  return children(resource.data);
}

export function formatTime(value: string | number | null): string {
  if (value === null) return "—";
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  return Number.isNaN(date.getTime()) ? "invalid date" : date.toLocaleString();
}

export function Short({
  value,
  length = 12,
}: {
  value: string;
  length?: number;
}) {
  return (
    <code title={value}>
      {value.length > length ? `${value.slice(0, length)}…` : value}
    </code>
  );
}
