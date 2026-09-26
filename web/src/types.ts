// Server response shapes and the type guards that admit them. Every
// response is checked before use: the server is untrusted, and a guard that
// fails surfaces as an error instead of a half-rendered page.

export type Guard<T> = (value: unknown) => value is T;

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const isString = (value: unknown): value is string => typeof value === "string";
const isNumber = (value: unknown): value is number => typeof value === "number";
const isNullableString = (value: unknown): value is string | null =>
  value === null || isString(value);

export function arrayOf<T>(guard: Guard<T>): Guard<T[]> {
  return (value): value is T[] => Array.isArray(value) && value.every(guard);
}

function hasFields(
  value: unknown,
  fields: Record<string, Guard<unknown>>,
): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  return Object.entries(fields).every(([key, guard]) => guard(value[key]));
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
}

export const isTokenResponse = (value: unknown): value is TokenResponse =>
  hasFields(value, { access_token: isString, refresh_token: isString });

export interface Me {
  email: string;
}

export const isMe = (value: unknown): value is Me =>
  hasFields(value, { email: isString });

export interface Secret {
  id: string;
  name: string;
  policy: unknown;
  version: number;
  owner_fingerprint: string;
  updated_at: string;
}

export const isSecret = (value: unknown): value is Secret =>
  hasFields(value, {
    id: isString,
    name: isString,
    version: isNumber,
    owner_fingerprint: isString,
    updated_at: isString,
  });

export interface HostRule {
  match: string;
  value: string;
}

const isHostRule = (value: unknown): value is HostRule =>
  hasFields(value, { match: isString, value: isString });

/** The host allowlist of an untyped policy, or null if it is malformed. */
export function policyHosts(policy: unknown): HostRule[] | null {
  if (!isRecord(policy)) return null;
  const hosts = policy["hosts"];
  return arrayOf(isHostRule)(hosts) ? hosts : null;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  owner_fingerprint: string;
  secret_ids: string[];
  grant_exp: number;
  last_used_at: string | null;
  created_at: string;
}

export const isApiKey = (value: unknown): value is ApiKey =>
  hasFields(value, {
    id: isString,
    name: isString,
    key_prefix: isString,
    owner_fingerprint: isString,
    secret_ids: arrayOf(isString),
    grant_exp: isNumber,
    last_used_at: isNullableString,
    created_at: isString,
  });

export interface Receipt {
  boot_id: string;
  seq: number;
  hash: string;
  payload: Record<string, unknown>;
}

export const isReceipt = (value: unknown): value is Receipt =>
  hasFields(value, {
    boot_id: isString,
    seq: isNumber,
    hash: isString,
    payload: isRecord,
  });

export interface ReceiptPage {
  receipts: Receipt[];
  next_cursor: string | null;
}

export const isReceiptPage = (value: unknown): value is ReceiptPage =>
  hasFields(value, {
    receipts: arrayOf(isReceipt),
    next_cursor: isNullableString,
  });

export interface Boot {
  boot_id: string;
  attestation_token: string;
  receipt_pubkey: string;
  image_digest: string;
  first_seen: string;
}

export const isBoot = (value: unknown): value is Boot =>
  hasFields(value, {
    boot_id: isString,
    attestation_token: isString,
    receipt_pubkey: isString,
    image_digest: isString,
    first_seen: isString,
  });
