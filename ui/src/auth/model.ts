// The sign-in and the API tokens as data: the text of a refused request,
// the state of a token and the fields of a new token.
import { ApiProblem } from "../api/client";
import type { TokenInfo } from "../api/types";

/** The text of a refused request: the detail of its problem. */
export function problemText(e: unknown): string {
  if (e instanceof ApiProblem) return e.detail || e.title || `status ${e.status}`;
  return String(e instanceof Error ? e.message : e);
}

/**
 * The detail of a 429 problem with the seconds that remain: the words
 * `wait <n> s` of the detail take the new count, and a detail with no such
 * words gets them at its end.
 */
export function waitDetail(detail: string, seconds: number): string {
  const wait = `wait ${seconds} s`;
  return /wait \d+ s/.test(detail) ? detail.replace(/wait \d+ s/, wait) : `${detail}, ${wait}`;
}

/** The end of the wait of a problem in ms since the epoch, or null with no wait. */
export function waitUntil(e: unknown, now: number): number | null {
  if (!(e instanceof ApiProblem) || e.status !== 429 || e.retryAfter === null) return null;
  return now + e.retryAfter * 1000;
}

/** The whole seconds from `now` to `until`, at least 0. */
export function secondsLeft(until: number, now: number): number {
  return Math.max(0, Math.ceil((until - now) / 1000));
}

export type TokenState = "active" | "revoked" | "expired";

/** The state of a token at a time in the form of the server, `YYYY-MM-DDTHH:MM:SSZ`. */
export function tokenState(t: TokenInfo, nowIso: string): TokenState {
  if (t.revoked) return "revoked";
  if (t.expires_at && t.expires_at <= nowIso) return "expired";
  return "active";
}

/** The time of the server in the form of its token times. */
export function isoSeconds(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
}

/** A time of a token as a date and a time in UTC, or `never` for no time. */
export function timeText(t: string | null | undefined, none: string): string {
  if (!t) return none;
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(t);
  return m ? `${m[1]} ${m[2]}` : t;
}

/** The days of a new token: null for an empty field, a whole number from 1, or `invalid`. */
export function daysValue(text: string): number | null | "invalid" {
  const s = text.trim();
  if (!s) return null;
  if (!/^\d+$/.test(s)) return "invalid";
  const n = Number(s);
  return n >= 1 && n <= 0xffffffff ? n : "invalid";
}

/** The scopes of a new token, in the order of the scopes of the user. */
export function chosenScopes(own: readonly string[], chosen: ReadonlySet<string>): string[] {
  return own.filter((s) => chosen.has(s));
}

/** The initials of a user name: the first letters of its first 2 parts. */
export function initials(name: string): string {
  const parts = name.split(/[._@-]+/).filter(Boolean);
  const letters = parts.length > 1 ? parts[0]![0]! + parts[1]![0]! : name.slice(0, 2);
  return letters.toUpperCase();
}

