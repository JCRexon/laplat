import { env } from "$env/dynamic/private";
import type { Cookies } from "@sveltejs/kit";
import type { Session } from "$lib/types";
import { accessCookie, clearSession, refreshCookie, setSession } from "./session";

// The authd origin. Server-side only (BFF) — never shipped to the browser.
const BASE = env.API_BASE || "http://localhost:8080";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

interface Init {
  method?: string;
  body?: unknown;
}

function call(path: string, init: Init, token?: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init.body !== undefined) headers["content-type"] = "application/json";
  if (token) headers["authorization"] = `Bearer ${token}`;
  return fetch(`${BASE}${path}`, {
    method: init.method ?? "GET",
    headers,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
}

async function parse<T>(res: Response): Promise<T> {
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? JSON.parse(text) : undefined;
  if (!res.ok) {
    const msg = (data && (data.error as string)) || res.statusText;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

// refresh re-mints the access token from the refresh cookie, rotating both
// cookies. Returns the new access token, or null if the refresh token is itself
// rejected (caller should treat as signed-out).
async function refresh(cookies: Cookies): Promise<string | null> {
  const rt = refreshCookie(cookies);
  if (!rt) return null;
  const res = await call("/v1/token/refresh", { method: "POST", body: { refreshToken: rt } });
  if (!res.ok) {
    clearSession(cookies);
    return null;
  }
  const s = (await res.json()) as Session;
  setSession(cookies, s);
  return s.accessToken;
}

// api is the authenticated server-side call: it attaches the access-token cookie
// and, on a single 401, refreshes once and retries. A tier climb that re-mints
// the token is therefore invisible to route code.
export async function api<T>(cookies: Cookies, path: string, init: Init = {}): Promise<T> {
  let token = accessCookie(cookies);
  let res = await call(path, init, token);
  if (res.status === 401) {
    const next = await refresh(cookies);
    if (!next) throw new ApiError(401, "unauthenticated");
    token = next;
    res = await call(path, init, token);
  }
  return parse<T>(res);
}

// remint forces a token refresh so a just-changed tier shows on the next load.
export async function remint(cookies: Cookies): Promise<void> {
  await refresh(cookies);
}

// --- unauthenticated login steps (set the cookies) ---------------------------

export async function emailRequest(email: string): Promise<void> {
  const res = await call("/v1/auth/email/request", { method: "POST", body: { email } });
  await parse<void>(res);
}

export async function emailVerify(cookies: Cookies, email: string, code: string): Promise<void> {
  const res = await call("/v1/auth/email/verify", { method: "POST", body: { email, code } });
  const s = await parse<Session>(res);
  setSession(cookies, s);
}
