import { env } from "$env/dynamic/private";
import type { Cookies } from "@sveltejs/kit";
import type { Me, Session } from "$lib/types";
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
  headers?: Record<string, string>;
}

function call(path: string, init: Init, token?: string): Promise<Response> {
  const headers: Record<string, string> = { ...init.headers };
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
  // Not every authd response is JSON — e.g. a 404 from an unmounted route is
  // plain text. Parse leniently so a non-JSON body still surfaces as an
  // ApiError with the right status, not a raw SyntaxError.
  let data: { error?: string } | undefined;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = undefined;
  }
  if (!res.ok) {
    throw new ApiError(res.status, data?.error || text || res.statusText);
  }
  return data as T;
}

// Single-flight refresh, scoped to one request via the per-request cookies
// object. The refresh token is single-use: authd rotates it on every refresh
// and invalidates the old one. When several api() calls run concurrently
// (Promise.all in a load) and all hit 401, each would otherwise refresh with
// the same refresh token — the first rotates it, the rest send a now-stale
// token, fail, and clearSession() logs the user out. Coalescing them onto one
// shared promise spends the token exactly once; every caller gets the same new
// access token. A WeakMap keyed by the cookies object isolates requests from
// each other (so each request still sets its own Set-Cookie) and needs no
// manual cleanup.
const inflightRefresh = new WeakMap<Cookies, Promise<string | null>>();

// refresh re-mints the access token from the refresh cookie, rotating both
// cookies. Returns the new access token, or null if the refresh token is itself
// rejected (caller should treat as signed-out).
function refresh(cookies: Cookies): Promise<string | null> {
  const existing = inflightRefresh.get(cookies);
  if (existing) return existing;

  const p = (async () => {
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
  })();

  inflightRefresh.set(cookies, p);
  // Drop the entry once settled so a later, genuine re-expiry in the same
  // request can refresh again rather than reuse a resolved promise.
  void p.finally(() => inflightRefresh.delete(cookies));
  return p;
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

// getMe resolves the signed-in user from the CURRENT cookies (null when signed
// out). Resolve it in the layout load — not once-per-request in hooks — so a
// tier climb that re-mints the token mid-action is reflected on the post-action
// re-render (hooks runs before the action; its locals.me would be stale).
export async function getMe(cookies: Cookies): Promise<Me | null> {
  try {
    return await api<Me>(cookies, "/v1/me");
  } catch (e) {
    if (e instanceof ApiError) return null;
    throw e;
  }
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
