import type { Session } from "./types";

// ApiError carries the HTTP status so callers can branch (e.g. 403 -> tier too
// low, 401 -> unauthenticated).
export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

const STORAGE_KEY = "laplat.session";
// VITE_API_BASE lets a deployed build target an absolute API origin; in dev it
// is empty and requests go through the Vite proxy (/v1).
const BASE = import.meta.env.VITE_API_BASE ?? "";

// --- session storage ---------------------------------------------------------

export function loadSession(): Session | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Session;
  } catch {
    return null;
  }
}

export function saveSession(s: Session | null) {
  if (s) localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
  else localStorage.removeItem(STORAGE_KEY);
}

// --- request core ------------------------------------------------------------

interface RequestOpts {
  method?: string;
  body?: unknown;
  // auth: attach the bearer token and transparently refresh on 401. Public
  // endpoints (login/verify) set this false.
  auth?: boolean;
}

async function raw(path: string, token: string | null, opts: RequestOpts) {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return fetch(`${BASE}${path}`, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
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

// refresh swaps the stored refresh token for a new session. Returns null if the
// refresh token is itself rejected (forces re-login).
async function refresh(): Promise<Session | null> {
  const s = loadSession();
  if (!s) return null;
  const res = await raw("/v1/token/refresh", null, {
    method: "POST",
    body: { refreshToken: s.refreshToken },
  });
  if (!res.ok) {
    saveSession(null);
    return null;
  }
  const next = (await res.json()) as Session;
  saveSession(next);
  return next;
}

// request is the typed entry point. With auth, it attaches the access token and,
// on a single 401, refreshes once and retries — so a short-lived access token
// expiring mid-session is invisible to callers.
export async function request<T>(path: string, opts: RequestOpts = {}): Promise<T> {
  const useAuth = opts.auth ?? true;
  let token = useAuth ? loadSession()?.accessToken ?? null : null;

  let res = await raw(path, token, opts);
  if (res.status === 401 && useAuth) {
    const next = await refresh();
    if (!next) throw new ApiError(401, "session expired");
    token = next.accessToken;
    res = await raw(path, token, opts);
  }
  return parse<T>(res);
}
