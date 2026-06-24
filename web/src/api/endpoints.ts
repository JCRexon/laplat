import { ApiError, loadSession, request, saveSession } from "./client";
import type {
  ClassView,
  JoinGrant,
  Me,
  Session,
  SessionSummary,
  VerifyBegin,
} from "./types";

// refreshSession re-mints the access token from the stored refresh token. A
// tier climb (attest / verify phone / eKYC) changes DB state but not the
// already-issued token; calling this picks up the new tier in a fresh token.
export async function refreshSession(): Promise<Session> {
  const s = loadSession();
  if (!s) throw new ApiError(401, "no session");
  const next = await request<Session>("/v1/token/refresh", {
    method: "POST",
    body: { refreshToken: s.refreshToken },
    auth: false,
  });
  saveSession(next);
  return next;
}

// --- auth (email OTP — the dev-friendly factor; the console sender logs the
// code, so no SMS/SMTP vendor is needed to exercise the loop) -----------------

export function requestEmailCode(email: string): Promise<void> {
  return request("/v1/auth/email/request", { method: "POST", body: { email }, auth: false });
}

export async function verifyEmailCode(email: string, code: string): Promise<Session> {
  const s = await request<Session>("/v1/auth/email/verify", {
    method: "POST",
    body: { email, code },
    auth: false,
  });
  saveSession(s);
  return s;
}

export function logout(refreshToken: string): Promise<void> {
  return request("/v1/token/logout", { method: "POST", body: { refreshToken } });
}

// --- identity / tier climb ---------------------------------------------------

export function me(): Promise<Me> {
  return request<Me>("/v1/me");
}

// Self-attest 18+ -> reaches the `declared` tier (after a token refresh).
export function attestAdult(): Promise<void> {
  return request("/v1/identity/tos-accept", { method: "POST", body: { adultAttested: true } });
}

// Phone OTP with a bearer token binds the phone to the current account
// (authenticated upgrade) -> `phone_verified` once also declared.
export function requestPhoneCode(phone: string): Promise<void> {
  return request("/v1/auth/phone/request", { method: "POST", body: { phone } });
}

export async function verifyPhoneCode(phone: string, code: string): Promise<Session> {
  const s = await request<Session>("/v1/auth/phone/verify", {
    method: "POST",
    body: { phone, code },
  });
  saveSession(s);
  return s;
}

// eKYC handoff -> `verified`. The provider is not wired in dev, so begin returns
// a redirect target the UI surfaces; completion happens via the provider
// callback in a real deployment.
export function beginVerify(): Promise<VerifyBegin> {
  return request<VerifyBegin>("/v1/identity/verify/begin", { method: "POST", body: {} });
}

// Self-serve instructor application (requires the verified tier).
export function applyInstructor(): Promise<void> {
  return request("/v1/instructor/apply", { method: "POST", body: {} });
}

// --- discovery + live --------------------------------------------------------

export async function publishedClasses(): Promise<ClassView[]> {
  const r = await request<{ classes: ClassView[] }>("/v1/classes/published");
  return r.classes ?? [];
}

export async function listSessions(): Promise<SessionSummary[]> {
  const r = await request<{ sessions: SessionSummary[] }>("/v1/sessions");
  return r.sessions ?? [];
}

export function joinSession(id: string): Promise<JoinGrant> {
  return request<JoinGrant>(`/v1/sessions/${id}/join`, { method: "POST" });
}
