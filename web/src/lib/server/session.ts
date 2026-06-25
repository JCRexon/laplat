import { dev } from "$app/environment";
import type { Cookies } from "@sveltejs/kit";
import type { Session } from "$lib/types";

// Tokens live ONLY in httpOnly cookies the browser's JS cannot read — never in
// localStorage or any client-visible store. This is the data-minimization
// choice (see README): the browser holds no account credentials.
const AT = "lp_at"; // access token
const RT = "lp_rt"; // refresh token

const base = {
  httpOnly: true,
  secure: !dev, // dev runs over http://localhost, where Secure cookies are dropped
  sameSite: "lax" as const,
  path: "/",
};

export function setSession(cookies: Cookies, s: Session) {
  const now = Math.floor(Date.now() / 1000);
  cookies.set(AT, s.accessToken, { ...base, maxAge: Math.max(1, s.accessExpiresAt - now) });
  cookies.set(RT, s.refreshToken, { ...base, maxAge: Math.max(1, s.refreshExpiresAt - now) });
}

export function clearSession(cookies: Cookies) {
  cookies.delete(AT, { path: "/" });
  cookies.delete(RT, { path: "/" });
}

export const accessCookie = (c: Cookies) => c.get(AT);
export const refreshCookie = (c: Cookies) => c.get(RT);
