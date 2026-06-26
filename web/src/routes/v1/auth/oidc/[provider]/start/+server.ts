import type { RequestHandler } from "./$types";
import { env } from "$env/dynamic/private";
import { redirect, error } from "@sveltejs/kit";

const BASE = env.API_BASE || "http://localhost:8080";
const SECURE = env.COOKIE_SECURE ? env.COOKIE_SECURE === "true" : true;

// Extract name=value from a Set-Cookie header string.
function parseCookieNameValue(header: string): [string, string] | null {
  const eq = header.indexOf("=");
  if (eq < 0) return null;
  const name = header.slice(0, eq).trim();
  const sc = header.indexOf(";", eq);
  const value = sc > 0 ? header.slice(eq + 1, sc).trim() : header.slice(eq + 1).trim();
  return [name, value];
}

// Proxy /v1/auth/oidc/{provider}/start to authd.
// authd generates state/secret, sets them as cookies in the response, and
// returns a 302 to the provider's auth URL. We re-set those cookies here
// with an environment-aware Secure flag (Secure: true hardcoded in authd
// would break dev over plain HTTP), then forward the redirect to the client.
export const GET: RequestHandler = async ({ params, cookies }) => {
  let res: Response;
  try {
    res = await fetch(`${BASE}/v1/auth/oidc/${params.provider}/start`, {
      redirect: "manual",
    });
  } catch {
    throw error(502, "social sign-in unavailable");
  }

  if (res.status === 404) throw error(404, "unknown provider");
  if (res.status !== 302) throw error(502, "unexpected response from auth service");

  const location = res.headers.get("location");
  if (!location) throw error(502, "missing redirect location from auth service");

  // getSetCookie() returns each Set-Cookie header as a separate string
  // (Node.js 18+ / undici). Fall back to empty array if not available.
  const setCookies: string[] =
    typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];

  for (const h of setCookies) {
    const parsed = parseCookieNameValue(h);
    if (!parsed) continue;
    const [name, value] = parsed;
    if (name === "laplat_oidc_state" || name === "laplat_oidc_secret") {
      cookies.set(name, value, {
        path: "/v1/auth/oidc",
        httpOnly: true,
        secure: SECURE,
        sameSite: "lax",
        maxAge: 600,
      });
    }
  }

  throw redirect(302, location);
};
