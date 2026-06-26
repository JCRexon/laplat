import type { RequestHandler } from "./$types";
import { env } from "$env/dynamic/private";
import { redirect } from "@sveltejs/kit";
import { setSession } from "$lib/server/session";
import type { Session } from "$lib/types";

const BASE = env.API_BASE || "http://localhost:8080";

// Proxy /v1/auth/oidc/{provider}/callback to authd.
// The browser arrives here after the provider redirects back with ?code&state.
// We forward the state/secret binding cookies (set during start) to authd
// server-to-server, let authd complete the exchange, then set our own session
// cookies from the returned JSON and redirect the user onward.
export const GET: RequestHandler = async ({ params, url, cookies }) => {
  // Provider-side error (e.g. user denied consent).
  const providerError = url.searchParams.get("error");
  if (providerError) {
    const msg = encodeURIComponent(providerError);
    throw redirect(303, `/signin?oidcError=${msg}`);
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) {
    throw redirect(303, "/signin?oidcError=missing+oauth+params");
  }

  // Read OIDC binding cookies the start proxy set.
  const oidcState = cookies.get("laplat_oidc_state") ?? "";
  const oidcSecret = cookies.get("laplat_oidc_secret") ?? "";

  // One-shot: clear binding cookies before the round-trip regardless of outcome.
  cookies.delete("laplat_oidc_state", { path: "/v1/auth/oidc" });
  cookies.delete("laplat_oidc_secret", { path: "/v1/auth/oidc" });

  const cbURL =
    `${BASE}/v1/auth/oidc/${params.provider}/callback` +
    `?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`;

  const cookieHeader = [
    oidcState ? `laplat_oidc_state=${oidcState}` : "",
    oidcSecret ? `laplat_oidc_secret=${oidcSecret}` : "",
  ]
    .filter(Boolean)
    .join("; ");

  let res: Response;
  try {
    res = await fetch(cbURL, {
      headers: cookieHeader ? { cookie: cookieHeader } : {},
    });
  } catch {
    throw redirect(303, "/signin?oidcError=sign-in+unavailable");
  }

  if (!res.ok) {
    let msg = "sign-in+failed";
    try {
      const data = (await res.json()) as { error?: string };
      if (data.error) msg = encodeURIComponent(data.error);
    } catch {
      // ignore parse failures
    }
    throw redirect(303, `/signin?oidcError=${msg}`);
  }

  const sess = (await res.json()) as Session;
  setSession(cookies, sess);
  throw redirect(303, "/onboarding");
};
