import { redirect } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { api, ApiError } from "$lib/server/authd";
import { clearSession, refreshCookie } from "$lib/server/session";

// POST /signout — best-effort server logout (revokes the refresh family), then
// clear the cookies and return to sign-in. Plain form post; no JS required.
export const POST: RequestHandler = async ({ cookies }) => {
  const rt = refreshCookie(cookies);
  if (rt) {
    try {
      await api(cookies, "/v1/token/logout", { method: "POST", body: { refreshToken: rt } });
    } catch (e) {
      if (!(e instanceof ApiError)) throw e;
    }
  }
  clearSession(cookies);
  throw redirect(303, "/signin");
};
