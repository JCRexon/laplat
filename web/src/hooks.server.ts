import type { Handle } from "@sveltejs/kit";
import { api, ApiError } from "$lib/server/authd";
import { accessCookie, refreshCookie } from "$lib/server/session";
import type { Me } from "$lib/types";

// Resolve the signed-in user once per request from the token cookies (refreshing
// transparently if the access token expired). Routes read event.locals.me; the
// browser is never handed a token.
export const handle: Handle = async ({ event, resolve }) => {
  event.locals.me = null;
  if (accessCookie(event.cookies) || refreshCookie(event.cookies)) {
    try {
      event.locals.me = await api<Me>(event.cookies, "/v1/me");
    } catch (e) {
      if (!(e instanceof ApiError)) throw e;
      // Unusable session — leave me null (treated as signed out).
    }
  }
  return resolve(event);
};
