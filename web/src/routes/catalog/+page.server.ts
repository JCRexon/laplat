import { redirect } from "@sveltejs/kit";
import type { PageServerLoad } from "./$types";
import { api, ApiError } from "$lib/server/authd";
import type { ClassView, SessionSummary } from "$lib/types";

export const load: PageServerLoad = async ({ locals, cookies }) => {
  if (!locals.me) throw redirect(303, "/signin");

  const classes = (await api<{ classes: ClassView[] }>(cookies, "/v1/classes/published")).classes ?? [];

  // Listing sessions requires the declared tier (403 below it). The endpoint is
  // also only mounted when live sessions (LiveKit) are configured, so it can 404
  // — treat that as "sessions unavailable", not an error.
  let sessions: SessionSummary[] = [];
  let sessionsLocked = false;
  try {
    sessions = (await api<{ sessions: SessionSummary[] }>(cookies, "/v1/sessions")).sessions ?? [];
  } catch (e) {
    if (e instanceof ApiError && e.status === 403) sessionsLocked = true;
    else if (!(e instanceof ApiError && e.status === 404)) throw e;
  }

  return { classes, sessions, sessionsLocked };
};
