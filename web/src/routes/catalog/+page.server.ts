import { redirect } from "@sveltejs/kit";
import type { PageServerLoad } from "./$types";
import { api, ApiError } from "$lib/server/authd";
import type { ClassView, SessionSummary, RecordingView } from "$lib/types";

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

  // Fetch completed recordings for each session in parallel. 404 means the
  // recording endpoint isn't mounted (LiveKit not configured); ignore it.
  // Any other error is also silently ignored so a recording query failure
  // never breaks the catalog.
  const recordingsBySession: Record<string, RecordingView[]> = {};
  if (sessions.length > 0) {
    await Promise.all(
      sessions.map(async (s) => {
        try {
          const data = await api<{ recordings: RecordingView[] }>(
            cookies,
            `/v1/recordings/sessions/${s.sessionId}/playback`
          );
          if (data.recordings?.length > 0) {
            recordingsBySession[s.sessionId] = data.recordings;
          }
        } catch {
          // Recording endpoint unavailable or no recordings — not an error.
        }
      })
    );
  }

  return { classes, sessions, sessionsLocked, recordingsBySession };
};
