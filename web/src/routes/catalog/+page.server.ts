import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
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

  // Fetch the user's enrolled class IDs. 403 means the user hasn't met the
  // declared tier yet — they can still browse, just can't enroll.
  let enrolledIds: string[] = [];
  try {
    const enrolled = (await api<{ classes: ClassView[] }>(cookies, "/v1/classes/enrolled")).classes ?? [];
    enrolledIds = enrolled.map((c) => c.id);
  } catch {
    // Not enrolled in anything, or tier too low — treat as empty.
  }

  return { classes, sessions, sessionsLocked, recordingsBySession, enrolledIds };
};

export const actions: Actions = {
  enroll: async ({ cookies, request }) => {
    const form = await request.formData();
    const classId = form.get("classId") as string;
    if (!classId) return fail(400, { error: "Missing class ID." });
    try {
      await api(cookies, `/v1/classes/${classId}/enroll`, { method: "POST" });
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        return fail(403, { error: "Identity verification required to enroll." });
      }
      throw e;
    }
  },

  unenroll: async ({ cookies, request }) => {
    const form = await request.formData();
    const classId = form.get("classId") as string;
    if (!classId) return fail(400, { error: "Missing class ID." });
    await api(cookies, `/v1/classes/${classId}/enroll`, { method: "DELETE" });
  },
};
