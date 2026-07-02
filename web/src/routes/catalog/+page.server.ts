import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { api, ApiError } from "$lib/server/authd";
import type { ClassView, SessionSummary, RecordingView } from "$lib/types";

// A catalog session carries the title of the class it belongs to, so the
// session list can say *what* is live, not just that something is.
export type CatalogSession = SessionSummary & { classTitle: string };

const STATUS_ORDER: Record<string, number> = { live: 0, scheduled: 1, ended: 2 };

export const load: PageServerLoad = async ({ locals, cookies }) => {
  if (!locals.me) throw redirect(303, "/signin");

  const classes = (await api<{ classes: ClassView[] }>(cookies, "/v1/classes/published")).classes ?? [];

  // Sessions are discovered per published class — there is no global session
  // list endpoint (GET /v1/sessions requires a classId). Fetch them in parallel
  // and flatten. Listing requires the declared tier: a 403 means sessions are
  // locked for this user. A 404 means the endpoint isn't mounted (LiveKit not
  // configured) — treat that as "sessions unavailable", not an error.
  let sessions: CatalogSession[] = [];
  let sessionsLocked = false;
  const perClass = await Promise.all(
    classes.map(async (c) => {
      try {
        const rows = (await api<{ sessions: SessionSummary[] }>(cookies, `/v1/sessions?classId=${c.id}`)).sessions ?? [];
        return rows.map((s): CatalogSession => ({ ...s, classTitle: c.title }));
      } catch (e) {
        if (e instanceof ApiError && e.status === 403) {
          sessionsLocked = true;
          return [];
        }
        if (e instanceof ApiError && e.status === 404) return [];
        throw e;
      }
    })
  );
  // Live sessions surface first, then upcoming, then ended.
  sessions = perClass.flat().sort(
    (a, b) => (STATUS_ORDER[a.status] ?? 3) - (STATUS_ORDER[b.status] ?? 3)
  );

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
