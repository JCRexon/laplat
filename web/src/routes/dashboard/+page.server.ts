import { redirect } from "@sveltejs/kit";
import type { PageServerLoad } from "./$types";
import { api, ApiError } from "$lib/server/authd";
import type {
  ClassView,
  SessionSummary,
  RecordingView,
  ClassProgress,
  CompletionsResponse,
  ClassCompletion,
} from "$lib/types";

export interface EnrolledClass extends ClassView {
  sessions: SessionSummary[];
}

export const load: PageServerLoad = async ({ locals, cookies }) => {
  if (!locals.me) throw redirect(303, "/signin");

  // Enrolled classes — 403 means declared tier not yet met; treat as empty.
  let enrolled: ClassView[] = [];
  try {
    enrolled = (await api<{ classes: ClassView[] }>(cookies, "/v1/classes/enrolled")).classes ?? [];
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 403)) throw e;
  }

  // Sessions per enrolled class — 403/404 mean locked or LiveKit not configured.
  const sessionsPerClass = await Promise.all(
    enrolled.map(async (c) => {
      try {
        return (await api<{ sessions: SessionSummary[] }>(cookies, `/v1/sessions?classId=${c.id}`)).sessions ?? [];
      } catch {
        return [] as SessionSummary[];
      }
    })
  );

  // Recordings per session — always best-effort; never block the page.
  const allSessions = sessionsPerClass.flat();
  const recordingsBySession: Record<string, RecordingView[]> = {};
  await Promise.all(
    allSessions.map(async (s) => {
      try {
        const data = await api<{ recordings: RecordingView[] }>(
          cookies,
          `/v1/recordings/sessions/${s.sessionId}/playback`
        );
        if (data.recordings?.length) {
          recordingsBySession[s.sessionId] = data.recordings;
        }
      } catch {
        // Not available — not an error.
      }
    })
  );

  // Attendance + completion per class — best-effort; absent maps just hide those
  // lines. Fetched together since both decorate the same course cards.
  const progressByClass: Record<string, ClassProgress> = {};
  const completionByClass: Record<string, ClassCompletion> = {};
  await Promise.all([
    (async () => {
      try {
        const rows = (await api<{ progress: ClassProgress[] }>(cookies, "/v1/me/progress")).progress ?? [];
        for (const p of rows) progressByClass[p.classId] = p;
      } catch {
        // Not available — not an error.
      }
    })(),
    (async () => {
      try {
        const rows = (await api<CompletionsResponse>(cookies, "/v1/me/completions")).completions ?? [];
        for (const c of rows) completionByClass[c.classId] = c;
      } catch {
        // Not available — not an error.
      }
    })(),
  ]);

  const classes: EnrolledClass[] = enrolled.map((c, i) => ({
    ...c,
    sessions: sessionsPerClass[i],
  }));

  return { classes, recordingsBySession, progressByClass, completionByClass };
};
