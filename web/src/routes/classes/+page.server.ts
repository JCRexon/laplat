import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { api, ApiError } from "$lib/server/authd";
import type { ClassView, SessionSummary } from "$lib/types";

export interface ClassWithSessions extends ClassView {
  sessions: SessionSummary[];
}

export const load: PageServerLoad = async ({ locals, cookies }) => {
  if (!locals.me) throw redirect(303, "/signin");
  if (!locals.me.capabilities.includes("can_instruct")) {
    throw redirect(303, "/catalog");
  }
  const data = await api<{ classes: ClassView[] }>(cookies, "/v1/classes");
  const classes = data.classes ?? [];

  const sessionsPerClass = await Promise.all(
    classes.map(c =>
      api<{ sessions: SessionSummary[] }>(cookies, `/v1/sessions?classId=${c.id}`)
        .then(r => r.sessions ?? [])
        .catch(() => [] as SessionSummary[])
    )
  );

  return {
    classes: classes.map((c, i) => ({
      ...c,
      sessions: sessionsPerClass[i],
    })) as ClassWithSessions[],
  };
};

function msg(e: unknown): string {
  return e instanceof Error ? e.message : "something went wrong";
}
function status(e: unknown): number {
  return e instanceof ApiError ? e.status : 500;
}

export const actions: Actions = {
  create: async ({ cookies, request }) => {
    const fd = await request.formData();
    const title = String(fd.get("title") ?? "").trim();
    const description = String(fd.get("description") ?? "").trim();
    if (!title) return fail(400, { error: "Title is required." });
    try {
      await api<ClassView>(cookies, "/v1/classes", {
        method: "POST",
        body: { title, description },
      });
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
  },

  setStatus: async ({ cookies, request }) => {
    const fd = await request.formData();
    const classId = String(fd.get("classId") ?? "");
    const newStatus = String(fd.get("status") ?? "");
    if (!classId || !newStatus) return fail(400, { error: "Missing parameters." });
    try {
      await api(cookies, `/v1/classes/${classId}/status`, {
        method: "POST",
        body: { status: newStatus },
      });
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
  },

  createSession: async ({ cookies, request }) => {
    const fd = await request.formData();
    const classId = String(fd.get("classId") ?? "");
    const scheduledStart = String(fd.get("scheduledStart") ?? "").trim();
    if (!classId) return fail(400, { error: "Missing class ID." });
    const body: Record<string, unknown> = { kind: "class", classId };
    if (scheduledStart) {
      body.scheduledStart = new Date(scheduledStart).toISOString();
    }
    try {
      await api(cookies, "/v1/sessions", { method: "POST", body });
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
  },

  startSession: async ({ cookies, request }) => {
    const fd = await request.formData();
    const sessionId = String(fd.get("sessionId") ?? "");
    if (!sessionId) return fail(400, { error: "Missing session ID." });
    try {
      await api(cookies, `/v1/sessions/${sessionId}/start`, { method: "POST" });
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
  },

  endSession: async ({ cookies, request }) => {
    const fd = await request.formData();
    const sessionId = String(fd.get("sessionId") ?? "");
    if (!sessionId) return fail(400, { error: "Missing session ID." });
    try {
      await api(cookies, `/v1/sessions/${sessionId}/end`, { method: "POST" });
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
  },
};
