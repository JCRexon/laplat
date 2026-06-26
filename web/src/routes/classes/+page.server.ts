import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { api, ApiError } from "$lib/server/authd";
import type { ClassView } from "$lib/types";

export const load: PageServerLoad = async ({ locals, cookies }) => {
  if (!locals.me) throw redirect(303, "/signin");
  if (!locals.me.capabilities.includes("can_instruct")) {
    // Non-instructors see the learner catalog, not this page.
    throw redirect(303, "/catalog");
  }
  const data = await api<{ classes: ClassView[] }>(cookies, "/v1/classes");
  return { classes: data.classes ?? [] };
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
};
