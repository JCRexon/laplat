import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { api, ApiError } from "$lib/server/authd";
import type { UserSummary } from "$lib/types";

export const load: PageServerLoad = async ({ locals, cookies }) => {
  if (!locals.me) throw redirect(303, "/signin");
  if (!locals.me.capabilities.includes("platform_moderator")) {
    throw redirect(303, "/catalog");
  }
  const data = await api<{ users: UserSummary[] }>(cookies, "/v1/moderation/users");
  return { users: data.users ?? [] };
};

function msg(e: unknown): string {
  return e instanceof Error ? e.message : "something went wrong";
}
function status(e: unknown): number {
  return e instanceof ApiError ? e.status : 500;
}

export const actions: Actions = {
  suspend: async ({ cookies, request }) => {
    const userId = String((await request.formData()).get("userId") ?? "");
    if (!userId) return fail(400, { error: "Missing user ID." });
    try {
      await api(cookies, `/v1/moderation/users/${userId}/suspend`, { method: "POST" });
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
  },

  reinstate: async ({ cookies, request }) => {
    const userId = String((await request.formData()).get("userId") ?? "");
    if (!userId) return fail(400, { error: "Missing user ID." });
    try {
      await api(cookies, `/v1/moderation/users/${userId}/reinstate`, { method: "POST" });
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
  },

  grantInstructor: async ({ cookies, request }) => {
    const userId = String((await request.formData()).get("userId") ?? "");
    if (!userId) return fail(400, { error: "Missing user ID." });
    try {
      await api(cookies, `/v1/moderation/users/${userId}/instructor`, { method: "POST" });
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
  },

  revokeInstructor: async ({ cookies, request }) => {
    const userId = String((await request.formData()).get("userId") ?? "");
    if (!userId) return fail(400, { error: "Missing user ID." });
    try {
      await api(cookies, `/v1/moderation/users/${userId}/instructor`, { method: "DELETE" });
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
  },
};
