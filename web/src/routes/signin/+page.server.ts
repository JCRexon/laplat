import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { ApiError, emailRequest, emailVerify } from "$lib/server/authd";

export const load: PageServerLoad = async ({ locals }) => {
  if (locals.me) throw redirect(303, "/catalog");
};

function msg(e: unknown): string {
  return e instanceof Error ? e.message : "something went wrong";
}

export const actions: Actions = {
  // Step 1: send the one-time code (the dev console sender logs it).
  request: async ({ request }) => {
    const data = await request.formData();
    const email = String(data.get("email") ?? "");
    if (!email) return fail(400, { step: "email", error: "Enter your email." });
    try {
      await emailRequest(email);
    } catch (e) {
      return fail(e instanceof ApiError ? e.status : 500, { step: "email", email, error: msg(e) });
    }
    return { step: "code", email };
  },

  // Step 2: verify the code; on success the session cookies are set.
  verify: async ({ request, cookies }) => {
    const data = await request.formData();
    const email = String(data.get("email") ?? "");
    const code = String(data.get("code") ?? "");
    if (!email || !code) return fail(400, { step: "code", email, error: "Enter the code." });
    try {
      await emailVerify(cookies, email, code);
    } catch (e) {
      return fail(e instanceof ApiError ? e.status : 500, { step: "code", email, error: msg(e) });
    }
    throw redirect(303, "/onboarding");
  },
};
