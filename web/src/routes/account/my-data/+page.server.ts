import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { api, ApiError } from "$lib/server/authd";
import { setStepUp, clearStepUp, stepUpCookie } from "$lib/server/session";
import type { DataExport, StepUpChannel } from "$lib/types";

function status(e: unknown): number {
  return e instanceof ApiError ? e.status : 500;
}
function msg(e: unknown): string {
  return e instanceof Error ? e.message : "something went wrong";
}

export const load: PageServerLoad = async ({ locals, cookies }) => {
  if (!locals.me) throw redirect(303, "/signin");

  const grant = stepUpCookie(cookies);
  if (!grant) return { export: null as DataExport | null };

  // We hold a grant — try the protected export. A 403 means it expired or was
  // never valid; drop the stale cookie and fall back to the step-up prompt.
  try {
    const data = await api<DataExport>(cookies, "/v1/me/data-export", {
      headers: { "X-StepUp-Token": grant },
    });
    return { export: data };
  } catch (e) {
    if (e instanceof ApiError && (e.status === 403 || e.status === 401)) {
      clearStepUp(cookies);
      return { export: null as DataExport | null };
    }
    throw e;
  }
};

export const actions: Actions = {
  // Send a step-up code to the user's registered phone/email.
  request: async ({ cookies }) => {
    try {
      const r = await api<StepUpChannel>(cookies, "/v1/me/stepup/request", {
        method: "POST",
        body: {},
      });
      return { sent: true, channel: r.channel, hint: r.hint };
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        return fail(409, {
          error: "Step-up verification needs a phone or email on your account. Add one from My identity.",
        });
      }
      return fail(status(e), { error: msg(e) });
    }
  },

  // Verify the code; on success store the short-lived grant cookie and reload so
  // the load function can fetch the export.
  verify: async ({ cookies, request }) => {
    const code = String((await request.formData()).get("code") ?? "").trim();
    if (!code) return fail(400, { sent: true, error: "Enter the code." });
    try {
      const r = await api<{ token: string; expiresAt: number }>(cookies, "/v1/me/stepup/verify", {
        method: "POST",
        body: { code },
      });
      const maxAge = r.expiresAt - Math.floor(Date.now() / 1000);
      setStepUp(cookies, r.token, maxAge);
    } catch (e) {
      return fail(status(e), { sent: true, error: msg(e) });
    }
    throw redirect(303, "/account/my-data");
  },

  // Explicit "lock again" — drop the grant so the page re-prompts.
  lock: async ({ cookies }) => {
    clearStepUp(cookies);
    throw redirect(303, "/account/my-data");
  },
};
