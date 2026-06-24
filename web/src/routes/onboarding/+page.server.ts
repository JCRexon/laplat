import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { api, ApiError, remint } from "$lib/server/authd";
import type { VerifyBegin } from "$lib/types";

export const load: PageServerLoad = async ({ locals }) => {
  if (!locals.me) throw redirect(303, "/signin");
  return { me: locals.me };
};

function status(e: unknown): number {
  return e instanceof ApiError ? e.status : 500;
}
function msg(e: unknown): string {
  return e instanceof Error ? e.message : "something went wrong";
}

export const actions: Actions = {
  // none -> declared
  attest: async ({ cookies }) => {
    try {
      await api(cookies, "/v1/identity/tos-accept", { method: "POST", body: { adultAttested: true } });
      await remint(cookies); // pick up the new tier in a fresh token
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
    return { ok: true };
  },

  // declared -> phone_verified (step 1: send code, bound to this account)
  phoneRequest: async ({ cookies, request }) => {
    const phone = String((await request.formData()).get("phone") ?? "");
    if (!phone) return fail(400, { error: "Enter a phone number." });
    try {
      await api(cookies, "/v1/auth/phone/request", { method: "POST", body: { phone } });
    } catch (e) {
      return fail(status(e), { error: msg(e), phone });
    }
    return { phoneStep: "code", phone };
  },

  // declared -> phone_verified (step 2: verify)
  phoneVerify: async ({ cookies, request }) => {
    const data = await request.formData();
    const phone = String(data.get("phone") ?? "");
    const code = String(data.get("code") ?? "");
    if (!phone || !code) return fail(400, { error: "Enter the code.", phoneStep: "code", phone });
    try {
      await api(cookies, "/v1/auth/phone/verify", { method: "POST", body: { phone, code } });
      await remint(cookies);
    } catch (e) {
      return fail(status(e), { error: msg(e), phoneStep: "code", phone });
    }
    return { ok: true };
  },

  // phone_verified -> verified (eKYC handoff; provider not wired in dev)
  beginVerify: async ({ cookies }) => {
    try {
      const r = await api<VerifyBegin>(cookies, "/v1/identity/verify/begin", { method: "POST", body: {} });
      return { verifyUrl: r.redirectUrl ?? null };
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
  },

  // verified -> instructor
  apply: async ({ cookies }) => {
    try {
      await api(cookies, "/v1/instructor/apply", { method: "POST", body: {} });
      await remint(cookies);
    } catch (e) {
      return fail(status(e), { error: msg(e) });
    }
    return { ok: true };
  },
};
