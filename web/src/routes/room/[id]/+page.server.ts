import { redirect } from "@sveltejs/kit";
import type { PageServerLoad } from "./$types";
import { api, ApiError } from "$lib/server/authd";
import type { JoinGrant } from "$lib/types";

export const load: PageServerLoad = async ({ locals, cookies, params }) => {
  if (!locals.me) throw redirect(303, "/signin");
  try {
    // POST .../join returns the LiveKit grant. (Joining is idempotent — a
    // re-join on reload re-issues the grant.) Requires the phone_verified tier;
    // below it authd returns 403.
    const grant = await api<JoinGrant>(cookies, `/v1/sessions/${params.id}/join`, { method: "POST" });
    return { grant, forbidden: false };
  } catch (e) {
    if (e instanceof ApiError && e.status === 403) return { grant: null, forbidden: true };
    throw e;
  }
};
