import { redirect } from "@sveltejs/kit";
import type { PageServerLoad } from "./$types";
import { api } from "$lib/server/authd";
import type {
  IdentityFactors,
  SessionHistoryEntry,
  ConsentHistoryEntry,
  LoginEvent,
} from "$lib/types";

export const load: PageServerLoad = async ({ locals, cookies }) => {
  if (!locals.me) throw redirect(303, "/signin");

  const [identities, sessionsData, consentsData, loginData] = await Promise.all([
    api<IdentityFactors>(cookies, "/v1/me/identities").catch(() => null),
    api<{ sessions: SessionHistoryEntry[] }>(cookies, "/v1/me/sessions").catch(() => null),
    api<{ consents: ConsentHistoryEntry[] }>(cookies, "/v1/me/consents").catch(() => null),
    api<{ events: LoginEvent[] }>(cookies, "/v1/me/login-events").catch(() => null),
  ]);

  return {
    identities: identities ?? { email: null, phone: null, federated: [] },
    sessions: sessionsData?.sessions ?? [],
    consents: consentsData?.consents ?? [],
    loginEvents: loginData?.events ?? [],
  };
};
