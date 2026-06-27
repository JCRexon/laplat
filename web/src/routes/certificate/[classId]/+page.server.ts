import { redirect } from "@sveltejs/kit";
import type { PageServerLoad } from "./$types";
import { api } from "$lib/server/authd";
import type { CompletionsResponse } from "$lib/types";

export const load: PageServerLoad = async ({ locals, cookies, params }) => {
  if (!locals.me) throw redirect(303, "/signin");

  let data: CompletionsResponse | null = null;
  try {
    data = await api<CompletionsResponse>(cookies, "/v1/me/completions");
  } catch {
    data = null;
  }

  const row = data?.completions.find((c) => c.classId === params.classId);
  // A certificate exists only for a genuinely completed class. Anything else
  // (not enrolled, not finished, endpoint unavailable) shows the "not ready" state.
  if (!data || !row || !row.complete) {
    return { cert: null };
  }

  return {
    cert: {
      learnerName: data.learnerName,
      title: row.title,
      instructorName: row.instructorName,
      completedAt: row.completedAt,
      sessions: row.attendedEnded,
    },
  };
};
