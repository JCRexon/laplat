import type { LayoutServerLoad } from "./$types";

// Expose the resolved user to every page (topbar tier badge, guards).
export const load: LayoutServerLoad = async ({ locals }) => {
  return { me: locals.me };
};
