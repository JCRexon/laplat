import { getMe } from "$lib/server/authd";
import type { LayoutServerLoad } from "./$types";

// Resolve the user freshly here (from the current cookies) so a tier climb that
// re-mints the token mid-action shows immediately on the post-action re-render.
// hooks resolves locals.me once per request (before any action), so it would be
// stale here; page guards still use locals.me for signed-in-ness, which a climb
// never changes.
export const load: LayoutServerLoad = async ({ cookies }) => {
  return { me: await getMe(cookies) };
};
