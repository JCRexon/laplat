import { invalidateAll } from "$app/navigation";

/**
 * Re-runs the page's load functions every `intervalMs` while the tab is
 * visible, and immediately when the tab becomes visible again — so "Live now"
 * status (and the short-lived playback URLs, LAPLAT_PLAYBACK_TTL = 5m) stay
 * fresh without a manual reload. Returns a cleanup function; call it from
 * onMount so the interval dies with the page.
 */
export function pollWhileVisible(intervalMs = 20000): () => void {
  const tick = () => {
    if (!document.hidden) void invalidateAll();
  };
  const id = setInterval(tick, intervalMs);
  document.addEventListener("visibilitychange", tick);
  return () => {
    clearInterval(id);
    document.removeEventListener("visibilitychange", tick);
  };
}
