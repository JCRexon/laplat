<script lang="ts">
  import { onMount } from "svelte";
  import RecordingPlayback from "$lib/components/RecordingPlayback.svelte";
  import { pollWhileVisible } from "$lib/poll";
  import type { PageData } from "./$types";
  let { data }: { data: PageData } = $props();

  // Scheduled times are shown in the viewer's locale + timezone. That can only
  // be done on the client: formatting during SSR would use the server's
  // timezone, so the markup would differ on hydration. Gate the formatted time
  // behind `mounted` so server and first client render agree (both show the
  // placeholder), then the real local time fills in after mount.
  let mounted = $state(false);
  onMount(() => {
    mounted = true;
    // Live status changes while the page is open — poll so "Live now" (and
    // the short-lived playback URLs) appear without a manual reload.
    return pollWhileVisible();
  });

  function statusLabel(status: string) {
    if (status === "live") return "● Live now";
    if (status === "ended") return "Ended";
    return "Scheduled";
  }

  function formatTime(iso: string) {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  }
</script>

<div class="stack">
  <h1 class="section-title">My courses</h1>

  {#if data.classes.length === 0}
    <div class="empty-state">
      <p class="muted">You haven't enrolled in any classes yet.</p>
      <a href="/catalog" class="cta-btn">Browse the catalog →</a>
    </div>
  {:else}
    <div class="course-list">
      {#each data.classes as c (c.id)}
        {@const liveSessions = c.sessions.filter(s => s.status === "live")}
        {@const upcomingSessions = c.sessions.filter(s => s.status === "scheduled")}
        {@const endedWithRecs = c.sessions.filter(s => s.status === "ended" && data.recordingsBySession[s.sessionId]?.length)}
        {@const prog = data.progressByClass[c.id]}
        {@const done = data.completionByClass[c.id]}

        <div class="course-card {liveSessions.length ? 'has-live' : ''}">
          <div class="course-head">
            <div class="course-title-row">
              <h2 class="course-title">{c.title}</h2>
              {#if liveSessions.length}
                <span class="live-chip">● Live now</span>
              {:else if done?.complete}
                <span class="done-chip">✓ Completed</span>
              {/if}
            </div>
            {#if c.description}
              <p class="course-desc muted">{c.description}</p>
            {/if}
            {#if prog && prog.totalSessions > 0}
              {@const pct = Math.round((prog.attended / prog.totalSessions) * 100)}
              <div class="progress">
                <svg class="ring" viewBox="0 0 36 36" width="42" height="42" aria-hidden="true">
                  <circle class="ring-bg" cx="18" cy="18" r="15.5" />
                  <circle
                    class="ring-fg {done?.complete ? 'ring-done' : ''}"
                    cx="18"
                    cy="18"
                    r="15.5"
                    pathLength="100"
                    style="stroke-dasharray: {pct} 100"
                  />
                  <text class="ring-text" x="18" y="18">{pct}%</text>
                </svg>
                <span class="progress-label muted small">
                  Attended {prog.attended} of {prog.totalSessions} session{prog.totalSessions > 1 ? "s" : ""}
                </span>
              </div>
            {/if}
          </div>

          {#if c.sessions.length === 0 && !liveSessions.length}
            <p class="no-sessions muted">No sessions scheduled yet.</p>
          {:else}
            <div class="sessions-section">
              <!-- Live sessions — shown prominently first -->
              {#each liveSessions as s (s.sessionId)}
                <div class="session-row session-live">
                  <div class="session-info">
                    <span class="sess-badge s-live">{statusLabel(s.status)}</span>
                    <span class="sess-label">Session in progress</span>
                  </div>
                  <a href="/room/{s.sessionId}" class="join-btn">Join →</a>
                </div>
              {/each}

              <!-- Upcoming scheduled sessions -->
              {#each upcomingSessions as s (s.sessionId)}
                <div class="session-row">
                  <div class="session-info">
                    <span class="sess-badge s-scheduled">{statusLabel(s.status)}</span>
                    {#if s.scheduledStart}
                      <span class="sess-label">
                        {#if mounted}{formatTime(s.scheduledStart)}{:else}<span class="time-skeleton"></span>{/if}
                      </span>
                    {:else}
                      <span class="sess-label muted">Time TBC</span>
                    {/if}
                  </div>
                </div>
              {/each}

              <!-- Ended sessions with recordings -->
              {#each endedWithRecs as s (s.sessionId)}
                {@const recs = data.recordingsBySession[s.sessionId] ?? []}
                <div class="session-row session-recs">
                  <div class="session-info">
                    <span class="sess-badge s-ended">{statusLabel(s.status)}</span>
                    <span class="sess-label muted">
                      {recs.length} recording{recs.length > 1 ? "s" : ""}
                    </span>
                  </div>
                  <RecordingPlayback recordings={recs} />
                </div>
              {/each}
            </div>
          {/if}

          <div class="course-foot">
            <a href="/catalog" class="text-link">View in catalog</a>
            {#if done?.complete}
              <a href="/certificate/{c.id}" class="cert-link">View certificate →</a>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  h1 {
    margin: 0 0 1.25rem;
    font-size: 1.5rem;
    font-weight: 700;
  }

  .stack > * + * {
    margin-top: 1.5rem;
  }

  /* Empty state */
  .empty-state {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: var(--shadow-1);
    padding: 3rem 2rem;
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
  }

  .cta-btn {
    display: inline-block;
    padding: 0.55rem 1.25rem;
    background: var(--accent);
    color: #fff;
    border-radius: 10px;
    font-size: 0.9rem;
    font-weight: 700;
    text-decoration: none;
    box-shadow: 0 3px 0 var(--accent-press);
    transition: transform 0.05s ease, box-shadow 0.05s ease, filter 0.15s;
  }
  .cta-btn:hover {
    filter: brightness(1.04);
  }
  .cta-btn:active {
    transform: translateY(2px);
    box-shadow: 0 1px 0 var(--accent-press);
  }

  /* Course list — cards flow left-to-right across the wide content column. */
  .course-list {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
    gap: 1rem;
    align-items: start;
  }

  .course-card {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    overflow: hidden;
    box-shadow: var(--shadow-1);
    transition: transform 0.12s ease, box-shadow 0.12s ease, border-color 0.15s;
  }
  .course-card:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-2);
  }

  .course-card.has-live {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--live-soft), var(--shadow-1);
  }

  .course-head {
    padding: 1.25rem 1.25rem 0.75rem;
  }

  .course-title-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-wrap: wrap;
    margin-bottom: 0.35rem;
  }

  .course-title {
    margin: 0;
    font-size: 1.05rem;
    font-weight: 600;
    flex: 1;
  }

  .live-chip {
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 700;
    background: var(--live-soft);
    color: var(--accent);
    white-space: nowrap;
    animation: live-pulse 1.6s ease-in-out infinite;
  }
  @keyframes live-pulse {
    0%, 100% { box-shadow: 0 0 0 0 rgba(218, 37, 29, 0.35); }
    50% { box-shadow: 0 0 0 4px rgba(218, 37, 29, 0); }
  }
  @media (prefers-reduced-motion: reduce) {
    .live-chip { animation: none; }
  }

  .done-chip {
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 700;
    background: var(--gold-soft);
    color: var(--gold-ink);
    white-space: nowrap;
  }

  .course-desc {
    margin: 0;
    font-size: 0.875rem;
    line-height: 1.5;
  }

  /* Attendance progress ring */
  .progress {
    margin-top: 0.85rem;
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  .ring {
    flex-shrink: 0;
    transform: rotate(-90deg);
  }
  .ring-bg {
    fill: none;
    stroke: var(--line);
    stroke-width: 3.5;
  }
  .ring-fg {
    fill: none;
    stroke: var(--accent);
    stroke-width: 3.5;
    stroke-linecap: round;
    transition: stroke-dasharray 0.5s ease;
  }
  .ring-fg.ring-done {
    stroke: var(--gold);
  }
  /* Counter-rotate the centred percentage so it stays upright. */
  .ring-text {
    transform: rotate(90deg);
    transform-origin: 18px 18px;
    fill: var(--text);
    font-size: 9px;
    font-weight: 700;
    text-anchor: middle;
    dominant-baseline: central;
  }

  .progress-label {
    font-size: 0.78rem;
  }

  /* Sessions */
  .sessions-section {
    border-top: 1px solid var(--line);
    display: flex;
    flex-direction: column;
  }

  .no-sessions {
    padding: 0.75rem 1.25rem;
    font-size: 0.875rem;
    margin: 0;
    border-top: 1px solid var(--line);
  }

  .session-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    padding: 0.65rem 1.25rem;
    border-bottom: 1px solid var(--line);
  }

  /* Rows hosting the recording player let it wrap onto its own full row. */
  .session-recs {
    flex-wrap: wrap;
  }

  .session-row:last-child {
    border-bottom: none;
  }

  .session-live {
    background: var(--live-soft);
  }

  .session-info {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    flex: 1;
    min-width: 0;
  }

  .sess-label {
    font-size: 0.875rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* Holds horizontal space for the localized time until it renders on mount,
     so the row doesn't jump when the client-formatted time fills in. */
  .time-skeleton {
    display: inline-block;
    width: 9rem;
    height: 0.9em;
    border-radius: 4px;
    background: var(--line);
    opacity: 0.4;
    vertical-align: middle;
  }

  /* Badges */
  .sess-badge {
    display: inline-block;
    padding: 0.1rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.72rem;
    font-weight: 600;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .s-live {
    background: var(--live-soft);
    color: var(--accent);
  }

  .s-scheduled {
    background: var(--line);
    color: var(--muted);
  }

  .s-ended {
    background: var(--line);
    color: var(--muted);
  }

  /* Tactile "Join" button */
  .join-btn {
    flex-shrink: 0;
    padding: 0.4rem 0.9rem;
    background: var(--accent);
    color: #fff;
    border-radius: 9px;
    font-size: 0.85rem;
    font-weight: 700;
    text-decoration: none;
    box-shadow: 0 3px 0 var(--accent-press);
    transition: transform 0.05s ease, box-shadow 0.05s ease, filter 0.15s;
  }
  .join-btn:hover {
    filter: brightness(1.04);
  }
  .join-btn:active {
    transform: translateY(2px);
    box-shadow: 0 1px 0 var(--accent-press);
  }

  /* Footer */
  .course-foot {
    padding: 0.6rem 1.25rem;
    border-top: 1px solid var(--line);
    background: var(--bg, #f9fafb);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
  }

  .text-link {
    font-size: 0.8rem;
    color: var(--muted);
    text-decoration: none;
  }
  .text-link:hover {
    color: var(--accent, #2563eb);
    text-decoration: underline;
  }

  .cert-link {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--accent, #2563eb);
    text-decoration: none;
  }
  .cert-link:hover {
    text-decoration: underline;
  }
</style>
