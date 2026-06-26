<script lang="ts">
  import type { PageData } from "./$types";
  let { data }: { data: PageData } = $props();

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
  <h1>My courses</h1>

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

        <div class="course-card {liveSessions.length ? 'has-live' : ''}">
          <div class="course-head">
            <div class="course-title-row">
              <h2 class="course-title">{c.title}</h2>
              {#if liveSessions.length}
                <span class="live-chip">● Live now</span>
              {/if}
            </div>
            {#if c.description}
              <p class="course-desc muted">{c.description}</p>
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
                      <span class="sess-label">{formatTime(s.scheduledStart)}</span>
                    {:else}
                      <span class="sess-label muted">Time TBC</span>
                    {/if}
                  </div>
                </div>
              {/each}

              <!-- Ended sessions with recordings -->
              {#each endedWithRecs as s (s.sessionId)}
                {@const recs = data.recordingsBySession[s.sessionId] ?? []}
                <div class="session-row">
                  <div class="session-info">
                    <span class="sess-badge s-ended">{statusLabel(s.status)}</span>
                    <span class="sess-label muted">
                      {recs.length} recording{recs.length > 1 ? "s" : ""}
                    </span>
                  </div>
                  <div class="watch-links">
                    {#each recs as rec (rec.id)}
                      {#if rec.playbackUrl}
                        <a href={rec.playbackUrl} class="watch-btn" target="_blank" rel="noopener">
                          Watch
                        </a>
                      {/if}
                    {/each}
                  </div>
                </div>
              {/each}
            </div>
          {/if}

          <div class="course-foot">
            <a href="/catalog" class="text-link">View in catalog</a>
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
    border-radius: 12px;
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
    background: var(--accent, #2563eb);
    color: #fff;
    border-radius: 8px;
    font-size: 0.9rem;
    font-weight: 600;
    text-decoration: none;
    transition: opacity 0.15s;
  }
  .cta-btn:hover {
    opacity: 0.85;
  }

  /* Course list */
  .course-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .course-card {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 12px;
    overflow: hidden;
    transition: border-color 0.15s;
  }

  .course-card.has-live {
    border-color: #34d399;
    box-shadow: 0 0 0 3px rgba(52, 211, 153, 0.12);
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
    background: rgba(52, 211, 153, 0.18);
    color: #059669;
    white-space: nowrap;
  }

  .course-desc {
    margin: 0;
    font-size: 0.875rem;
    line-height: 1.5;
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

  .session-row:last-child {
    border-bottom: none;
  }

  .session-live {
    background: rgba(52, 211, 153, 0.05);
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

  .watch-links {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    flex-shrink: 0;
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
    background: rgba(52, 211, 153, 0.18);
    color: #059669;
  }

  .s-scheduled {
    background: rgba(99, 102, 241, 0.12);
    color: #6366f1;
  }

  .s-ended {
    background: #f3f4f6;
    color: #9ca3af;
  }

  /* Buttons */
  .join-btn {
    flex-shrink: 0;
    padding: 0.35rem 0.85rem;
    background: var(--accent, #2563eb);
    color: #fff;
    border-radius: 8px;
    font-size: 0.85rem;
    font-weight: 600;
    text-decoration: none;
    transition: opacity 0.15s;
  }
  .join-btn:hover {
    opacity: 0.85;
  }

  .watch-btn {
    flex-shrink: 0;
    padding: 0.3rem 0.75rem;
    background: transparent;
    color: var(--accent, #2563eb);
    border: 1px solid var(--accent, #2563eb);
    border-radius: 8px;
    font-size: 0.8rem;
    font-weight: 600;
    text-decoration: none;
    transition: opacity 0.15s;
  }
  .watch-btn:hover {
    opacity: 0.8;
  }

  /* Footer */
  .course-foot {
    padding: 0.6rem 1.25rem;
    border-top: 1px solid var(--line);
    background: var(--bg, #f9fafb);
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
</style>
