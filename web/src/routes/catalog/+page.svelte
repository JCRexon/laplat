<script lang="ts">
  import { enhance } from "$app/forms";
  import type { PageData, ActionData } from "./$types";
  let { data, form }: { data: PageData; form: ActionData } = $props();

  function sessionKindLabel(kind: string) {
    return kind === "live" ? "Live" : kind === "group" ? "Group" : kind;
  }

  function statusBadgeClass(status: string) {
    if (status === "live") return "status-live";
    if (status === "ended") return "status-ended";
    return "status-scheduled";
  }

  function statusLabel(status: string) {
    if (status === "live") return "● Live now";
    if (status === "ended") return "Ended";
    return "Scheduled";
  }

  function formatDuration(startedAt: number, endedAt?: number): string {
    if (!endedAt) return "";
    const secs = endedAt - startedAt;
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}m ${s}s`;
  }

  const enrolledSet = $derived(new Set(data.enrolledIds));
</script>

<div class="stack">
  {#if form?.error}
    <div class="form-error">{form.error}</div>
  {/if}

  <!-- Classes section -->
  <section>
    <h1 class="section-title">Classes</h1>
    {#if data.classes.length === 0}
      <div class="empty-state">
        <p class="muted">No published classes yet.</p>
      </div>
    {:else}
      <div class="class-grid">
        {#each data.classes as c (c.id)}
          {@const isEnrolled = enrolledSet.has(c.id)}
          <div class="class-card">
            <div class="class-card-body">
              <h2 class="class-title">{c.title}</h2>
              {#if c.description}
                <p class="class-desc muted">{c.description}</p>
              {/if}
            </div>
            <div class="class-card-foot">
              <span class="status-pill">{c.status}</span>
              {#if isEnrolled}
                <form method="POST" action="?/unenroll" use:enhance>
                  <input type="hidden" name="classId" value={c.id} />
                  <button type="submit" class="enroll-btn enroll-btn--out">Unenroll</button>
                </form>
              {:else}
                <form method="POST" action="?/enroll" use:enhance>
                  <input type="hidden" name="classId" value={c.id} />
                  <button type="submit" class="enroll-btn">Enroll</button>
                </form>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </section>

  <!-- Sessions section -->
  <section>
    <h2 class="section-title section-title-sm">Live &amp; scheduled sessions</h2>
    {#if data.sessionsLocked}
      <div class="locked-notice">
        <span class="lock-icon">🔒</span>
        <span>
          Verify you're 18+ on <a href="/onboarding" class="text-link">My identity</a>
          to see session schedules.
        </span>
      </div>
    {:else if data.sessions.length === 0}
      <div class="empty-state">
        <p class="muted">No sessions right now.</p>
      </div>
    {:else}
      <ul class="session-list">
        {#each data.sessions as s (s.sessionId)}
          {@const recs = data.recordingsBySession[s.sessionId] ?? []}
          <li class="session-row">
            <div class="session-meta">
              <span class="session-kind">{sessionKindLabel(s.kind)}</span>
              <span class="status-dot {statusBadgeClass(s.status)}">
                {statusLabel(s.status)}
              </span>
            </div>
            <div class="session-actions">
              {#if recs.length > 0}
                <span class="rec-badge" title="Recording available">
                  ⏺ {recs.length} recording{recs.length > 1 ? "s" : ""}
                  {#if recs[0].endedAt}
                    · {formatDuration(recs[0].startedAt, recs[0].endedAt)}
                  {/if}
                </span>
                {#each recs as rec (rec.id)}
                  {#if rec.playbackUrl}
                    <a class="watch-btn" href={rec.playbackUrl} target="_blank" rel="noopener">
                      Watch
                    </a>
                  {/if}
                {/each}
              {/if}
              {#if s.status === "live"}
                <a class="join-btn" href={`/room/${s.sessionId}`}>Join →</a>
              {/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>

<style>
  .stack > * + * { margin-top: 2rem; }

  .form-error {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    color: #f87171;
    font-size: 0.875rem;
  }

  .section-title {
    margin: 0 0 1rem;
    font-size: 1.4rem;
    font-weight: 700;
    position: relative;
    padding-bottom: 0.45rem;
  }
  /* Motif: red→gold flag marker under the section heading. */
  .section-title::after {
    content: "";
    position: absolute;
    left: 0;
    bottom: 0;
    width: 2.75rem;
    height: 3px;
    border-radius: 3px;
    background: linear-gradient(90deg, var(--accent) 62%, var(--gold) 62%);
  }
  .section-title-sm {
    font-size: 1.1rem;
  }

  /* Class grid */
  .class-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 1rem;
  }

  .class-card {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    box-shadow: var(--shadow-1);
    transition: transform 0.12s ease, box-shadow 0.12s ease, border-color 0.15s;
  }
  .class-card:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-2);
    border-color: var(--accent);
  }

  .class-card-body {
    padding: 1.25rem 1.25rem 0.75rem;
    flex: 1;
  }
  .class-title {
    margin: 0 0 0.4rem;
    font-size: 1rem;
    font-weight: 600;
  }
  .class-desc {
    margin: 0;
    font-size: 0.85rem;
    line-height: 1.5;
    display: -webkit-box;
    -webkit-line-clamp: 3;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }

  .class-card-foot {
    padding: 0.75rem 1.25rem;
    border-top: 1px solid var(--line);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
  }
  .status-pill {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
  }

  .enroll-btn {
    padding: 0.3rem 0.75rem;
    border-radius: 6px;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    border: 1px solid var(--accent);
    background: var(--accent);
    color: #fff;
    transition: opacity 0.15s;
  }
  .enroll-btn:hover { opacity: 0.85; }
  .enroll-btn--out {
    background: transparent;
    color: var(--muted);
    border-color: var(--line);
  }
  .enroll-btn--out:hover { border-color: var(--muted); }

  /* Empty / locked states */
  .empty-state {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 2rem;
    text-align: center;
  }
  .locked-notice {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 1rem 1.25rem;
    color: var(--muted);
    font-size: 0.9rem;
  }
  .lock-icon { font-size: 1.1rem; }
  .text-link { color: var(--accent); text-decoration: none; font-weight: 600; }
  .text-link:hover { text-decoration: underline; }

  /* Sessions list */
  .session-list {
    list-style: none;
    padding: 0;
    margin: 0;
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 12px;
    overflow: hidden;
  }
  .session-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.9rem 1.25rem;
    border-bottom: 1px solid var(--line);
    gap: 0.75rem;
  }
  .session-row:last-child { border-bottom: none; }

  .session-meta {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex: 1;
    min-width: 0;
  }
  .session-kind {
    font-weight: 600;
    font-size: 0.9rem;
    white-space: nowrap;
  }

  .status-dot {
    font-size: 0.8rem;
    padding: 0.2rem 0.6rem;
    border-radius: 999px;
    white-space: nowrap;
  }
  .status-live {
    background: rgba(34, 197, 94, 0.15);
    color: #4ade80;
  }
  .status-scheduled {
    background: rgba(99, 102, 241, 0.12);
    color: #818cf8;
  }
  .status-ended {
    background: rgba(139, 151, 168, 0.12);
    color: var(--muted);
  }

  .session-actions {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-shrink: 0;
  }

  .rec-badge {
    font-size: 0.78rem;
    color: var(--muted);
    white-space: nowrap;
  }

  .watch-btn {
    flex-shrink: 0;
    padding: 0.3rem 0.75rem;
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 8px;
    font-size: 0.8rem;
    font-weight: 600;
    text-decoration: none;
    transition: opacity 0.15s;
  }
  .watch-btn:hover { opacity: 0.8; }

  .join-btn {
    flex-shrink: 0;
    padding: 0.4rem 0.9rem;
    background: var(--accent);
    color: #fff;
    border-radius: 8px;
    font-size: 0.85rem;
    font-weight: 600;
    text-decoration: none;
    transition: opacity 0.15s;
  }
  .join-btn:hover { opacity: 0.85; }
</style>
