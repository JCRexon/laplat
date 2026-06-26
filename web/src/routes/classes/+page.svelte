<script lang="ts">
  import { enhance } from "$app/forms";
  import type { PageData, ActionData } from "./$types";

  let { data, form }: { data: PageData; form: ActionData } = $props();

  const STATUS_LABEL: Record<string, string> = {
    draft: "Draft",
    published: "Published",
    archived: "Archived",
  };

  const SESSION_STATUS_LABEL: Record<string, string> = {
    scheduled: "Scheduled",
    live: "Live",
    ended: "Ended",
  };

  const TRANSITIONS: Record<string, { label: string; value: string }[]> = {
    draft: [{ label: "Publish", value: "published" }],
    published: [
      { label: "Unpublish", value: "draft" },
      { label: "Archive", value: "archived" },
    ],
    archived: [{ label: "Restore to draft", value: "draft" }],
  };
</script>

<div class="stack">
  <h1>My classes</h1>

  {#if form?.error}
    <div class="form-error">{form.error}</div>
  {/if}

  <!-- Create class form -->
  <details class="create-box">
    <summary>+ New class</summary>
    <form method="POST" action="?/create" use:enhance class="create-form">
      <label>
        Title
        <input name="title" placeholder="e.g. Introduction to Vietnamese grammar" required maxlength="200" />
      </label>
      <label>
        Description
        <textarea name="description" rows="3" placeholder="What will students learn?"></textarea>
      </label>
      <button type="submit">Create draft</button>
    </form>
  </details>

  {#if data.classes.length === 0}
    <p class="muted">No classes yet — create your first one above.</p>
  {:else}
    <div class="class-list">
      {#each data.classes as c (c.id)}
        <div class="class-card status-{c.status}">
          <div class="class-head">
            <span class="class-title">{c.title}</span>
            <span class="badge s-{c.status}">{STATUS_LABEL[c.status] ?? c.status}</span>
          </div>
          {#if c.description}
            <p class="class-desc muted">{c.description}</p>
          {/if}
          <div class="class-actions">
            {#each TRANSITIONS[c.status] ?? [] as t}
              <form method="POST" action="?/setStatus" use:enhance>
                <input type="hidden" name="classId" value={c.id} />
                <input type="hidden" name="status" value={t.value} />
                <button type="submit" class="btn-sm btn-{t.value}">{t.label}</button>
              </form>
            {/each}
          </div>

          <!-- Sessions section -->
          <details class="sessions-box">
            <summary class="sessions-summary">
              Sessions{#if c.sessions.some(s => s.status === "live")} <span class="live-indicator">● Live</span>{/if}
              ({c.sessions.length})
            </summary>

            {#if c.sessions.length > 0}
              <div class="session-list">
                {#each c.sessions as s (s.sessionId)}
                  <div class="session-row">
                    <span class="sess-badge s-sess-{s.status}">{SESSION_STATUS_LABEL[s.status] ?? s.status}</span>
                    {#if s.scheduledStart}
                      <span class="sess-time">{new Date(s.scheduledStart).toLocaleString()}</span>
                    {/if}
                    <div class="sess-actions">
                      {#if s.status === "scheduled"}
                        <form method="POST" action="?/startSession" use:enhance>
                          <input type="hidden" name="sessionId" value={s.sessionId} />
                          <button type="submit" class="btn-sm btn-go-live">Start</button>
                        </form>
                        <a href="/room/{s.sessionId}" class="btn-sm">Enter room</a>
                      {:else if s.status === "live"}
                        <a href="/room/{s.sessionId}" class="btn-sm btn-go-live">Enter room</a>
                        <form method="POST" action="?/endSession" use:enhance>
                          <input type="hidden" name="sessionId" value={s.sessionId} />
                          <button type="submit" class="btn-sm btn-end">End session</button>
                        </form>
                      {/if}
                    </div>
                  </div>
                {/each}
              </div>
            {:else}
              <p class="muted no-sessions">No sessions yet.</p>
            {/if}

            <!-- New session form -->
            <form method="POST" action="?/createSession" use:enhance class="new-session-form">
              <input type="hidden" name="classId" value={c.id} />
              <label class="inline-label">
                Scheduled start (optional)
                <input type="datetime-local" name="scheduledStart" />
              </label>
              <button type="submit" class="btn-sm">+ Schedule session</button>
            </form>
          </details>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .create-box {
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 0.75rem 1rem;
  }

  .create-box summary {
    cursor: pointer;
    font-weight: 600;
    color: var(--accent, #2563eb);
  }

  .create-form {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    margin-top: 1rem;
  }

  .create-form label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.9rem;
    font-weight: 500;
  }

  .create-form input,
  .create-form textarea {
    width: 100%;
    padding: 0.45rem 0.6rem;
    border: 1px solid #d1d5db;
    border-radius: 4px;
    font-size: 0.9rem;
    font-family: inherit;
  }

  .class-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .class-card {
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 0.85rem 1rem;
  }

  .class-card.status-draft {
    border-left: 3px solid #d1d5db;
  }

  .class-card.status-published {
    border-left: 3px solid #34d399;
  }

  .class-card.status-archived {
    border-left: 3px solid #9ca3af;
    opacity: 0.75;
  }

  .class-head {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-wrap: wrap;
  }

  .class-title {
    font-weight: 600;
    flex: 1;
  }

  .class-desc {
    margin: 0.35rem 0 0.6rem;
    font-size: 0.9rem;
  }

  .class-actions {
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
    margin-top: 0.5rem;
  }

  /* Sessions section */
  .sessions-box {
    margin-top: 0.75rem;
    border-top: 1px solid #f3f4f6;
    padding-top: 0.6rem;
  }

  .sessions-summary {
    cursor: pointer;
    font-size: 0.85rem;
    font-weight: 600;
    color: #6b7280;
    list-style: none;
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .sessions-summary::-webkit-details-marker {
    display: none;
  }

  .sessions-summary::before {
    content: "▶";
    font-size: 0.65rem;
    transition: transform 0.15s;
  }

  details[open] .sessions-summary::before {
    transform: rotate(90deg);
  }

  .live-indicator {
    color: #059669;
    font-size: 0.75rem;
    font-weight: 600;
  }

  .session-list {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    margin: 0.6rem 0;
  }

  .session-row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    flex-wrap: wrap;
    padding: 0.4rem 0.5rem;
    background: #f9fafb;
    border-radius: 6px;
    font-size: 0.85rem;
  }

  .sess-time {
    color: #6b7280;
    flex: 1;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .sess-actions {
    display: flex;
    gap: 0.35rem;
    align-items: center;
  }

  .no-sessions {
    font-size: 0.85rem;
    margin: 0.4rem 0;
  }

  .new-session-form {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-top: 0.5rem;
  }

  .inline-label {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    color: #6b7280;
  }

  .inline-label input {
    padding: 0.2rem 0.4rem;
    border: 1px solid #d1d5db;
    border-radius: 4px;
    font-size: 0.8rem;
    font-family: inherit;
  }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
  }

  .s-draft {
    background: #f3f4f6;
    color: #374151;
  }

  .s-published {
    background: #d1fae5;
    color: #065f46;
  }

  .s-archived {
    background: #f3f4f6;
    color: #6b7280;
  }

  .sess-badge {
    display: inline-block;
    padding: 0.1rem 0.45rem;
    border-radius: 9999px;
    font-size: 0.7rem;
    font-weight: 600;
    white-space: nowrap;
  }

  .s-sess-scheduled {
    background: #e0f2fe;
    color: #0369a1;
  }

  .s-sess-live {
    background: #d1fae5;
    color: #065f46;
  }

  .s-sess-ended {
    background: #f3f4f6;
    color: #9ca3af;
  }

  /* Buttons */
  .btn-sm {
    padding: 0.25rem 0.65rem;
    font-size: 0.8rem;
    border: 1px solid #d1d5db;
    border-radius: 4px;
    background: #fff;
    cursor: pointer;
    white-space: nowrap;
    text-decoration: none;
    color: inherit;
    display: inline-flex;
    align-items: center;
  }

  .btn-published {
    background: #d1fae5;
    color: #065f46;
    border-color: #6ee7b7;
  }

  .btn-published:hover {
    background: #6ee7b7;
  }

  .btn-draft {
    background: #f9fafb;
    color: #374151;
  }

  .btn-draft:hover {
    background: #e5e7eb;
  }

  .btn-archived {
    background: #f3f4f6;
    color: #6b7280;
  }

  .btn-archived:hover {
    background: #e5e7eb;
  }

  .btn-go-live {
    background: #d1fae5;
    color: #065f46;
    border-color: #6ee7b7;
  }

  .btn-go-live:hover {
    background: #6ee7b7;
  }

  .btn-end {
    background: #fee2e2;
    color: #991b1b;
    border-color: #fca5a5;
  }

  .btn-end:hover {
    background: #fca5a5;
  }
</style>
