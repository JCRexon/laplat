<script lang="ts">
  import { enhance } from "$app/forms";
  import type { PageData, ActionData } from "./$types";

  let { data, form }: { data: PageData; form: ActionData } = $props();

  const STATUS_LABEL: Record<string, string> = {
    draft: "Draft",
    published: "Published",
    archived: "Archived",
  };

  // Next valid transitions for each status.
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

  <!-- Create form -->
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

  .btn-sm {
    padding: 0.25rem 0.65rem;
    font-size: 0.8rem;
    border: 1px solid #d1d5db;
    border-radius: 4px;
    background: #fff;
    cursor: pointer;
    white-space: nowrap;
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
</style>
