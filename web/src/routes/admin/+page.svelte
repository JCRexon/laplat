<script lang="ts">
  import { enhance } from "$app/forms";
  import type { PageData, ActionData } from "./$types";

  let { data, form }: { data: PageData; form: ActionData } = $props();
</script>

<div class="stack">
  <h1>Moderation</h1>
  <p class="muted">{data.users.length} user{data.users.length === 1 ? "" : "s"}</p>

  {#if form?.error}
    <div class="form-error">{form.error}</div>
  {/if}

  <div class="mod-table-wrap">
    <table class="mod-table">
      <thead>
        <tr>
          <th>Handle</th>
          <th>Display name</th>
          <th>Status</th>
          <th>Instructor</th>
          <th>Moderator</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each data.users as u (u.id)}
          <tr class="status-{u.status}">
            <td class="mono">{u.handle}</td>
            <td>{u.displayName}</td>
            <td><span class="badge s-{u.status}">{u.status}</span></td>
            <td>{u.canInstruct ? "yes" : "—"}</td>
            <td>{u.isPlatformModerator ? "yes" : "—"}</td>
            <td class="actions">
              {#if u.status === "suspended"}
                <form method="POST" action="?/reinstate" use:enhance>
                  <input type="hidden" name="userId" value={u.id} />
                  <button type="submit" class="btn-sm btn-ok">Reinstate</button>
                </form>
              {:else}
                <form method="POST" action="?/suspend" use:enhance>
                  <input type="hidden" name="userId" value={u.id} />
                  <button type="submit" class="btn-sm btn-warn">Suspend</button>
                </form>
              {/if}

              {#if u.canInstruct}
                <form method="POST" action="?/revokeInstructor" use:enhance>
                  <input type="hidden" name="userId" value={u.id} />
                  <button type="submit" class="btn-sm btn-warn">Revoke instructor</button>
                </form>
              {:else}
                <form method="POST" action="?/grantInstructor" use:enhance>
                  <input type="hidden" name="userId" value={u.id} />
                  <button type="submit" class="btn-sm btn-ok">Grant instructor</button>
                </form>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>

<style>
  .mod-table-wrap {
    overflow-x: auto;
  }

  .mod-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
  }

  .mod-table th,
  .mod-table td {
    padding: 0.5rem 0.75rem;
    text-align: left;
    border-bottom: 1px solid var(--line);
  }

  .mod-table th {
    font-weight: 600;
    color: var(--muted);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .mono {
    font-family: monospace;
  }

  .badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
  }

  .s-active {
    background: var(--success-soft);
    color: var(--success);
  }

  .s-suspended {
    background: var(--live-soft);
    color: var(--error);
  }

  .s-pending {
    background: var(--gold-soft);
    color: var(--gold-ink);
  }

  .actions {
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
  }

  .btn-sm {
    padding: 0.25rem 0.6rem;
    font-size: 0.8rem;
    border: 1px solid transparent;
    border-radius: 6px;
    cursor: pointer;
    white-space: nowrap;
    box-shadow: none;
    font-weight: 600;
  }
  .btn-sm:active {
    transform: none;
    box-shadow: none;
  }

  .btn-warn {
    background: var(--live-soft);
    color: var(--error);
  }
  .btn-warn:hover {
    filter: brightness(0.97);
  }

  .btn-ok {
    background: var(--success-soft);
    color: var(--success);
  }
  .btn-ok:hover {
    filter: brightness(0.97);
  }
</style>
