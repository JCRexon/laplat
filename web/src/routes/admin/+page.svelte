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
    border-bottom: 1px solid #e5e7eb;
  }

  .mod-table th {
    font-weight: 600;
    color: #6b7280;
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
    background: #d1fae5;
    color: #065f46;
  }

  .s-suspended {
    background: #fee2e2;
    color: #991b1b;
  }

  .s-pending {
    background: #fef3c7;
    color: #92400e;
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
    border-radius: 4px;
    cursor: pointer;
    white-space: nowrap;
  }

  .btn-warn {
    background: #fee2e2;
    color: #991b1b;
    border-color: #fca5a5;
  }

  .btn-warn:hover {
    background: #fca5a5;
  }

  .btn-ok {
    background: #d1fae5;
    color: #065f46;
    border-color: #6ee7b7;
  }

  .btn-ok:hover {
    background: #6ee7b7;
  }
</style>
