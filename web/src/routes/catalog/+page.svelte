<script lang="ts">
  import type { PageData } from "./$types";
  let { data }: { data: PageData } = $props();
</script>

<div class="stack">
  <section class="card">
    <h1>Classes</h1>
    {#if data.classes.length === 0}
      <p class="muted">No published classes yet.</p>
    {:else}
      <ul class="list">
        {#each data.classes as c (c.id)}
          <li>
            <strong>{c.title}</strong>
            <p class="muted small">{c.description}</p>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <section class="card">
    <h2>Live &amp; scheduled sessions</h2>
    {#if data.sessionsLocked}
      <p class="muted">
        Verify you're 18+ on <a href="/onboarding">My identity</a> to see session schedules.
      </p>
    {:else if data.sessions.length === 0}
      <p class="muted">No sessions right now.</p>
    {:else}
      <ul class="list">
        {#each data.sessions as s (s.sessionId)}
          <li class="row spread">
            <span><strong>{s.kind}</strong> · {s.status}</span>
            {#if s.status === "live"}
              <a class="btn-link" href={`/room/${s.sessionId}`}>Join</a>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>
