<script lang="ts">
  import { onMount } from "svelte";
  import type { PageData } from "./$types";

  let { data }: { data: PageData } = $props();

  let mounted = $state(false);
  onMount(() => { mounted = true; });

  function fmt(iso: string) {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  }

  function purposeLabel(p: string) {
    if (p === "session_recording") return "Session recording";
    return p;
  }

  function roleLabel(r: string) {
    if (r === "publisher") return "Instructor";
    if (r === "subscriber") return "Participant";
    return r;
  }

  function methodLabel(m: string) {
    if (m === "email") return "Email code";
    if (m === "phone") return "Phone code";
    if (m === "google") return "Google";
    if (m === "apple") return "Apple";
    if (m === "zalo") return "Zalo";
    return m;
  }
</script>

<div class="stack page-narrow">
  <h1 class="section-title">My account</h1>

  <!-- ─── Connected login methods ─────────────────────────────────── -->
  <section class="card">
    <h2>Login methods</h2>
    <p class="muted sub">The ways you can sign in to laplat.</p>

    <div class="factors">
      <div class="factor-row">
        <span class="factor-label">Email</span>
        {#if data.identities.email}
          <span class="factor-value">{data.identities.email}</span>
        {:else}
          <span class="factor-none muted">Not linked</span>
        {/if}
      </div>

      <div class="factor-row">
        <span class="factor-label">Phone</span>
        {#if data.identities.phone}
          <span class="factor-value">{data.identities.phone}</span>
        {:else}
          <span class="factor-none muted">Not linked</span>
        {/if}
      </div>

      <div class="factor-row">
        <span class="factor-label">Social</span>
        {#if data.identities.federated.length}
          <div class="provider-chips">
            {#each data.identities.federated as provider (provider)}
              <span class="provider-chip">{provider}</span>
            {/each}
          </div>
        {:else}
          <span class="factor-none muted">Not linked</span>
        {/if}
      </div>
    </div>

    <p class="muted small mt">
      To add or change a login method, use <a href="/onboarding">My identity</a>.
    </p>
  </section>

  <!-- ─── Login activity ──────────────────────────────────────────── -->
  <section class="card">
    <h2>Recent sign-ins</h2>
    <p class="muted sub">Your most recent account access, newest first.</p>

    {#if data.loginEvents.length === 0}
      <p class="muted">No sign-in activity recorded yet.</p>
    {:else}
      <div class="login-list">
        {#each data.loginEvents as e (e.id)}
          <div class="login-row">
            <span class="method-chip">{methodLabel(e.method)}</span>
            <span class="login-time muted small mono">
              {#if mounted}{fmt(e.createdAt)}{:else}<span class="time-skeleton"></span>{/if}
            </span>
          </div>
        {/each}
      </div>
      <p class="muted small mt">
        Don't recognise a sign-in? Change your login methods from
        <a href="/onboarding">My identity</a>.
      </p>
    {/if}
  </section>

  <!-- ─── Session attendance history ──────────────────────────────── -->
  <section class="card">
    <h2>Session history</h2>
    <p class="muted sub">Every live session you joined, newest first.</p>

    {#if data.sessions.length === 0}
      <p class="muted">No sessions yet — join a live class to see your attendance here.</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Class</th>
              <th>Your role</th>
              <th>Joined</th>
              <th>Duration</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {#each data.sessions as s (s.sessionId)}
              <tr>
                <td>
                  {#if s.classTitle}
                    {s.classTitle}
                  {:else}
                    <span class="muted">1:1 call</span>
                  {/if}
                </td>
                <td><span class="role-chip role-{s.role}">{roleLabel(s.role)}</span></td>
                <td class="mono">
                  {#if mounted}{fmt(s.joinedAt)}{:else}<span class="time-skeleton"></span>{/if}
                </td>
                <td class="mono">
                  {#if s.durationMinutes !== null}
                    {s.durationMinutes} min
                  {:else if s.status === "live"}
                    <span class="live-dot">● Live</span>
                  {:else}
                    —
                  {/if}
                </td>
                <td><span class="status-chip s-{s.status}">{s.status}</span></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <!-- ─── Consent history ──────────────────────────────────────────── -->
  <section class="card">
    <h2>Recording consents</h2>
    <p class="muted sub">
      Your recording consent decisions — this is the cryptographically signed
      ledger of what you agreed to and when.
    </p>

    {#if data.consents.length === 0}
      <p class="muted">No consent decisions recorded yet.</p>
    {:else}
      <div class="consent-list">
        {#each data.consents as c (c.id)}
          <div class="consent-row">
            <div class="consent-info">
              <span class="consent-action {c.granted ? 'granted' : 'withdrawn'}">
                {c.granted ? "Granted" : "Withdrawn"}
              </span>
              <span class="consent-purpose">{purposeLabel(c.purpose)}</span>
              <span class="muted small">session {c.sessionId.slice(0, 8)}…</span>
            </div>
            <span class="consent-time muted small mono">
              {#if mounted}{fmt(c.grantedAt)}{:else}<span class="time-skeleton"></span>{/if}
            </span>
          </div>
        {/each}
      </div>
    {/if}
  </section>

  <!-- ─── Data export (right of access) ────────────────────────────── -->
  <section class="card">
    <h2>Download my data</h2>
    <p class="muted sub">
      See everything laplat holds about you — your profile, identity status,
      enrolments, and activity — in one place. For your security this requires a
      fresh identity check.
    </p>
    <a href="/account/my-data" class="cta-btn">View my data →</a>
  </section>
</div>

<style>
  h1 {
    margin: 0 0 1.25rem;
    font-size: 1.5rem;
    font-weight: 700;
  }

  h2 {
    margin: 0 0 0.2rem;
    font-size: 1.05rem;
    font-weight: 600;
  }

  .stack > * + * {
    margin-top: 1.25rem;
  }

  .card {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 1.25rem;
  }

  .sub {
    margin: 0 0 1rem;
    font-size: 0.875rem;
  }

  .mt {
    margin-top: 0.75rem;
  }

  /* Login methods */
  .factors {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .factor-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.55rem 0.75rem;
    border-radius: 8px;
    background: var(--bg, #f9fafb);
    border: 1px solid var(--line);
  }

  .factor-label {
    width: 4rem;
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--muted);
    flex-shrink: 0;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .factor-value {
    font-size: 0.9rem;
  }

  .factor-none {
    font-size: 0.875rem;
    font-style: italic;
  }

  .provider-chips {
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
  }

  .provider-chip {
    padding: 0.15rem 0.55rem;
    border-radius: 9999px;
    background: var(--line);
    color: var(--text);
    font-size: 0.78rem;
    font-weight: 600;
    text-transform: capitalize;
  }

  /* Session history table */
  .table-wrap {
    overflow-x: auto;
    border-radius: 8px;
    border: 1px solid var(--line);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }

  th {
    padding: 0.55rem 0.85rem;
    text-align: left;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    background: var(--bg, #f9fafb);
    border-bottom: 1px solid var(--line);
  }

  td {
    padding: 0.6rem 0.85rem;
    border-bottom: 1px solid var(--line);
    vertical-align: middle;
  }

  tr:last-child td {
    border-bottom: none;
  }

  .mono {
    font-variant-numeric: tabular-nums;
    font-size: 0.82rem;
  }

  .time-skeleton {
    display: inline-block;
    width: 8rem;
    height: 0.85em;
    border-radius: 4px;
    background: var(--line);
    opacity: 0.4;
    vertical-align: middle;
  }

  .role-chip {
    display: inline-block;
    padding: 0.1rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.72rem;
    font-weight: 600;
  }

  .role-publisher {
    background: var(--gold-soft);
    color: var(--gold-ink);
  }

  .role-subscriber {
    background: var(--line);
    color: var(--muted);
  }

  .status-chip {
    display: inline-block;
    padding: 0.1rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.72rem;
    font-weight: 600;
  }

  .s-live {
    background: var(--live-soft);
    color: var(--accent);
  }

  .s-ended {
    background: var(--line);
    color: var(--muted);
  }

  .s-scheduled {
    background: var(--line);
    color: var(--muted);
  }

  .live-dot {
    color: var(--accent);
    font-weight: 600;
  }

  /* Consent history */
  .consent-list {
    display: flex;
    flex-direction: column;
    border: 1px solid var(--line);
    border-radius: 8px;
    overflow: hidden;
  }

  .consent-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.65rem 0.85rem;
    border-bottom: 1px solid var(--line);
  }

  .consent-row:last-child {
    border-bottom: none;
  }

  .consent-info {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    flex: 1;
    min-width: 0;
    flex-wrap: wrap;
  }

  .consent-action {
    display: inline-block;
    padding: 0.1rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.72rem;
    font-weight: 600;
    white-space: nowrap;
  }

  .granted {
    background: var(--success-soft);
    color: var(--success);
  }

  .withdrawn {
    background: var(--live-soft);
    color: var(--error);
  }

  .consent-purpose {
    font-size: 0.875rem;
  }

  .consent-time {
    white-space: nowrap;
    flex-shrink: 0;
    font-variant-numeric: tabular-nums;
  }

  .small {
    font-size: 0.8rem;
  }

  /* Login activity */
  .login-list {
    display: flex;
    flex-direction: column;
    border: 1px solid var(--line);
    border-radius: 8px;
    overflow: hidden;
  }

  .login-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.6rem 0.85rem;
    border-bottom: 1px solid var(--line);
  }

  .login-row:last-child {
    border-bottom: none;
  }

  .method-chip {
    display: inline-block;
    padding: 0.1rem 0.55rem;
    border-radius: 9999px;
    background: var(--live-soft);
    color: var(--accent);
    font-size: 0.75rem;
    font-weight: 600;
  }

  .login-time {
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }

  /* Data export CTA — tactile, matches the global button idiom */
  .cta-btn {
    display: inline-block;
    padding: 0.55rem 1.1rem;
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

  a {
    color: var(--accent);
    text-decoration: underline;
  }
</style>
