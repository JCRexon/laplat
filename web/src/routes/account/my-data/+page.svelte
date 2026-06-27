<script lang="ts">
  import { onMount } from "svelte";
  import { enhance } from "$app/forms";
  import type { ActionData, PageData } from "./$types";

  let { data, form }: { data: PageData; form: ActionData } = $props();

  let mounted = $state(false);
  onMount(() => { mounted = true; });

  function fmt(iso: string | null) {
    if (!iso) return "—";
    return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }
  function fmtDate(iso: string | null) {
    if (!iso) return "—";
    return new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });
  }

  // form may carry { sent, channel, hint } after a request, or an error.
  let sent = $derived(Boolean(form && "sent" in form && form.sent));
</script>

<div class="stack">
  <div class="head-row">
    <h1 class="section-title">My data</h1>
    {#if data.export}
      <form method="POST" action="?/lock" use:enhance>
        <button type="submit" class="lock-btn">Lock again</button>
      </form>
    {/if}
  </div>

  {#if !data.export}
    <!-- ─── Step-up gate ──────────────────────────────────────────── -->
    <section class="card gate">
      <h2>Confirm it's you</h2>
      <p class="muted">
        This page shows everything laplat holds about you. For your security we
        need a fresh identity check before showing it — even though you're already
        signed in.
      </p>

      {#if !sent}
        <form method="POST" action="?/request" use:enhance>
          <button type="submit">Send me a verification code</button>
        </form>
      {:else}
        <p class="muted small">
          {#if form && "channel" in form && form.channel === "phone"}
            We sent a code by SMS to <strong>{form.hint}</strong>.
          {:else if form && "hint" in form}
            We sent a code by email to <strong>{form.hint}</strong>.
          {:else}
            We sent you a code.
          {/if}
        </p>
        <form method="POST" action="?/verify" use:enhance class="code-form">
          <input inputmode="numeric" name="code" placeholder="123456" autocomplete="one-time-code" required />
          <button type="submit">Verify &amp; continue</button>
        </form>
        <form method="POST" action="?/request" use:enhance class="resend">
          <button type="submit" class="link-btn">Resend code</button>
        </form>
      {/if}

      {#if form && "error" in form && form.error}
        <p class="error">{form.error}</p>
      {/if}
    </section>
  {:else}
    {@const x = data.export}
    <p class="muted unlocked-note">
      Verified — this view is unlocked for a few minutes. Nothing here is shared
      externally.
    </p>

    <!-- Profile -->
    <section class="card">
      <h2>Profile</h2>
      <dl>
        <dt>Display name</dt><dd>{x.profile.displayName}</dd>
        <dt>Handle</dt><dd>@{x.profile.handle}</dd>
        {#if x.profile.bio}<dt>Bio</dt><dd>{x.profile.bio}</dd>{/if}
        <dt>Language</dt><dd>{x.profile.locale}</dd>
        <dt>Account status</dt><dd>{x.profile.status}</dd>
        <dt>Member since</dt>
        <dd>{#if mounted}{fmtDate(x.profile.createdAt)}{:else}<span class="skel"></span>{/if}</dd>
        <dt>User ID</dt><dd class="mono">{x.profile.userId}</dd>
      </dl>
    </section>

    <!-- Identity -->
    <section class="card">
      <h2>Identity verification</h2>
      <dl>
        <dt>Status</dt><dd>{x.identity.verificationStatus}</dd>
        <dt>Confirmed 18+</dt><dd>{x.identity.isAdult ? "Yes" : "No"}</dd>
        {#if x.identity.verifiedAt}
          <dt>Verified at</dt>
          <dd>{#if mounted}{fmt(x.identity.verifiedAt)}{:else}<span class="skel"></span>{/if}</dd>
        {/if}
        {#if x.identity.retainUntil}
          <dt>Retained until</dt>
          <dd>{#if mounted}{fmtDate(x.identity.retainUntil)}{:else}<span class="skel"></span>{/if}</dd>
        {/if}
      </dl>
      <div class="pii-note muted small">
        <p>Identity documents (Decree 147 / eKYC):</p>
        <ul>
          <li>Full name: {x.identity.fullNameOnFile ? "on file (encrypted)" : "not yet collected"}</li>
          <li>Date of birth: {x.identity.dobOnFile ? "on file (encrypted)" : "not yet collected"}</li>
          <li>Verified email: {x.identity.emailOnFile ? "on file (encrypted)" : "not yet collected"}</li>
        </ul>
        <p>
          These are collected only during ID verification and stored encrypted;
          their values are never displayed here.
        </p>
      </div>
    </section>

    <!-- Login methods -->
    <section class="card">
      <h2>Login methods</h2>
      <dl>
        <dt>Email</dt><dd>{x.loginMethods.email ?? "—"}</dd>
        <dt>Phone</dt><dd>{x.loginMethods.phone ?? "—"}</dd>
        <dt>Social</dt><dd>{x.loginMethods.federated.length ? x.loginMethods.federated.join(", ") : "—"}</dd>
      </dl>
    </section>

    <!-- Enrolments -->
    <section class="card">
      <h2>Enrolled classes</h2>
      {#if x.enrolledClasses.length === 0}
        <p class="muted">None.</p>
      {:else}
        <ul class="plain">
          {#each x.enrolledClasses as c (c.id)}
            <li>{c.title} <span class="muted small">({c.status})</span></li>
          {/each}
        </ul>
      {/if}
    </section>

    <!-- ToS -->
    <section class="card">
      <h2>Agreements</h2>
      {#if x.tosAcceptances.length === 0}
        <p class="muted">None recorded.</p>
      {:else}
        <ul class="plain">
          {#each x.tosAcceptances as t (t.version)}
            <li>
              Terms {t.version}{t.adultAttested ? " · attested 18+" : ""}
              <span class="muted small">
                — {#if mounted}{fmtDate(t.acceptedAt)}{:else}<span class="skel"></span>{/if}
              </span>
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    <!-- Activity summary -->
    <section class="card">
      <h2>Activity</h2>
      <dl>
        <dt>Sessions joined</dt><dd>{x.activity.sessionCount}</dd>
        <dt>Consent decisions</dt><dd>{x.activity.consentCount}</dd>
      </dl>
      <p class="muted small">
        Full session and consent history is on your <a href="/account">account page</a>.
      </p>
    </section>
  {/if}
</div>

<style>
  .head-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  h1 {
    margin: 0;
    font-size: 1.5rem;
    font-weight: 700;
  }

  h2 {
    margin: 0 0 0.75rem;
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

  .gate p {
    margin: 0 0 1rem;
  }

  .code-form {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }
  .code-form input {
    max-width: 10rem;
    margin: 0;
  }

  .resend {
    margin-top: 0.5rem;
  }

  .unlocked-note {
    margin: 0;
    font-size: 0.85rem;
  }

  .lock-btn {
    background: transparent;
    color: var(--muted);
    border: 1px solid var(--line);
    font-size: 0.8rem;
    padding: 0.35rem 0.75rem;
  }

  dl {
    display: grid;
    grid-template-columns: 9rem 1fr;
    gap: 0.4rem 1rem;
    margin: 0;
    font-size: 0.9rem;
  }
  dt {
    color: var(--muted);
    font-size: 0.85rem;
  }
  dd {
    margin: 0;
    word-break: break-word;
  }

  .mono {
    font-family: ui-monospace, monospace;
    font-size: 0.8rem;
  }

  .pii-note {
    margin-top: 1rem;
    padding-top: 0.85rem;
    border-top: 1px solid var(--line);
  }
  .pii-note p { margin: 0 0 0.4rem; }
  .pii-note ul { margin: 0 0 0.4rem; padding-left: 1.1rem; }

  .plain {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .plain > li {
    padding: 0.4rem 0;
    border-top: 1px solid var(--line);
    font-size: 0.9rem;
  }
  .plain > li:first-child {
    border-top: none;
  }

  .skel {
    display: inline-block;
    width: 7rem;
    height: 0.85em;
    border-radius: 4px;
    background: var(--line);
    opacity: 0.4;
    vertical-align: middle;
  }

  .error {
    color: var(--error);
    margin: 0.75rem 0 0;
  }

  a {
    color: var(--accent);
  }
</style>
