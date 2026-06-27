<script lang="ts">
  import type { ActionData, PageData } from "./$types";

  let { data, form }: { data: PageData; form: ActionData } = $props();
  let onCode = $derived(form?.step === "code");
  let email = $derived(form?.email ?? "");
  let oidcError = $derived(form?.error ?? data.oidcError ?? null);
</script>

<div class="card narrow">
  <h1>Sign in</h1>

  <div class="social-btns">
    <a href="/v1/auth/oidc/google/start" class="btn-social">Sign in with Google</a>
    <a href="/v1/auth/oidc/apple/start" class="btn-social">Sign in with Apple</a>
    <a href="/v1/auth/oidc/zalo/start" class="btn-social">Sign in with Zalo</a>
  </div>

  <div class="divider"><span>or</span></div>

  <p class="muted">Sign in with your email — we'll send a one-time code.</p>

  {#if !onCode}
    <form method="POST" action="?/request">
      <input type="email" name="email" placeholder="you@example.com" value={email} required />
      <button type="submit">Send code</button>
    </form>
  {:else}
    <p class="muted small">Code sent to {email} (check authd's console in dev).</p>
    <form method="POST" action="?/verify">
      <input type="hidden" name="email" value={email} />
      <input inputmode="numeric" name="code" placeholder="123456" required />
      <button type="submit">Verify &amp; continue</button>
    </form>
    <form method="POST" action="?/request">
      <input type="hidden" name="email" value={email} />
      <button class="link-btn" type="submit">Resend code</button>
    </form>
  {/if}

  {#if oidcError}
    <p class="error">{oidcError}</p>
  {/if}
</div>

<style>
  .social-btns {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  .btn-social {
    display: block;
    padding: 0.6rem 1rem;
    border: 1px solid #ccc;
    border-radius: 4px;
    text-align: center;
    text-decoration: none;
    color: inherit;
    font-size: 0.95rem;
  }

  .btn-social:hover {
    background: var(--input-bg);
  }

  .divider {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 1rem 0;
    color: #888;
    font-size: 0.85rem;
  }

  .divider::before,
  .divider::after {
    content: "";
    flex: 1;
    border-top: 1px solid #ddd;
  }
</style>
