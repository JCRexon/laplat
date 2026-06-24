<script lang="ts">
  import type { ActionData } from "./$types";

  let { form }: { form: ActionData } = $props();
  // The verify step is active once the code has been sent.
  let onCode = $derived(form?.step === "code");
  let email = $derived(form?.email ?? "");
</script>

<div class="card narrow">
  <h1>Sign in</h1>
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

  {#if form?.error}
    <p class="error">{form.error}</p>
  {/if}
</div>
