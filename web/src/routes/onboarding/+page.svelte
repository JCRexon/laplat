<script lang="ts">
  import { LADDER, TIER_LABEL, TIER_UNLOCKS, meets, nextRung } from "$lib/tier";
  import type { ActionData, PageData } from "./$types";

  let { data, form }: { data: PageData; form: ActionData } = $props();

  let tier = $derived(data.me.identityVerification);
  let next = $derived(nextRung(tier));
  let onPhoneCode = $derived(form?.phoneStep === "code");
</script>

<div class="card">
  <div class="row spread">
    <h1>Your identity</h1>
    <span class="badge tier-{tier}">{TIER_LABEL[tier]}</span>
  </div>
  <p class="muted">Assurance climbs with what you want to do. Each step proves a little more.</p>

  <ol class="ladder">
    {#each LADDER as rung (rung)}
      {@const reached = meets(tier, rung)}
      {@const isNext = next === rung}
      <li class="rung {reached ? 'done' : isNext ? 'next' : ''}">
        <div class="rung-head">
          <span class="check">{reached ? "✓" : isNext ? "→" : "•"}</span>
          <strong>{TIER_LABEL[rung]}</strong>
        </div>
        <p class="muted small">{TIER_UNLOCKS[rung]}</p>

        {#if isNext && rung === "declared"}
          <form method="POST" action="?/attest">
            <button type="submit">I confirm I am 18 or older</button>
          </form>
        {/if}

        {#if isNext && rung === "phone_verified"}
          {#if !onPhoneCode}
            <form method="POST" action="?/phoneRequest" class="subflow">
              <input name="phone" placeholder="+84…" required />
              <button type="submit">Send code</button>
            </form>
          {:else}
            <form method="POST" action="?/phoneVerify" class="subflow">
              <input type="hidden" name="phone" value={form?.phone ?? ""} />
              <input inputmode="numeric" name="code" placeholder="123456" required />
              <button type="submit">Verify phone</button>
            </form>
          {/if}
        {/if}

        {#if isNext && rung === "verified"}
          <form method="POST" action="?/beginVerify" class="subflow">
            <button type="submit">Start ID verification (eKYC)</button>
          </form>
          {#if form?.verifyUrl}
            <p class="muted small">Continue at your eKYC provider: <code>{form.verifyUrl}</code></p>
          {/if}
          <p class="muted small">
            Note: the eKYC provider isn't wired in local dev — this starts the handoff only.
          </p>
        {/if}
      </li>
    {/each}
  </ol>

  {#if tier === "pending"}
    <p class="muted">Your ID verification is under review. You keep your current access meanwhile.</p>
  {/if}

  {#if tier === "verified"}
    <div class="subflow">
      <h2>Teach on laplat</h2>
      {#if data.me.capabilities.includes("can_instruct")}
        <p class="muted">You're an instructor — you can create and host classes.</p>
      {:else}
        <form method="POST" action="?/apply">
          <button type="submit">Become an instructor</button>
        </form>
      {/if}
    </div>
  {/if}

  {#if form?.error}
    <p class="error">{form.error}</p>
  {/if}

  <div class="continue">
    <p class="muted small">
      Finished declaring for now? You can come back any time to verify further and
      unlock more.
    </p>
    <a class="continue-btn" href="/catalog">Continue to the catalog →</a>
  </div>
</div>

<style>
  .continue {
    margin-top: 1.5rem;
    padding-top: 1.25rem;
    border-top: 1px solid var(--line);
  }
  .continue-btn {
    display: inline-block;
    margin-top: 0.5rem;
    padding: 0.55rem 1rem;
    background: var(--accent);
    color: #fff;
    border-radius: 8px;
    text-decoration: none;
    font-weight: 600;
  }
</style>
