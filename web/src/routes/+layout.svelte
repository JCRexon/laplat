<script lang="ts">
  import "../app.css";
  import { TIER_LABEL } from "$lib/tier";
  import type { LayoutData } from "./$types";

  let { data, children }: { data: LayoutData; children: import("svelte").Snippet } = $props();
</script>

<div class="app">
  <header class="topbar">
    <a class="brand" href="/">laplat</a>
    {#if data.me}
      <nav>
        <a href="/dashboard">Dashboard</a>
        <a href="/catalog">Catalog</a>
        {#if data.me.capabilities.includes("can_instruct")}
          <a href="/classes">My classes</a>
        {/if}
        <a href="/onboarding">My identity</a>
        <a href="/account">Account</a>
        {#if data.me.capabilities.includes("platform_moderator")}
          <a href="/admin">Moderation</a>
        {/if}
      </nav>
      <div class="topbar-right">
        <span class="badge tier-{data.me.identityVerification}">
          {TIER_LABEL[data.me.identityVerification]}
        </span>
        <form method="POST" action="/signout">
          <button class="link-btn" type="submit">Sign out</button>
        </form>
      </div>
    {/if}
  </header>
  <main class="content">
    {@render children()}
  </main>
</div>
