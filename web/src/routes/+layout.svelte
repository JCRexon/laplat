<script lang="ts">
  import "../app.css";
  import { onMount } from "svelte";
  import { TIER_LABEL } from "$lib/tier";
  import type { LayoutData } from "./$types";

  let { data, children }: { data: LayoutData; children: import("svelte").Snippet } = $props();

  // Theme is applied pre-paint by the inline script in app.html; here we just
  // mirror and toggle it. Default is the warm light theme.
  let theme = $state<"light" | "dark">("light");
  onMount(() => {
    theme = document.documentElement.dataset.theme === "dark" ? "dark" : "light";
  });
  function toggleTheme() {
    theme = theme === "dark" ? "light" : "dark";
    if (theme === "dark") document.documentElement.dataset.theme = "dark";
    else delete document.documentElement.dataset.theme;
    try {
      localStorage.setItem("lp-theme", theme);
    } catch (e) {
      // ignore (private mode / disabled storage)
    }
  }
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
        <button
          class="link-btn theme-toggle"
          type="button"
          onclick={toggleTheme}
          aria-label="Toggle light/dark theme"
          title="Toggle theme"
        >
          {theme === "dark" ? "☀" : "☾"}
        </button>
        <form method="POST" action="/signout">
          <button class="link-btn" type="submit">Sign out</button>
        </form>
      </div>
    {:else}
      <div class="topbar-right">
        <button
          class="link-btn theme-toggle"
          type="button"
          onclick={toggleTheme}
          aria-label="Toggle light/dark theme"
          title="Toggle theme"
        >
          {theme === "dark" ? "☀" : "☾"}
        </button>
      </div>
    {/if}
  </header>
  <main class="content">
    {@render children()}
  </main>
</div>
