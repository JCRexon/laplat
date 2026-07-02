<script lang="ts">
  import type { RecordingView } from "$lib/types";

  let { recordings }: { recordings: RecordingView[] } = $props();

  // Snapshot the URL at click time rather than binding to page data: the
  // pages that host this component poll-refresh their loads, which rotates
  // the short-lived playback token — a reactive src would restart an
  // in-flight video on every poll tick.
  let openId = $state<string | null>(null);
  let openUrl = $state<string | null>(null);

  const playable = $derived(recordings.filter((r) => r.playbackUrl));

  function toggle(rec: RecordingView) {
    if (openId === rec.id) {
      openId = null;
      openUrl = null;
    } else {
      openId = rec.id;
      openUrl = rec.playbackUrl ?? null;
    }
  }

  function duration(rec: RecordingView): string {
    if (!rec.endedAt) return "";
    const secs = rec.endedAt - rec.startedAt;
    return ` · ${Math.floor(secs / 60)}m ${secs % 60}s`;
  }
</script>

{#if playable.length > 0}
  <div class="rec-block">
    <div class="rec-actions">
      {#each playable as rec, i (rec.id)}
        <button
          type="button"
          class="watch-btn"
          class:open={openId === rec.id}
          onclick={() => toggle(rec)}
        >
          {#if openId === rec.id}
            Hide recording
          {:else}
            ▶ {playable.length > 1 ? `Watch part ${i + 1}` : "Watch recording"}{duration(rec)}
          {/if}
        </button>
      {/each}
    </div>
    {#if openUrl}
      <!-- svelte-ignore a11y_media_has_caption -->
      <video class="player" src={openUrl} controls autoplay playsinline></video>
    {/if}
  </div>
{/if}

<style>
  .rec-block {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .rec-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .watch-btn {
    padding: 0.3rem 0.75rem;
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 8px;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    box-shadow: none;
    transition: background 0.15s, color 0.15s;
  }
  .watch-btn:hover {
    background: var(--live-soft);
    filter: none;
  }
  .watch-btn:active {
    transform: none;
    box-shadow: none;
  }
  .watch-btn.open {
    background: var(--accent);
    color: #fff;
  }

  .player {
    width: 100%;
    max-height: min(60vh, 480px);
    aspect-ratio: 16 / 9;
    border-radius: 10px;
    background: #000;
  }
</style>
