<script lang="ts">
  import { onMount } from "svelte";
  import { Room, RoomEvent, type RemoteTrack } from "livekit-client";
  import type { PageData } from "./$types";

  let { data }: { data: PageData } = $props();

  let stage = $state<HTMLDivElement>();
  let status = $state<"connecting" | "connected" | "error">("connecting");
  let detail = $state("");

  onMount(() => {
    const grant = data.grant;
    if (!grant) return;

    const room = new Room({ adaptiveStream: true, dynacast: true });

    // Attach remote media as participants publish; detach on unsubscribe.
    room.on(RoomEvent.TrackSubscribed, (track: RemoteTrack) => {
      if (track.kind === "video" || track.kind === "audio") {
        const el = track.attach();
        if (track.kind === "video") el.classList.add("tile");
        stage?.appendChild(el);
      }
    });
    room.on(RoomEvent.TrackUnsubscribed, (track: RemoteTrack) => {
      track.detach().forEach((el) => el.remove());
    });
    room.on(RoomEvent.Disconnected, () => {
      status = "error";
      detail = "disconnected";
    });

    (async () => {
      try {
        await room.connect(grant.wsUrl, grant.token);
        await room.localParticipant.enableCameraAndMicrophone();
        // Show our own camera locally.
        for (const pub of room.localParticipant.videoTrackPublications.values()) {
          if (pub.track) {
            const el = pub.track.attach();
            el.classList.add("tile", "local");
            el.muted = true;
            stage?.appendChild(el);
          }
        }
        status = "connected";
      } catch (e) {
        status = "error";
        detail = e instanceof Error ? e.message : "could not connect";
      }
    })();

    return () => {
      room.disconnect();
    };
  });
</script>

{#if data.forbidden}
  <div class="card narrow">
    <h1>Verify to join live</h1>
    <p class="muted">
      Joining a live session needs a verified phone. Add one on
      <a href="/onboarding">My identity</a>.
    </p>
  </div>
{:else}
  <div class="room">
    <div class="room-bar">
      <a href="/catalog" class="link-btn">← Leave</a>
      <span class="muted small">
        {status === "connecting" ? "Connecting…" : status === "connected" ? "Live" : `Error: ${detail}`}
      </span>
    </div>
    <div class="stage" bind:this={stage}></div>
  </div>
{/if}

<style>
  .room {
    position: fixed;
    inset: 0;
    background: #000;
    display: flex;
    flex-direction: column;
  }
  .room-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 1rem;
    background: #0b0f17;
  }
  .stage {
    flex: 1;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 0.5rem;
    padding: 0.5rem;
    overflow: auto;
  }
  :global(.stage .tile) {
    width: 100%;
    height: 100%;
    object-fit: cover;
    border-radius: 8px;
    background: #111;
  }
</style>
