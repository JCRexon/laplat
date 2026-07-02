<script lang="ts">
  import { onMount } from "svelte";
  import type { PageData } from "./$types";

  let { data }: { data: PageData } = $props();

  let mounted = $state(false);
  onMount(() => { mounted = true; });

  function fmtDate(iso: string | null) {
    if (!iso) return "";
    return new Date(iso).toLocaleDateString(undefined, { dateStyle: "long" });
  }

  function print() {
    window.print();
  }
</script>

{#if !data.cert}
  <div class="card notice">
    <h1>Certificate not available</h1>
    <p class="muted">
      A certificate is issued once you've attended every session of a class and
      all of them have finished. This class isn't complete yet.
    </p>
    <a href="/dashboard" class="back">← Back to my courses</a>
  </div>
{:else}
  {@const c = data.cert}
  <div class="cert-actions">
    <a href="/dashboard" class="back">← Back to my courses</a>
    <button onclick={print} class="print-btn">Print / Save as PDF</button>
  </div>

  <div class="certificate">
    <div class="cert-inner">
      <p class="cert-kicker">laplat</p>
      <h1 class="cert-title">Certificate of Completion</h1>
      <p class="cert-lead">This certifies that</p>
      <p class="cert-name">{c.learnerName}</p>
      <p class="cert-lead">has successfully completed</p>
      <p class="cert-course">{c.title}</p>
      <p class="cert-detail">
        {c.sessions} session{c.sessions === 1 ? "" : "s"} attended · instructor {c.instructorName}
      </p>
      <div class="cert-foot">
        <div class="cert-date">
          {#if mounted}{fmtDate(c.completedAt)}{:else}<span class="skel"></span>{/if}
          <span class="cert-foot-label">Date completed</span>
        </div>
        <div class="cert-seal">★</div>
      </div>
    </div>
  </div>
{/if}

<style>
  /* A certificate is a document — keep it at a readable measure even in the
     wide content column. */
  .notice,
  .cert-actions,
  .certificate {
    max-width: 720px;
    margin-inline: auto;
  }

  .notice {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 2rem;
    text-align: center;
  }
  .notice h1 {
    font-size: 1.3rem;
    margin: 0 0 0.5rem;
  }

  .cert-actions {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
  }

  .back {
    color: var(--muted);
    text-decoration: none;
    font-size: 0.85rem;
  }
  .back:hover {
    color: var(--accent);
  }

  .print-btn {
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 0.5rem 1rem;
    font-weight: 600;
    cursor: pointer;
  }

  /* The certificate itself — light, print-friendly surface regardless of theme. */
  .certificate {
    background: #fdfcf7;
    color: #1a1a1a;
    border-radius: 12px;
    padding: 0.75rem;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
  }

  .cert-inner {
    border: 3px double #da251d;
    border-radius: 8px;
    padding: 3rem 2rem;
    text-align: center;
  }

  .cert-kicker {
    margin: 0;
    font-weight: 800;
    letter-spacing: 0.3em;
    text-transform: uppercase;
    font-size: 0.85rem;
    color: #da251d;
  }

  .cert-title {
    margin: 0.5rem 0 2rem;
    font-size: 1.9rem;
    font-weight: 700;
    letter-spacing: 0.02em;
  }

  .cert-lead {
    margin: 0.35rem 0;
    color: #555;
    font-size: 0.95rem;
  }

  .cert-name {
    margin: 0.5rem 0;
    font-size: 2rem;
    font-weight: 700;
    font-style: italic;
    border-bottom: 1px solid #ddd;
    display: inline-block;
    padding: 0 1.5rem 0.4rem;
  }

  .cert-course {
    margin: 0.75rem 0 0.25rem;
    font-size: 1.35rem;
    font-weight: 600;
  }

  .cert-detail {
    margin: 0.25rem 0 0;
    color: #555;
    font-size: 0.9rem;
  }

  .cert-foot {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    margin-top: 3rem;
  }

  .cert-date {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    font-size: 1rem;
    font-weight: 600;
    border-top: 1px solid #999;
    padding-top: 0.35rem;
    min-width: 12rem;
  }

  .cert-foot-label {
    font-size: 0.72rem;
    font-weight: 400;
    color: #777;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  .cert-seal {
    width: 3.5rem;
    height: 3.5rem;
    border-radius: 50%;
    background: #da251d;
    color: #ffcd00;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.6rem;
  }

  .skel {
    display: inline-block;
    width: 8rem;
    height: 1em;
    border-radius: 4px;
    background: #ddd;
    vertical-align: middle;
  }

  /* Print: drop the app chrome and the action bar; show only the certificate. */
  @media print {
    :global(.topbar) {
      display: none !important;
    }
    :global(.content) {
      padding: 0 !important;
      max-width: none !important;
    }
    .cert-actions {
      display: none !important;
    }
    .certificate {
      box-shadow: none;
    }
  }
</style>
