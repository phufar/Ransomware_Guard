<script lang="ts">
  import { onMount } from "svelte";
  import {
    FileText,
    RefreshCw,
    Clock,
    AlertTriangle,
    CheckCircle2,
    Snowflake,
    Skull,
    RotateCcw,
    Eye,
    ShieldAlert,
  } from "lucide-svelte";

  interface DetectionEvent {
    what: string;
    who: { pid: number | null; process: string };
    when: string;
    where: string | null;
    decision: string;
    entropy?: number;
    base64_encoded?: boolean;
    details?: any;
  }

  let events: DetectionEvent[] = [];
  let loading = false;
  let filterWhat = "";
  let searchQuery = "";

  const EVENT_TYPES = [
    { value: "", label: "All" },
    { value: "WRITE_DETECTED", label: "Write Detected" },
    { value: "PROCESS_FROZEN", label: "Process Frozen" },
    { value: "FILE_SAFE", label: "File Safe" },
    { value: "THREAT_DETECTED", label: "Threat Detected" },
    { value: "PROCESS_KILLED", label: "Process Killed" },
    { value: "FILE_RESTORED", label: "File Restored" },
  ];

  function getEventIcon(what: string) {
    switch (what) {
      case "WRITE_DETECTED":
        return Eye;
      case "PROCESS_FROZEN":
        return Snowflake;
      case "FILE_SAFE":
        return CheckCircle2;
      case "THREAT_DETECTED":
        return ShieldAlert;
      case "PROCESS_KILLED":
        return Skull;
      case "FILE_RESTORED":
        return RotateCcw;
      default:
        return AlertTriangle;
    }
  }

  function getEventColor(what: string): string {
    switch (what) {
      case "WRITE_DETECTED":
        return "#888";
      case "PROCESS_FROZEN":
        return "#ffaa00";
      case "FILE_SAFE":
        return "#00ff88";
      case "THREAT_DETECTED":
        return "#ff4444";
      case "PROCESS_KILLED":
        return "#ff6666";
      case "FILE_RESTORED":
        return "#4da6ff";
      default:
        return "#888";
    }
  }

  function getDecisionClass(decision: string): string {
    switch (decision) {
      case "safe":
        return "safe";
      case "threat":
      case "killed":
        return "threat";
      case "frozen":
        return "frozen";
      case "restored":
        return "restored";
      case "analyzing":
        return "analyzing";
      default:
        return "normal";
    }
  }

  function formatPath(path: string | null): string {
    if (!path) return "—";
    const parts = path.split("/");
    return parts.length > 3 ? ".../" + parts.slice(-3).join("/") : path;
  }

  $: filteredEvents = events.filter((e) => {
    if (filterWhat && e.what !== filterWhat) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      e.what.toLowerCase().includes(q) ||
      (e.who.process && e.who.process.toLowerCase().includes(q)) ||
      (e.who.pid && String(e.who.pid).includes(q)) ||
      (e.where && e.where.toLowerCase().includes(q)) ||
      (e.decision && e.decision.toLowerCase().includes(q))
    );
  });

  async function fetchEvents() {
    loading = true;
    try {
      const res = await fetch("/api/events?limit=500");
      events = await res.json();
    } catch (e) {
      console.error("Failed to fetch events:", e);
    }
    loading = false;
  }

  onMount(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  });
</script>

<div class="event-view">
  <section>
    <div class="section-header">
      <h2 style="display: flex; align-items: center; gap: 0.5rem;">
        <FileText size={18} /> Detection Event Log
      </h2>
      <div class="controls-row">
        <select class="filter-select" bind:value={filterWhat}>
          {#each EVENT_TYPES as type}
            <option value={type.value}>{type.label}</option>
          {/each}
        </select>
        <input
          type="text"
          class="search-input"
          placeholder="Search events..."
          bind:value={searchQuery}
        />
        <button
          class="refresh-btn"
          on:click={fetchEvents}
          disabled={loading}
          style="display: flex; align-items: center; gap: 0.5rem;"
        >
          {#if loading}
            <Clock size={16} />
          {:else}
            <RefreshCw size={16} />
          {/if}
          Refresh
        </button>
      </div>
    </div>

    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>What</th>
            <th>Who</th>
            <th>When</th>
            <th>Where</th>
            <th>Decision</th>
            <th>Entropy</th>
          </tr>
        </thead>
        <tbody>
          {#if filteredEvents.length === 0}
            <tr>
              <td colspan="6" class="empty"
                >{loading ? "Loading..." : "No events found"}</td
              >
            </tr>
          {:else}
            {#each filteredEvents as event}
              <tr
                class:threat-row={event.decision === "threat" ||
                  event.decision === "killed"}
                class:safe-row={event.decision === "safe"}
                class:frozen-row={event.decision === "frozen"}
                class:restored-row={event.decision === "restored"}
              >
                <td>
                  <span
                    class="what-label"
                    style="color: {getEventColor(event.what)}"
                  >
                    <svelte:component
                      this={getEventIcon(event.what)}
                      size={14}
                    />
                    {event.what.replace(/_/g, " ")}
                  </span>
                </td>
                <td>
                  {#if event.who.pid}
                    <span class="pid">{event.who.pid}</span>
                    <span class="process-name">{event.who.process}</span>
                  {:else}
                    <span class="no-data">—</span>
                  {/if}
                </td>
                <td class="time">{event.when}</td>
                <td class="filepath" title={event.where || ""}>
                  {formatPath(event.where)}
                </td>
                <td>
                  <span class="badge {getDecisionClass(event.decision)}">
                    {event.decision.toUpperCase()}
                  </span>
                </td>
                <td>
                  {#if event.entropy != null}
                    <span class="entropy" class:high={event.entropy >= 7.5}>
                      {event.entropy.toFixed(4)}
                    </span>

                    {#if event.base64_encoded}
                      <span class="badge b64">B64</span>
                    {/if}
                  {:else}
                    <span class="no-data">—</span>
                  {/if}
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
    <div class="table-footer">
      <span>Showing {filteredEvents.length} of {events.length} events</span>
    </div>
  </section>
</div>

<style>
  .event-view {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
    flex: 1;
    min-height: 0;
  }

  section {
    background: rgba(0, 0, 0, 0.4);
    border-radius: 12px;
    padding: 1.5rem;
    border: 1px solid rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(10px);
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
  }

  h2 {
    font-size: 1.1rem;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin: 0;
  }

  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.25rem;
    flex-wrap: wrap;
    gap: 1rem;
  }

  .controls-row {
    display: flex;
    gap: 0.75rem;
    align-items: center;
  }

  .filter-select {
    padding: 0.5rem 1rem;
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(0, 0, 0, 0.3);
    color: #fff;
    font-size: 0.9rem;
    cursor: pointer;
  }

  .filter-select:focus {
    outline: none;
    border-color: #00d9ff;
    box-shadow: 0 0 10px rgba(0, 217, 255, 0.3);
  }

  .search-input {
    padding: 0.5rem 1rem;
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(0, 0, 0, 0.3);
    color: #fff;
    font-size: 0.9rem;
    width: 220px;
  }

  .search-input:focus {
    outline: none;
    border-color: #00d9ff;
    box-shadow: 0 0 10px rgba(0, 217, 255, 0.3);
  }

  .refresh-btn {
    padding: 0.5rem 1rem;
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(0, 217, 255, 0.1);
    color: #ffffff;
    cursor: pointer;
    font-size: 0.9rem;
    transition: all 0.2s;
  }

  .refresh-btn:hover:not(:disabled) {
    background: rgba(0, 217, 255, 0.2);
    transform: translateY(-1px);
  }

  .refresh-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  /* Table */
  .table-wrapper {
    overflow-x: auto;
    flex: 1;
    overflow-y: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
  }

  thead {
    position: sticky;
    top: 0;
    z-index: 1;
  }

  th {
    background: #0a0a0a;
    padding: 0.7rem 0.75rem;
    text-align: left;
    color: #888;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 0.78rem;
    white-space: nowrap;
    border-bottom: 2px solid rgba(255, 255, 255, 0.1);
  }

  td {
    padding: 0.55rem 0.75rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    white-space: nowrap;
  }

  tr {
    transition: background 0.15s;
  }

  tbody tr:hover {
    background: rgba(255, 255, 255, 0.04);
  }

  .threat-row {
    background: rgba(255, 68, 68, 0.04);
  }

  .safe-row {
    background: rgba(0, 255, 136, 0.02);
  }

  .frozen-row {
    background: rgba(255, 170, 0, 0.03);
  }

  .restored-row {
    background: rgba(0, 150, 255, 0.04);
  }

  /* Cell styles */
  .what-label {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-weight: 500;
    font-size: 0.82rem;
    white-space: nowrap;
  }

  .pid {
    color: #888;
    font-family: monospace;
    margin-right: 0.5rem;
  }

  .process-name {
    color: #00ffcc;
    font-weight: 500;
  }

  .time {
    color: #666;
    font-family: monospace;
    font-size: 0.82rem;
  }

  .filepath {
    color: #aaa;
    font-family: monospace;
    max-width: 250px;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .entropy {
    font-family: monospace;
    color: #ffaa00;
  }

  .entropy.high {
    color: #ff4444;
    font-weight: 600;
  }

  .no-data {
    color: #444;
  }

  .empty {
    text-align: center;
    padding: 2rem;
    color: #888;
  }

  /* Badges */
  .badge {
    padding: 0.2rem 0.6rem;
    border-radius: 12px;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.5px;
  }

  .badge.safe {
    background: rgba(0, 255, 136, 0.15);
    color: #00ff88;
  }

  .badge.threat {
    background: rgba(255, 68, 68, 0.15);
    color: #ff4444;
  }

  .badge.frozen {
    background: rgba(255, 170, 0, 0.15);
    color: #ffaa00;
  }

  .badge.restored {
    background: rgba(0, 150, 255, 0.15);
    color: #4da6ff;
  }

  .badge.analyzing {
    background: rgba(255, 255, 255, 0.08);
    color: #888;
  }

  .badge.normal {
    background: rgba(255, 255, 255, 0.08);
    color: #888;
  }

  .badge.b64 {
    background: rgba(180, 0, 255, 0.15);
    color: #cc66ff;
    margin-left: 0.3rem;
  }

  .table-footer {
    margin-top: 0.75rem;
    font-size: 0.8rem;
    color: #666;
    text-align: right;
  }

  /* Scrollbar */
  .table-wrapper::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }

  .table-wrapper::-webkit-scrollbar-track {
    background: rgba(255, 255, 255, 0.05);
    border-radius: 3px;
  }

  .table-wrapper::-webkit-scrollbar-thumb {
    background: rgba(255, 255, 255, 0.2);
    border-radius: 3px;
  }
</style>
