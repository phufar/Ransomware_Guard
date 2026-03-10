<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import SecondaryBar from "./components/SecondaryBar.svelte";
  import AlertList from "./components/AlertList.svelte";
  import ProcessView from "./components/ProcessView.svelte";
  import { LayoutDashboard, Cpu } from "lucide-svelte";

  let activeTab: "dashboard" | "processes" = "dashboard";

  let status: {
    running: boolean;
    watch_path: string | null;
    websocket_clients: number;
  } = { running: false, watch_path: null, websocket_clients: 0 };
  let stats = {
    files_scanned: 0,
    threats_detected: 0,
    processes_terminated: 0,
    alerts_total: 0,
  };
  let alerts: any[] = [];
  let processes: any[] = [];
  let ws: WebSocket | null = null;
  let guardLoading = false;

  // Fetch initial data
  async function fetchStatus() {
    try {
      const res = await fetch("/api/status");
      status = await res.json();
    } catch (e) {
      console.error("Failed to fetch status:", e);
    }
  }

  async function fetchStats() {
    try {
      const res = await fetch("/api/stats");
      stats = await res.json();
    } catch (e) {
      console.error("Failed to fetch stats:", e);
    }
  }

  async function fetchAlerts() {
    try {
      const res = await fetch("/api/alerts");
      alerts = await res.json();
    } catch (e) {
      console.error("Failed to fetch alerts:", e);
    }
  }

  // WebSocket connection
  function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${protocol}//${window.location.host}/ws/alerts`);

    ws.onopen = () => {
      console.log("WebSocket connected");
    };

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);

      if (message.type === "alert") {
        alerts = [message.data, ...alerts].slice(0, 50);
        stats.threats_detected++;
        stats.alerts_total++;
      } else if (message.type === "stats") {
        stats = message.data;
      } else if (message.type === "status") {
        status = { ...status, ...message.data };
      } else if (message.type === "processes") {
        processes = message.data.processes || [];
      }
    };

    ws.onclose = () => {
      console.log("WebSocket disconnected, reconnecting...");
      setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (error) => {
      console.error("WebSocket error:", error);
    };
  }

  // Guard control
  async function startGuard(watchPath: string, entropy: number = 7.5) {
    guardLoading = true;
    try {
      const res = await fetch("/api/guard/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          watch_path: watchPath,
          entropy_threshold: entropy,
        }),
      });
      const data = await res.json();
      if (data.success) {
        status.running = true;
        status.watch_path = watchPath;
      }
      return data;
    } catch (e) {
      console.error("Failed to start guard:", e);
      throw e;
    } finally {
      guardLoading = false;
    }
  }

  async function stopGuard() {
    guardLoading = true;
    try {
      const res = await fetch("/api/guard/stop", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        status.running = false;
      }
      return data;
    } catch (e) {
      console.error("Failed to stop guard:", e);
      throw e;
    } finally {
      guardLoading = false;
    }
  }

  onMount(() => {
    fetchStatus();
    fetchStats();
    fetchAlerts();
    connectWebSocket();

    // Refresh stats every 5 seconds
    const interval = setInterval(() => {
      if (status.running) {
        fetchStats();
      }
    }, 5000);

    return () => clearInterval(interval);
  });

  onDestroy(() => {
    if (ws) ws.close();
  });
</script>

<main>
  <header>
    <h1>Ransomware Guard</h1>
    <div class="header-right">
      <nav class="tabs">
        <button
          class="tab"
          class:active={activeTab === "dashboard"}
          on:click={() => (activeTab = "dashboard")}
        >
          <LayoutDashboard size={16} />
          <span>Dashboard</span>
        </button>
        <button
          class="tab"
          class:active={activeTab === "processes"}
          on:click={() => (activeTab = "processes")}
        >
          <Cpu size={16} />
          <span>Processes</span>
        </button>
      </nav>
    </div>
  </header>

  {#if activeTab === "dashboard"}
    <div class="dashboard">
      <SecondaryBar
        running={status.running}
        loading={guardLoading}
        processesKilled={stats.processes_terminated}
        threatsDetected={stats.threats_detected}
        on:start={(e) => startGuard(e.detail.path, e.detail.entropy)}
        on:stop={() => stopGuard()}
      />

      <AlertList {alerts} />
    </div>
  {:else}
    <ProcessView {processes} guardRunning={status.running} />
  {/if}
</main>

<style>
  :global(*) {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  :global(body) {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen,
      Ubuntu, sans-serif;
    background: #0a0a0a;
    background-image: linear-gradient(
      to bottom,
      #000000 0%,
      #111111 200px,
      #0a0a0a 100%
    );
    min-height: 100vh;
    color: #e0e0e0;
  }

  main {
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem 2rem 1rem 2rem;
    height: 100vh;
    display: flex;
    flex-direction: column;
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    flex-wrap: wrap;
    gap: 1rem;
  }

  h1 {
    font-family: "Jersey 10", sans-serif;
    font-size: 3.5rem;
    font-weight: 400;
    line-height: 1;
    background: linear-gradient(135deg, #ff0000 0%, #ffffff 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin: 0;
  }

  .header-right {
    display: flex;
    align-items: center;
    gap: 1.5rem;
  }

  /* Tabs */
  .tabs {
    display: flex;
    gap: 0.25rem;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 10px;
    padding: 0.25rem;
  }

  .tab {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1.25rem;
    border: none;
    background: transparent;
    color: #888;
    font-size: 0.9rem;
    font-weight: 500;
    cursor: pointer;
    border-radius: 8px;
    transition: all 0.2s;
  }

  .tab:hover {
    color: #ccc;
  }

  .tab.active {
    background: rgba(255, 255, 255, 0.1);
    color: #fff;
  }

  .dashboard {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
    flex: 1;
    min-height: 0;
  }
</style>
