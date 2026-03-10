<script lang="ts">
  import {
    Bell,
    CheckCircle2,
    FileText,
    Bug,
    HelpCircle,
    AlertTriangle,
  } from "lucide-svelte";
  export let alerts: Array<{
    id: number;
    file_path: string;
    entropy: number;
    timestamp: number;
    process_found: boolean;
    process_name: string | null;
    process_pid: number | null;
    action_taken: string | null;
    action_success: boolean;
  }>;

  function formatTime(timestamp: number): string {
    return new Date(timestamp * 1000).toLocaleTimeString();
  }

  function formatPath(path: string): string {
    const parts = path.split("/");
    return parts.length > 3 ? ".../" + parts.slice(-3).join("/") : path;
  }
</script>

<div class="alert-list">
  <h2 style="display: flex; align-items: center; gap: 0.5rem;">
    <Bell size={18} /> Recent Alerts
  </h2>

  {#if alerts.length === 0}
    <div class="empty-state">
      <span class="icon"><CheckCircle2 size={48} /></span>
      <p>No threats detected</p>
    </div>
  {:else}
    <div class="alerts">
      {#each alerts as alert (alert.id)}
        <div class="alert-item" class:success={alert.action_success}>
          <div class="alert-icon-left">
            {#if alert.action_success}
              <CheckCircle2 size={24} color="#00ff88" />
            {:else}
              <AlertTriangle size={24} color="#ff4444" />
            {/if}
          </div>

          <div class="alert-content-wrapper">
            <div class="alert-header">
              <span class="alert-id">#{alert.id}</span>
              <span class="alert-time">{formatTime(alert.timestamp)}</span>
            </div>

            <div class="alert-content">
              <div class="alert-left">
                <div
                  class="file-path"
                  title={alert.file_path}
                  style="display: flex; align-items: center; gap: 0.5rem;"
                >
                  <FileText size={16} />
                  {formatPath(alert.file_path)}
                </div>
                <div class="alert-details">
                  {#if alert.process_found}
                    <span
                      class="process"
                      style="display: flex; align-items: center; gap: 0.25rem;"
                    >
                      <Bug size={14} />
                      {alert.process_name}
                    </span>
                  {:else}
                    <span
                      class="process unknown"
                      style="display: flex; align-items: center; gap: 0.25rem;"
                    >
                      <HelpCircle size={14} /> Process not found
                    </span>
                  {/if}
                </div>
              </div>

              <div class="alert-right">
                <span class="entropy">
                  Entropy: <strong>{alert.entropy.toFixed(4)}</strong>
                </span>

                {#if alert.process_found}
                  <span class="pid-badge">PID: {alert.process_pid}</span>
                {/if}

                <div
                  class="action-status"
                  class:success={alert.action_success}
                  style="display: flex; align-items: center; gap: 0.25rem;"
                >
                  {#if alert.action_success}
                    <CheckCircle2 size={14} /> Terminated
                  {:else if alert.action_taken}
                    <AlertTriangle size={14} /> {alert.action_taken}
                  {:else}
                    <AlertTriangle size={14} /> No action
                  {/if}
                </div>
              </div>
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .alert-list {
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
    margin-bottom: 1.5rem;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    flex: 1;
    color: #888;
  }

  .empty-state .icon {
    font-size: 3rem;
    display: block;
    margin-bottom: 1rem;
  }

  .alerts {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    flex: 1;
    overflow-y: auto;
  }

  .alert-item {
    background: #0a0a0a;
    border: 1px solid #1a1a1a;
    border-radius: 6px;
    padding: 0.75rem 1rem;
    animation: slideIn 0.3s ease-out;
    display: flex;
    align-items: flex-start;
    gap: 1rem;
  }

  .alert-icon-left {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding-top: 0.25rem;
  }

  .alert-content-wrapper {
    display: flex;
    flex-direction: column;
    flex: 1;
  }

  .alert-item.success {
    border-color: #002200;
  }

  @keyframes slideIn {
    from {
      opacity: 0;
      transform: translateX(-20px);
    }
    to {
      opacity: 1;
      transform: translateX(0);
    }
  }

  .alert-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
    font-size: 0.8rem;
    color: #666;
  }

  .alert-id {
    color: #ff6b6b;
    font-weight: bold;
  }

  .alert-item.success .alert-id {
    color: #00ff88;
  }

  .alert-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
  }

  .alert-left {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    flex: 1;
    min-width: 200px;
  }

  .alert-right {
    display: flex;
    align-items: center;
    gap: 1.25rem;
  }

  .file-path {
    font-family: monospace;
    color: #e0e0e0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .alert-details {
    display: flex;
    gap: 1rem;
    font-size: 0.85rem;
  }

  .entropy {
    color: #ffaa00;
    font-size: 0.85rem;
  }

  .pid-badge {
    background: #222;
    color: #ccc;
    font-family: monospace;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-size: 0.8rem;
    border: 1px solid #444;
  }

  .process {
    color: #ff6b6b;
  }

  .process.unknown {
    color: #666;
  }

  .action-status {
    font-size: 0.8rem;
    padding: 0.3rem 0.6rem;
    background: #221100;
    border: 1px solid #553300;
    border-radius: 4px;
    color: #ffaa00;
    font-weight: 500;
  }

  .action-status.success {
    background: #002211;
    border: 1px solid #005522;
    color: #00ff88;
  }

  /* Scrollbar styling */
  .alerts::-webkit-scrollbar {
    width: 6px;
  }

  .alerts::-webkit-scrollbar-track {
    background: rgba(255, 255, 255, 0.05);
    border-radius: 3px;
  }

  .alerts::-webkit-scrollbar-thumb {
    background: rgba(255, 255, 255, 0.2);
    border-radius: 3px;
  }
</style>
