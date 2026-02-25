<script lang="ts">
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
    const parts = path.split('/');
    return parts.length > 3 
      ? '.../' + parts.slice(-3).join('/')
      : path;
  }
</script>

<div class="alert-list">
  <h2>🚨 Recent Alerts</h2>

  {#if alerts.length === 0}
    <div class="empty-state">
      <span class="icon">✅</span>
      <p>No threats detected</p>
    </div>
  {:else}
    <div class="alerts">
      {#each alerts as alert (alert.id)}
        <div class="alert-item" class:success={alert.action_success}>
          <div class="alert-header">
            <span class="alert-id">#{alert.id}</span>
            <span class="alert-time">{formatTime(alert.timestamp)}</span>
          </div>
          
          <div class="alert-content">
            <div class="file-path" title={alert.file_path}>
              📄 {formatPath(alert.file_path)}
            </div>
            
            <div class="alert-details">
              <span class="entropy">
                Entropy: <strong>{alert.entropy.toFixed(4)}</strong>
              </span>
              
              {#if alert.process_found}
                <span class="process">
                  👾 {alert.process_name} (PID: {alert.process_pid})
                </span>
              {:else}
                <span class="process unknown">
                  ❓ Process not found
                </span>
              {/if}
            </div>

            <div class="action-status" class:success={alert.action_success}>
              {#if alert.action_success}
                ✅ Process terminated
              {:else if alert.action_taken}
                ⚠️ {alert.action_taken}
              {:else}
                ⚠️ No action taken
              {/if}
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .alert-list {
    background: rgba(255, 255, 255, 0.05);
    border-radius: 16px;
    padding: 1.5rem;
    border: 1px solid rgba(255, 255, 255, 0.1);
    backdrop-filter: blur(10px);
  }

  h2 {
    font-size: 1.1rem;
    color: #888;
    margin-bottom: 1.5rem;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .empty-state {
    text-align: center;
    padding: 3rem;
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
    max-height: 400px;
    overflow-y: auto;
  }

  .alert-item {
    background: rgba(255, 68, 68, 0.1);
    border: 1px solid rgba(255, 68, 68, 0.3);
    border-radius: 12px;
    padding: 1rem;
    animation: slideIn 0.3s ease-out;
  }

  .alert-item.success {
    background: rgba(0, 255, 136, 0.05);
    border-color: rgba(0, 255, 136, 0.3);
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
    margin-bottom: 0.75rem;
    font-size: 0.85rem;
    color: #888;
  }

  .alert-id {
    color: #ff6b6b;
    font-weight: bold;
  }

  .alert-item.success .alert-id {
    color: #00ff88;
  }

  .file-path {
    font-family: monospace;
    color: #00d9ff;
    margin-bottom: 0.5rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .alert-details {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    font-size: 0.9rem;
    margin-bottom: 0.75rem;
  }

  .entropy {
    color: #ffaa00;
  }

  .process {
    color: #ff6b6b;
  }

  .process.unknown {
    color: #888;
  }

  .action-status {
    font-size: 0.85rem;
    padding: 0.5rem;
    background: rgba(255, 170, 0, 0.1);
    border-radius: 6px;
    color: #ffaa00;
  }

  .action-status.success {
    background: rgba(0, 255, 136, 0.1);
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
