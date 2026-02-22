<script lang="ts">
  export let status: {
    running: boolean;
    watch_path: string | null;
    websocket_clients: number;
  };
</script>

<div class="status-card">
  <h2>Guard Status</h2>
  
  <div class="status-indicator" class:active={status.running}>
    <div class="pulse"></div>
    <span>{status.running ? 'ACTIVE' : 'INACTIVE'}</span>
  </div>

  <div class="details">
    <div class="detail-item">
      <span class="label">Watching:</span>
      <span class="value">{status.watch_path || 'Not set'}</span>
    </div>
    <div class="detail-item">
      <span class="label">Connected Clients:</span>
      <span class="value">{status.websocket_clients}</span>
    </div>
  </div>
</div>

<style>
  .status-card {
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

  .status-indicator {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1rem;
    background: rgba(255, 0, 0, 0.1);
    border-radius: 12px;
    margin-bottom: 1.5rem;
  }

  .status-indicator.active {
    background: rgba(0, 255, 100, 0.1);
  }

  .pulse {
    width: 16px;
    height: 16px;
    background: #ff4444;
    border-radius: 50%;
    animation: pulse 2s infinite;
  }

  .status-indicator.active .pulse {
    background: #00ff88;
  }

  @keyframes pulse {
    0%, 100% { transform: scale(1); opacity: 1; }
    50% { transform: scale(1.2); opacity: 0.7; }
  }

  .status-indicator span {
    font-size: 1.5rem;
    font-weight: bold;
    letter-spacing: 2px;
  }

  .details {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .detail-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }

  .label {
    color: #888;
  }

  .value {
    color: #00d9ff;
    font-family: monospace;
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
