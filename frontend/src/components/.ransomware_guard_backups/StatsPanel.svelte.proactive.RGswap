<script lang="ts">
  export let stats: {
    files_scanned: number;
    threats_detected: number;
    processes_terminated: number;
    alerts_total: number;
  };
</script>

<div class="stats-panel">
  <h2>Statistics</h2>
  
  <div class="stats-grid">
    <div class="stat-item">
      <div class="stat-value">{stats.files_scanned}</div>
      <div class="stat-label">Files Scanned</div>
    </div>
    
    <div class="stat-item threats">
      <div class="stat-value">{stats.threats_detected}</div>
      <div class="stat-label">Threats Detected</div>
    </div>
    
    <div class="stat-item terminated">
      <div class="stat-value">{stats.processes_terminated}</div>
      <div class="stat-label">Processes Killed</div>
    </div>
    
    <div class="stat-item">
      <div class="stat-value">{stats.alerts_total}</div>
      <div class="stat-label">Total Alerts</div>
    </div>
  </div>
</div>

<style>
  .stats-panel {
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

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
  }

  .stat-item {
    background: rgba(0, 217, 255, 0.1);
    border-radius: 12px;
    padding: 1.5rem;
    text-align: center;
    transition: transform 0.2s, background 0.2s;
  }

  .stat-item:hover {
    transform: translateY(-2px);
    background: rgba(0, 217, 255, 0.15);
  }

  .stat-item.threats {
    background: rgba(255, 68, 68, 0.1);
  }

  .stat-item.threats:hover {
    background: rgba(255, 68, 68, 0.15);
  }

  .stat-item.terminated {
    background: rgba(255, 170, 0, 0.1);
  }

  .stat-item.terminated:hover {
    background: rgba(255, 170, 0, 0.15);
  }

  .stat-value {
    font-size: 2.5rem;
    font-weight: bold;
    color: #00d9ff;
    margin-bottom: 0.5rem;
  }

  .stat-item.threats .stat-value {
    color: #ff4444;
  }

  .stat-item.terminated .stat-value {
    color: #ffaa00;
  }

  .stat-label {
    font-size: 0.85rem;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  @media (max-width: 700px) {
    .stats-grid {
      grid-template-columns: repeat(2, 1fr);
    }
  }
</style>
