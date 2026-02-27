<script lang="ts">
  import { createEventDispatcher } from "svelte";

  export let running: boolean;
  export let watchPath: string | null;

  const dispatch = createEventDispatcher();

  let inputPath = "/home";
  let entropyThreshold = 7.5;
  let loading = false;
  let message = "";

  // Enforce minimum entropy of 6
  function validateEntropy() {
    if (entropyThreshold < 6) {
      entropyThreshold = 6;
    }
    if (entropyThreshold > 8) {
      entropyThreshold = 8;
    }
  }

  async function handleStart() {
    if (!inputPath.trim()) {
      message = "Please enter a path to monitor";
      return;
    }

    validateEntropy();

    loading = true;
    message = "";

    try {
      dispatch("start", { path: inputPath, entropy: entropyThreshold });
      message = "Guard started successfully!";
    } catch (e) {
      message = "Failed to start guard";
    } finally {
      loading = false;
    }
  }

  async function handleStop() {
    loading = true;
    message = "";

    try {
      dispatch("stop");
      message = "Guard stopped";
    } catch (e) {
      message = "Failed to stop guard";
    } finally {
      loading = false;
    }
  }
</script>

<div class="control-panel">
  <h2>Control Panel</h2>

  <div class="controls">
    {#if !running}
      <div class="input-group">
        <div class="path-input">
          <label for="path">Path to Monitor</label>
          <input
            id="path"
            type="text"
            bind:value={inputPath}
            placeholder="Enter path to monitor..."
            disabled={loading}
          />
        </div>
        <div class="entropy-input">
          <label for="entropy">Entropy Threshold</label>
          <input
            id="entropy"
            type="number"
            bind:value={entropyThreshold}
            on:blur={validateEntropy}
            min="6"
            max="8"
            step="0.1"
            disabled={loading}
          />
        </div>
      </div>
      <button class="btn start" on:click={handleStart} disabled={loading}>
        {loading ? "⏳ Starting..." : "▶️ Start Guard"}
      </button>
    {:else}
      <div class="watching-info">
        <span class="label">Currently monitoring:</span>
        <span class="path">{watchPath}</span>
      </div>
      <button class="btn stop" on:click={handleStop} disabled={loading}>
        {loading ? "⏳ Stopping..." : "⏹️ Stop Guard"}
      </button>
    {/if}
  </div>

  {#if message}
    <div class="message">{message}</div>
  {/if}
</div>

<style>
  .control-panel {
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

  .controls {
    display: flex;
    gap: 1rem;
    align-items: flex-end;
    flex-wrap: wrap;
  }

  .input-group {
    display: flex;
    gap: 1rem;
    flex: 1;
    flex-wrap: wrap;
  }

  .path-input {
    flex: 2;
    min-width: 250px;
  }

  .entropy-input {
    flex: 0 0 140px;
  }

  label {
    display: block;
    font-size: 0.8rem;
    color: #888;
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  input {
    width: 100%;
    padding: 0.75rem 1rem;
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(0, 0, 0, 0.3);
    color: #fff;
    font-size: 1rem;
    font-family: monospace;
  }

  input[type="number"] {
    text-align: center;
    font-family: inherit;
  }

  input[type="number"]::-webkit-inner-spin-button,
  input[type="number"]::-webkit-outer-spin-button {
    opacity: 1;
    height: 28px;
  }

  input:focus {
    outline: none;
    border-color: #00d9ff;
    box-shadow: 0 0 10px rgba(0, 217, 255, 0.3);
  }

  .btn {
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    border: none;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn.start {
    background: linear-gradient(135deg, #00d9ff, #00ff88);
    color: #1a1a2e;
  }

  .btn.start:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 5px 20px rgba(0, 255, 136, 0.3);
  }

  .btn.stop {
    background: linear-gradient(135deg, #ff4444, #ff6b6b);
    color: #fff;
  }

  .btn.stop:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 5px 20px rgba(255, 68, 68, 0.3);
  }

  .watching-info {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .watching-info .label {
    color: #888;
  }

  .watching-info .path {
    color: #00ff88;
    font-family: monospace;
    background: rgba(0, 255, 136, 0.1);
    padding: 0.5rem 1rem;
    border-radius: 4px;
  }

  .message {
    margin-top: 1rem;
    padding: 0.75rem;
    background: rgba(0, 217, 255, 0.1);
    border-radius: 8px;
    color: #00d9ff;
    text-align: center;
  }
</style>
