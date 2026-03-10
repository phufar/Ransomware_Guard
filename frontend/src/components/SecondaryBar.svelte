<script lang="ts">
    import { createEventDispatcher } from "svelte";
    import { Play, Square, Hourglass } from "lucide-svelte";

    export let running: boolean;
    export let processesKilled: number = 0;
    export let threatsDetected: number = 0;

    const dispatch = createEventDispatcher();

    let inputPath = "/home";
    let entropyThreshold = 7.5;
    export let loading: boolean = false;

    function validateEntropy() {
        if (entropyThreshold < 6) entropyThreshold = 6;
        if (entropyThreshold > 8) entropyThreshold = 8;
    }

    function handleStart() {
        if (!inputPath.trim()) return;
        validateEntropy();
        dispatch("start", { path: inputPath, entropy: entropyThreshold });
    }

    function handleStop() {
        dispatch("stop");
    }
</script>

<div class="secondary-bar">
    <div class="left-side">
        <span class="stat">Process Kill: {processesKilled}</span>
        <span class="stat">Threat Detected: {threatsDetected}</span>
    </div>

    <div class="right-side">
        <label class="input-wrapper">
            <span class="input-label">Path:</span>
            <input
                type="text"
                bind:value={inputPath}
                placeholder="/home"
                disabled={running || loading}
                class="minimal-input path-input"
            />
        </label>
        <label class="input-wrapper">
            <span class="input-label">Entropy:</span>
            <input
                type="number"
                bind:value={entropyThreshold}
                on:blur={validateEntropy}
                min="6"
                max="8"
                disabled={running || loading}
                class="minimal-input entropy-input"
                title="Entropy Threshold"
            />
        </label>

        {#if !running}
            {#if loading}
                <button class="action-btn starting-btn" disabled>
                    <Hourglass size={18} />
                    <span>Starting...</span>
                </button>
            {:else}
                <button class="action-btn start-btn" on:click={handleStart}>
                    <Play size={18} />
                    <span>Start</span>
                </button>
            {/if}
        {:else if loading}
            <button class="action-btn stopping-btn" disabled>
                <Hourglass size={18} />
                <span>Stopping...</span>
            </button>
        {:else}
            <button class="action-btn stop-btn" on:click={handleStop}>
                <Square size={18} />
                <span>Stop</span>
            </button>
        {/if}
    </div>
</div>

<style>
    .secondary-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: rgba(0, 0, 0, 0.4);
        padding: 0.75rem 1.5rem;
        border-radius: 8px;
        border: 1px solid rgba(255, 255, 255, 0.05);
        margin-bottom: 0.5rem;
        flex-wrap: wrap;
        gap: 1rem;
    }

    .left-side {
        display: flex;
        gap: 2rem;
    }

    .stat {
        font-size: 1rem;
        color: #ccc;
        font-weight: 500;
    }

    .right-side {
        display: flex;
        align-items: center;
        gap: 1.25rem;
        flex-wrap: wrap;
    }

    .input-wrapper {
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .input-label {
        font-size: 0.9rem;
        color: #888;
        font-weight: 500;
    }

    .minimal-input {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        color: #fff;
        padding: 0.5rem 0.75rem;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.9rem;
        transition: border-color 0.2s;
    }

    .minimal-input:focus {
        outline: none;
        border-color: #00d9ff;
    }

    .minimal-input:disabled {
        opacity: 0.6;
        cursor: not-allowed;
    }

    .path-input {
        width: 350px;
        max-width: 100%;
    }

    .entropy-input {
        width: 70px;
        text-align: center;
    }

    input[type="number"] {
        -moz-appearance: textfield;
        appearance: textfield;
    }

    input[type="number"]::-webkit-inner-spin-button,
    input[type="number"]::-webkit-outer-spin-button {
        -webkit-appearance: none;
        margin: 0;
    }

    .action-btn {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
        padding: 0.5rem 1rem;
        border: none;
        border-radius: 4px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s;
        width: 125px; /* Ensures consistent button sizing during text shifts */
    }

    .action-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }

    .start-btn {
        background: #00ff88;
        color: #000;
    }

    .start-btn:hover:not(:disabled) {
        background: #00e67a;
    }

    .stop-btn {
        background: #ff4444;
        color: #fff;
    }

    .stop-btn:hover:not(:disabled) {
        background: #e63d3d;
    }

    .starting-btn {
        background: #ffcc00;
        color: #000;
        opacity: 1 !important;
        cursor: wait !important;
    }

    .stopping-btn {
        background: #ff9900;
        color: #000;
        opacity: 1 !important;
        cursor: wait !important;
    }

    @media (max-width: 850px) {
        .secondary-bar {
            flex-direction: column;
            align-items: stretch;
            gap: 1.5rem;
        }

        .left-side {
            justify-content: space-between;
        }

        .right-side {
            justify-content: space-between;
            width: 100%;
        }

        .input-wrapper {
            flex: 1;
        }

        .path-input {
            width: 100%;
        }
    }
</style>
