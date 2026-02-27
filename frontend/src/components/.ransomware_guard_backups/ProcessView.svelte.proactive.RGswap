<script lang="ts">
    import { onMount } from "svelte";

    interface Process {
        pid: number;
        name: string;
        exe: string | null;
        cmdline: string;
        username: string | null;
        cpu_percent: number;
        memory_percent: number;
        is_protected: boolean;
        is_trusted: boolean;
    }

    interface ActionLog {
        pid: number;
        name: string;
        action: string;
        success: boolean;
        message: string;
        timestamp: number;
    }

    export let processes: Process[] = [];
    export let guardRunning: boolean = false;

    let actionLog: ActionLog[] = [];
    let searchQuery = "";
    let sortField: keyof Process = "cpu_percent";
    let sortAsc = false;
    let loading = false;

    $: filteredProcesses = processes
        .filter((p) => {
            if (!searchQuery) return true;
            const q = searchQuery.toLowerCase();
            return (
                p.name.toLowerCase().includes(q) ||
                String(p.pid).includes(q) ||
                (p.username && p.username.toLowerCase().includes(q)) ||
                (p.exe && p.exe.toLowerCase().includes(q))
            );
        })
        .sort((a, b) => {
            const aVal = a[sortField] ?? "";
            const bVal = b[sortField] ?? "";
            if (aVal < bVal) return sortAsc ? -1 : 1;
            if (aVal > bVal) return sortAsc ? 1 : -1;
            return 0;
        });

    function toggleSort(field: keyof Process) {
        if (sortField === field) {
            sortAsc = !sortAsc;
        } else {
            sortField = field;
            sortAsc = false;
        }
    }

    function sortIcon(field: keyof Process): string {
        if (sortField !== field) return "↕";
        return sortAsc ? "↑" : "↓";
    }

    async function fetchProcesses() {
        loading = true;
        try {
            const res = await fetch("/api/processes?limit=0");
            const data = await res.json();
            processes = data.processes || [];
        } catch (e) {
            console.error("Failed to fetch processes:", e);
        } finally {
            loading = false;
        }
    }

    async function fetchActionLog() {
        try {
            const res = await fetch("/api/processes/action-log?limit=20");
            actionLog = await res.json();
        } catch (e) {
            console.error("Failed to fetch action log:", e);
        }
    }

    function formatTime(timestamp: number): string {
        return new Date(timestamp * 1000).toLocaleTimeString();
    }

    function getStatusBadge(p: Process): { text: string; cls: string } {
        if (p.is_protected) return { text: "PROTECTED", cls: "protected" };
        if (p.is_trusted) return { text: "TRUSTED", cls: "trusted" };
        return { text: "NORMAL", cls: "normal" };
    }

    onMount(() => {
        fetchProcesses();
        fetchActionLog();

        const interval = setInterval(() => {
            if (!guardRunning) {
                fetchProcesses();
            }
            fetchActionLog();
        }, 5000);

        return () => clearInterval(interval);
    });
</script>

<div class="process-view">
    <!-- Process Table Section -->
    <section class="process-table-section">
        <div class="section-header">
            <h2>⚙️ Running Processes</h2>
            <div class="controls-row">
                <input
                    type="text"
                    class="search-input"
                    placeholder="Search processes..."
                    bind:value={searchQuery}
                />
                <button
                    class="refresh-btn"
                    on:click={fetchProcesses}
                    disabled={loading}
                >
                    {loading ? "⏳" : "🔄"} Refresh
                </button>
            </div>
        </div>

        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th on:click={() => toggleSort("pid")}
                            >PID {sortIcon("pid")}</th
                        >
                        <th on:click={() => toggleSort("name")}
                            >Name {sortIcon("name")}</th
                        >
                        <th on:click={() => toggleSort("username")}
                            >User {sortIcon("username")}</th
                        >
                        <th on:click={() => toggleSort("cpu_percent")}
                            >CPU% {sortIcon("cpu_percent")}</th
                        >
                        <th on:click={() => toggleSort("memory_percent")}
                            >Mem% {sortIcon("memory_percent")}</th
                        >
                        <th>Status</th>
                        <th>Executable</th>
                    </tr>
                </thead>
                <tbody>
                    {#if filteredProcesses.length === 0}
                        <tr>
                            <td colspan="7" class="empty"
                                >{loading
                                    ? "Loading..."
                                    : "No processes found"}</td
                            >
                        </tr>
                    {:else}
                        {#each filteredProcesses as proc (proc.pid)}
                            <tr
                                class:protected-row={proc.is_protected}
                                class:trusted-row={proc.is_trusted}
                            >
                                <td class="pid">{proc.pid}</td>
                                <td class="name">{proc.name}</td>
                                <td class="username">{proc.username || "—"}</td>
                                <td class="cpu"
                                    >{proc.cpu_percent.toFixed(1)}</td
                                >
                                <td class="mem"
                                    >{proc.memory_percent.toFixed(1)}</td
                                >
                                <td>
                                    <span
                                        class="badge {getStatusBadge(proc).cls}"
                                        >{getStatusBadge(proc).text}</span
                                    >
                                </td>
                                <td class="exe" title={proc.exe || ""}
                                    >{proc.exe
                                        ? proc.exe
                                              .split("/")
                                              .slice(-2)
                                              .join("/")
                                        : "—"}</td
                                >
                            </tr>
                        {/each}
                    {/if}
                </tbody>
            </table>
        </div>
        <div class="table-footer">
            <span
                >Showing {filteredProcesses.length} of {processes.length} processes</span
            >
        </div>
    </section>

    <!-- Action Log Section -->
    <section class="action-log-section">
        <h2>📋 Action Log</h2>
        {#if actionLog.length === 0}
            <div class="empty-state">
                <span class="icon">📭</span>
                <p>No actions taken yet</p>
            </div>
        {:else}
            <div class="action-log">
                {#each actionLog as entry}
                    <div class="log-entry" class:success={entry.success}>
                        <div class="log-header">
                            <span class="log-action"
                                >{entry.success ? "✅" : "❌"}
                                {entry.action.toUpperCase()}</span
                            >
                            <span class="log-time"
                                >{formatTime(entry.timestamp)}</span
                            >
                        </div>
                        <div class="log-body">
                            <span class="log-process"
                                >{entry.name} (PID: {entry.pid})</span
                            >
                            <span class="log-message">{entry.message}</span>
                        </div>
                    </div>
                {/each}
            </div>
        {/if}
    </section>
</div>

<style>
    .process-view {
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
    }

    section {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 16px;
        padding: 1.5rem;
        border: 1px solid rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px);
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
        color: #00d9ff;
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
        max-height: 500px;
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
        background: #1a1a2e;
        padding: 0.7rem 0.75rem;
        text-align: left;
        color: #888;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        font-size: 0.78rem;
        cursor: pointer;
        user-select: none;
        white-space: nowrap;
        transition: color 0.2s;
        border-bottom: 2px solid rgba(255, 255, 255, 0.1);
    }

    th:hover {
        color: #00d9ff;
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

    .protected-row {
        background: rgba(0, 255, 136, 0.04);
    }

    .trusted-row {
        background: rgba(0, 150, 255, 0.04);
    }

    .pid {
        color: #888;
        font-family: monospace;
    }

    .name {
        color: #e0e0e0;
        font-weight: 500;
    }

    .username {
        color: #aaa;
    }

    .cpu,
    .mem {
        font-family: monospace;
        color: #ffaa00;
        text-align: right;
    }

    .exe {
        color: #666;
        font-family: monospace;
        max-width: 200px;
        overflow: hidden;
        text-overflow: ellipsis;
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

    .badge.protected {
        background: rgba(0, 255, 136, 0.15);
        color: #00ff88;
    }

    .badge.trusted {
        background: rgba(0, 150, 255, 0.15);
        color: #4da6ff;
    }

    .badge.normal {
        background: rgba(255, 255, 255, 0.08);
        color: #888;
    }

    .table-footer {
        margin-top: 0.75rem;
        font-size: 0.8rem;
        color: #666;
        text-align: right;
    }

    /* Action log */
    .action-log-section h2 {
        margin-bottom: 1.25rem;
    }

    .empty-state {
        text-align: center;
        padding: 2.5rem;
        color: #888;
    }

    .empty-state .icon {
        font-size: 2.5rem;
        display: block;
        margin-bottom: 0.75rem;
    }

    .action-log {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
        max-height: 300px;
        overflow-y: auto;
    }

    .log-entry {
        background: rgba(255, 68, 68, 0.08);
        border: 1px solid rgba(255, 68, 68, 0.2);
        border-radius: 10px;
        padding: 0.85rem;
    }

    .log-entry.success {
        background: rgba(0, 255, 136, 0.05);
        border-color: rgba(0, 255, 136, 0.2);
    }

    .log-header {
        display: flex;
        justify-content: space-between;
        margin-bottom: 0.5rem;
        font-size: 0.85rem;
    }

    .log-action {
        font-weight: 600;
        color: #ff6b6b;
    }

    .log-entry.success .log-action {
        color: #00ff88;
    }

    .log-time {
        color: #888;
    }

    .log-body {
        display: flex;
        gap: 1rem;
        font-size: 0.85rem;
        flex-wrap: wrap;
    }

    .log-process {
        color: #00d9ff;
        font-family: monospace;
    }

    .log-message {
        color: #aaa;
    }

    /* Scrollbar */
    .table-wrapper::-webkit-scrollbar,
    .action-log::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }

    .table-wrapper::-webkit-scrollbar-track,
    .action-log::-webkit-scrollbar-track {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 3px;
    }

    .table-wrapper::-webkit-scrollbar-thumb,
    .action-log::-webkit-scrollbar-thumb {
        background: rgba(255, 255, 255, 0.2);
        border-radius: 3px;
    }
</style>
