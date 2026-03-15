# Ransomware Guard — Function-Level Detection Flow

This document provides a deep dive into the exact function calls across the Python modules from detection to termination, including the Base64 evasion protection mechanism.

```mermaid
flowchart TD
    %% Guard Initialization
    API_start["POST /api/guard/start"] --> GS_start["GuardService.start()"]
    
    GS_start --> Init_EC["Init EntropyCalculator"]
    GS_start --> Init_PM["Init ProcessMonitor"]
    GS_start --> Init_FM["Init FileMonitor"]
    
    GS_start --> FM_start["FileMonitor.start()"]
    
    FM_start --> FM_proactive_scan["_run_proactive_backup_scan()<br/>Walk dir & backup"]
    FM_start --> FM_ebpf{"_try_start_ebpf()"}
    
    FM_start --> FM_threads["Start Analysis & Backup Workers"]
    
    FM_ebpf -->|Success| Monitor_EBPF["EBPFMonitor.start()<br/>Compile & Load BPF_PROGRAM"]
    FM_ebpf -->|Fallback| Monitor_WD["Watchdog Observer.start()"]
    
    %% eBPF Kernel Hooks
    Monitor_EBPF --> Hook_Write["kprobe: vfs_write()<br/>Kernel-space"]
    Monitor_EBPF --> Hook_Rename["tracepoint: sys_enter_renameat2"]
    Monitor_EBPF --> Hook_Unlink["tracepoint: sys_enter_unlinkat"]
    
    Hook_Write --> BPF_Logic["__builtin_memset event<br/>Extract PID, UID, comm, basename"]
    Hook_Write -.-> BPF_Anomaly["Update write_counts Map<br/>count > 50? rapid_writes = 1"]
    
    BPF_Logic --> Perf_Buffer["file_events.perf_submit()<br/>Ring Buffer"]
    Hook_Rename --> Perf_Buffer
    Hook_Unlink --> Perf_Buffer
    
    Perf_Buffer --> BPF_Poll["_poll_events()<br/>User-space Thread"]
    BPF_Poll --> BPF_Handle["_handle_kernel_event()"]
    BPF_Handle --> BPF_Resolve["_resolve_path()<br/>Read /proc/pid/fd symlinks"]
    BPF_Resolve --> FM_on_ebpf["FileMonitor._on_ebpf_event()<br/>SIGSTOP & queue"]
    
    Monitor_WD -.->|inotify/FSEvents| FM_on_mod["Watchdog Handler"]
    
    FM_on_ebpf --> Event_Queue["_event_queue.put()"]
    FM_on_mod --> Event_Queue
    
    Event_Queue --> FM_worker["FileMonitor._analysis_worker()"]
    FM_worker --> FM_analyze["FileMonitor._analyze_file()"]
    
    %% Entropy Calculation Phase
    FM_analyze --> EC_calc["EntropyCalculator.calculate_file_entropy()"]
    
    EC_calc --> EC_size{"file_size < 80KB?"}
    EC_size -->|Yes| EC_mem["read() all into memory"]
    EC_size -->|No| EC_large["_calculate_large_file_entropy()<br/>Sample Head/Mid/Tail"]
    
    %% Base64 Handling
    EC_mem --> EC_b64{"_is_base64_encoded()"}
    EC_large --> EC_b64
    
    EC_b64 -->|True| EC_try["_try_decode_base64()<br/>In-memory translation"]
    EC_try -->|Success| EC_calc_dec["calculate_entropy()<br/>on DECODED bytes"]
    EC_try -->|Failed| EC_calc_raw["calculate_entropy()<br/>on RAW bytes"]
    EC_b64 -->|False| EC_calc_raw
    
    %% Evaluation Phase
    EC_calc_dec --> EC_score["Return Result Dict"]
    EC_calc_raw --> EC_score
    
    EC_score --> FM_eval{"entropy >= 7.5?"}
    FM_eval -->|No| FM_safe["FileMonitor._resume_process()"]
    
    %% Magic Bytes Verification
    FM_eval -->|Yes| MB_check["MagicBytesDetector.is_known_type()"]
    MB_check -->|Yes| FM_safe
    MB_check -->|No| PM_handle["ProcessMonitor.handle_ransomware_alert()"]
    
    %% Threat Neutralization
    PM_handle --> PM_cache["ProcessMonitor.get_cached_writer()"]
    PM_cache --> PM_term["ProcessMonitor.terminate_process()<br/>SIGTERM -> SIGKILL"]
    
    %% Restoration & Alerting
    PM_term --> BM_restore["BackupManager.restore_backup()"]
    BM_restore --> WS_alert["GuardService._handle_alert()<br/>WebSocket Broadcast"]
```
