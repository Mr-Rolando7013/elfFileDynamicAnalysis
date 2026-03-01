#!/bin/bash
# =============================================================================
# Kernel tracing setup for ftrace + specific events (sched, syscalls, modules)
# =============================================================================

TRACING_DIR="/sys/kernel/debug/tracing"

# Make sure tracing directory exists
if [ ! -d "$TRACING_DIR" ]; then
    echo "[-] Tracing directory $TRACING_DIR not found. Is debugfs mounted?"
    exit 1
fi

echo "[*] Stopping tracing..."
echo 0 > "$TRACING_DIR/tracing_on"

echo "[*] Resetting tracer..."
echo nop > "$TRACING_DIR/current_tracer"

echo "[*] Clearing trace buffer..."
echo > "$TRACING_DIR/trace"

echo "[*] Clearing PID filters..."
echo > "$TRACING_DIR/set_ftrace_pid"
echo > "$TRACING_DIR/set_event_pid"

# ===================== ENABLE EVENTS =====================
declare -a EVENTS=(
    "sched/sched_switch"
    "sched/sched_process_exec"
    "sched/sched_process_fork"
    "sched/sched_process_exit"
    "syscalls/sys_enter_kill"
    "syscalls/sys_enter_getdents64"
    "syscalls/sys_enter_bpf"
    "module/module_load"
    "module/module_free"
    # Add more events here if needed
)

echo "[*] Enabling events..."
for e in "${EVENTS[@]}"; do
    if [ -f "$TRACING_DIR/events/$e/enable" ]; then
        echo 1 > "$TRACING_DIR/events/$e/enable"
        echo "[+] Enabled $e"
    else
        echo "[-] Event $e not found"
    fi
done

# Example of checking a specific event
echo "[*] Checking sys_enter_openat..."
if [ -f "$TRACING_DIR/events/syscalls/sys_enter_openat/enable" ]; then
    cat "$TRACING_DIR/events/syscalls/sys_enter_openat/enable"
else
    echo "[-] sys_enter_openat not found"
fi

echo "[*] Tracing setup complete."
