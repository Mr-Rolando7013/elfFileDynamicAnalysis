from bcc import BPF
from time import sleep
import subprocess
import pandas as pd
import sys
import os

if len(sys.argv) != 2:
    print(f"Usage: sudo {sys.argv[0]} <module.ko>")
    sys.exit(1)

module_path = sys.argv[1]

# ================= BPF PROGRAM =================
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/sched.h>
#include <linux/limits.h>

// ---------------- Openat ----------------
struct open_data_t {
    u64 ts;
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    int flags;
    int dfd;
};

BPF_PERF_OUTPUT(open_events);

// ---------------- Generic Events ----------------
struct simple_event_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char info[64];   // e.g., module_load, kallsyms_lookup
};

BPF_PERF_OUTPUT(events);

// -------- Tracepoints --------
int trace_openat(struct tracepoint__syscalls__sys_enter_openat *ctx) {
    struct open_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.dfd = ctx->dfd;
    data.flags = ctx->flags;
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), ctx->filename);
    open_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_openat_ret(struct tracepoint__syscalls__sys_exit_openat *ctx) {
    struct simple_event_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.info, "exit_openat", sizeof("exit_openat"));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_module_load(struct tracepoint__module__module_load *ctx) {
    struct simple_event_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.info, "module_load", sizeof("module_load"));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_module_free(struct tracepoint__module__module_free *ctx) {
    struct simple_event_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.info, "module_free", sizeof("module_free"));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// -------- Kprobes --------
int trace_lookup(struct pt_regs *ctx) {
    struct simple_event_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.info, "kallsyms_lookup", sizeof("kallsyms_lookup"));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_text_patch(struct pt_regs *ctx) {
    struct simple_event_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.info, "text_poke", sizeof("text_poke"));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_proc_pid_readdir(struct pt_regs *ctx) {
    struct simple_event_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.info, "proc_readdir", sizeof("proc_readdir"));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_sys_kill(struct pt_regs *ctx) {
    struct simple_event_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.info, "sys_kill", sizeof("sys_kill"));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_set_memory_rw(struct pt_regs *ctx) {
    struct simple_event_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.info, "set_memory_rw", sizeof("set_memory_rw"));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_set_memory_ro(struct pt_regs *ctx) {
    struct simple_event_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.info, "set_memory_ro", sizeof("set_memory_ro"));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_sys_bpf(struct pt_regs *ctx)
{
    struct simple_event_t data = {};
    int cmd = PT_REGS_PARM1(ctx);

    if (cmd != BPF_PROG_LOAD)
        return 0;

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    __builtin_memcpy(&data.info, "bpf_prog_load",
                     sizeof("bpf_prog_load"));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

"""

# Make sure debugfs is mounted
debugfs_path = "/sys/kernel/debug/tracing"
if not os.path.exists(debugfs_path):
    subprocess.run(["mount", "-t", "debugfs", "none", debugfs_path], check=True)

enabled_functions_path = f"{debugfs_path}/enabled_functions"

# --- Snapshot before module load ---
with open(enabled_functions_path, "r") as f:
    before = set(f.read().splitlines())

# ================= LOAD BPF =================
print("[*] Loading BPF program...")
b = BPF(text=bpf_text)

# Tracepoints
b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="trace_openat")
b.attach_tracepoint(tp="syscalls:sys_exit_openat", fn_name="trace_openat_ret")
b.attach_tracepoint(tp="module:module_load", fn_name="trace_module_load")
b.attach_tracepoint(tp="module:module_free", fn_name="trace_module_free")
#b.attach_kprobe(event="register_ftrace_function", fn_name="trace_register_ftrace")
#b.attach_kprobe(event="unregister_ftrace_function", fn_name="trace_unregister_ftrace")

# Kprobes
b.attach_kprobe(event="kallsyms_lookup_name", fn_name="trace_lookup")
b.attach_kprobe(event="text_poke", fn_name="trace_text_patch")
b.attach_kprobe(event="proc_pid_readdir", fn_name="trace_proc_pid_readdir")
b.attach_kprobe(event="__x64_sys_kill", fn_name="trace_sys_kill")
#b.attach_kprobe(event="__write_cr0", fn_name="trace_write_cr0")
b.attach_kprobe(event="set_memory_rw", fn_name="trace_set_memory_rw")
b.attach_kprobe(event="set_memory_ro", fn_name="trace_set_memory_ro")
b.attach_kprobe(event="__x64_sys_bpf", fn_name="trace_sys_bpf")
# ================= HANDLERS =================
open_events_list = []
events_list = []

def handle_open(cpu, data, size):
    event = b["open_events"].event(data)
    open_events_list.append({
        "ts": event.ts,
        "pid": event.pid,
        "tid": event.tid,
        "comm": event.comm.decode('utf-8', 'replace'),
        "fname": event.fname.decode('utf-8', 'replace'),
        "dfd": event.dfd,
        "flags": event.flags,
        "event": "enter_openat"
    })

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    events_list.append({
        "ts": event.ts,
        "pid": event.pid,
        "tid": 0,
        "comm": event.comm.decode('utf-8', 'replace'),
        "fname": "",
        "dfd": "",
        "flags": "",
        "event": event.info.decode('utf-8', 'replace')
    })

b["open_events"].open_perf_buffer(handle_open)
b["events"].open_perf_buffer(handle_event)

# ================= RUN MODULE =================
print("[*] Tracer running...")
print("[*] Loading module:", module_path)
proc = subprocess.Popen(["insmod", module_path])

# --- Snapshot after module load ---
with open(enabled_functions_path, "r") as f:
    after = set(f.read().splitlines())

# --- Compare ---
new_hooks = after - before
if new_hooks:
    print("[!] New ftrace hooks detected:")
    for hook in new_hooks:
        print(" ", hook)
else:
    print("[*] No new ftrace hooks detected")

try:
    while True:
        b.perf_buffer_poll(timeout=100)
        if proc.poll() is not None:
            break
except KeyboardInterrupt:
    pass

sleep(1)

# ================= SAVE CSV =================
df_open = pd.DataFrame(open_events_list)
df_events = pd.DataFrame(events_list)

# Merge into one CSV sorted by timestamp
df = pd.concat([df_open, df_events], ignore_index=True)
df.sort_values("ts", inplace=True)
df.to_csv("kernel_trace.csv", index=False)

print("[*] Trace saved to kernel_trace.csv")