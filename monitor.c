#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/sched.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/netdevice.h>

#define COMM_LEN 16
#define DATA_LOC_PTR(ctx, field) ((char *)ctx + ((ctx->field) & 0xFFFF))
#define BPF_PROG_LOAD 5

struct stats_t {
    char comm[16];
    u64 text_poke;
    u64 module_load;
    u64 module_free;
    u64 mem_rw;
    u64 bpf_calls;
    u64 kallsyms;
    u64 proc_readdir;
    u64 bpf_attach;
    u64 xdp_attach;
    u64 sys_kill;
    u64 mem_ro;
};

BPF_HASH(stats, u32, struct stats_t);

static void update_stat(u32 pid, int field) {
    struct stats_t zero = {};
    struct stats_t *s;

    // Try to get existing stats
    s = stats.lookup(&pid);
    if (!s) {
        // Initialize comm for this PID
        bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
        stats.update(&pid, &zero);
        s = stats.lookup(&pid);
        if (!s)
            return; // Failed to initialize
    }

    // Increment the proper counter based on 'field'
    switch (field) {
        case 0:
            __sync_fetch_and_add(&s->text_poke, 1);
            break;
        case 1:
            __sync_fetch_and_add(&s->module_load, 1);
            break;
        case 2:
            __sync_fetch_and_add(&s->module_free, 1);
            break;
        case 3:
            __sync_fetch_and_add(&s->mem_rw, 1);
            break;
        case 4:
            __sync_fetch_and_add(&s->bpf_calls, 1);
            break;
        case 5:
            __sync_fetch_and_add(&s->kallsyms, 1);
            break;
        case 6:
            __sync_fetch_and_add(&s->proc_readdir, 1);
            break;
        case 7:
            __sync_fetch_and_add(&s->bpf_attach, 1);
            break;
        case 8:
            __sync_fetch_and_add(&s->xdp_attach, 1);
            break;
        case 9:
            __sync_fetch_and_add(&s->sys_kill, 1);
            break;
        case 10:
            __sync_fetch_and_add(&s->mem_ro, 1);
            break;
        default:
            break;
    }
}

int trace_text_poke(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 0);
    return 0;
}

struct simple_event_t {
    u64 ts;
    u32 pid;
    u32 uid;
    char comm[COMM_LEN];
    char action[8];
    char module[64];
};

BPF_PERF_OUTPUT(events);

/* Trace module load */
int trace_module_load(struct tracepoint__module__module_load *ctx) {
    struct simple_event_t event = {};
    event.ts  = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.action, "LOAD", 5);

    __u32 offset = ctx->data_loc_name & 0xffff;
    bpf_probe_read_str(event.module, sizeof(event.module), (char *)ctx + offset);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_module_free(struct tracepoint__module__module_free *ctx) {
    struct simple_event_t event = {};
    event.ts  = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.action, "FREE", 5);

    __u32 offset = ctx->data_loc_name & 0xffff;
    bpf_probe_read_str(event.module, sizeof(event.module), (char *)ctx + offset);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_set_memory_rw(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 3);
    return 0;
}

struct prog_load_event_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[COMM_LEN];
};

BPF_PERF_OUTPUT(prog_load_events);

int trace_sys_bpf(struct pt_regs *ctx) {
     int cmd = PT_REGS_PARM1(ctx);

    // Only care about program loads
    if (cmd != BPF_PROG_LOAD)
        return 0;

    struct prog_load_event_t evt = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();

    evt.ts = bpf_ktime_get_ns();

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    prog_load_events.perf_submit(ctx, &evt, sizeof(evt));
    update_stat(evt.pid, 5);
    return 0;
}

int trace_lookup(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 5);
    return 0;
}

int trace_proc_pid_readdir(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 6);
    return 0;
}

int trace_bpf_attach(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 7);
    return 0;
}

struct event_t {
    u32 pid;
    char comm[COMM_LEN];
    char ifname[16];
};

BPF_PERF_OUTPUT(events2);

// Buggy
int trace_xdp_attach(struct pt_regs *ctx, struct net_device *dev) {
    struct event_t evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_kernel_str(evt.ifname, sizeof(evt.ifname), dev->name);
    events2.perf_submit(ctx, &evt, sizeof(evt));

    update_stat(evt.pid, 7);
    return 0;
}

int trace_sys_kill(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 9);
    return 0;
}

int trace_set_memory_ro(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 10);
    return 0;
}