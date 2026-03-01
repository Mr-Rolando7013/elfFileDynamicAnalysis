#include <uapi/linux/ptrace.h>

#define COMM_LEN 16

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
    u64 map_update;
    u64 map_lookup;
    u64 map_delete;
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
            __sync_fetch_and_add(&s->map_update, 1);
            break;
        case 10:
            __sync_fetch_and_add(&s->map_lookup, 1);
            break;
        case 11:
            __sync_fetch_and_add(&s->map_delete, 1);
            break;
        case 12:
            __sync_fetch_and_add(&s->sys_kill, 1);
            break;
        case 13:
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

int trace_module_load(struct tracepoint__module__module_load *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 1);
    return 0;
}

int trace_module_free(struct tracepoint__module__module_free *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 2);
    return 0;
}

int trace_set_memory_rw(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 3);
    return 0;
}

int trace_sys_bpf(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 4);
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

int trace_xdp_attach(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 8);
    return 0;
}

int trace_bpf_map_update_elem(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 9);
    return 0;
}

int trace_bpf_map_lookup_elem(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 10);
    return 0;
}

int trace_bpf_map_delete_elem(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 11);
    return 0;
}

int trace_sys_kill(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 12);
    return 0;
}

int trace_set_memory_ro(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stat(pid, 13);
    return 0;
}