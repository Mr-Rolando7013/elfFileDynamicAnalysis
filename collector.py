from bcc import BPF
import time
import os

def handle_bpf_prog_event(cpu, data, size):
    event = b["bpf_prog_events"].event(data)
    print(f"[BPF_ATTACH] PID {event.pid} ({event.comm}): prog_id={event.prog_id}")

bpf_text = open("monitor.c").read()
b = BPF(text=bpf_text)

# Attach probes
b.attach_kprobe(event="kallsyms_lookup_name", fn_name="trace_lookup")
b.attach_kprobe(event="text_poke", fn_name="trace_text_poke")
b.attach_kprobe(event="proc_pid_readdir", fn_name="trace_proc_pid_readdir")
b.attach_kprobe(event="__x64_sys_kill", fn_name="trace_sys_kill")
b.attach_kprobe(event="set_memory_rw", fn_name="trace_set_memory_rw")
b.attach_kprobe(event="set_memory_ro", fn_name="trace_set_memory_ro")
b.attach_kprobe(event="__x64_sys_bpf", fn_name="trace_sys_bpf")
b.attach_kprobe(event="bpf_map_update_elem", fn_name="trace_bpf_map_update_elem")
b.attach_kprobe(event="bpf_map_lookup_elem", fn_name="trace_bpf_map_lookup_elem")
b.attach_kprobe(event="bpf_map_delete_elem", fn_name="trace_bpf_map_delete_elem")
b.attach_kprobe(event="__cgroup_bpf_attach", fn_name="trace_bpf_attach")
b.attach_kprobe(event="dev_xdp_attach", fn_name="trace_xdp_attach")

# Tracepoints
b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="trace_openat")
b.attach_tracepoint(tp="syscalls:sys_exit_openat", fn_name="trace_openat_ret")
b.attach_tracepoint(tp="module:module_load", fn_name="trace_module_load")
b.attach_tracepoint(tp="module:module_free", fn_name="trace_module_free")

stats = b.get_table("stats")

print("[*] Kernel Integrity Monitor Started")
print("[*] Press Ctrl+C to stop\n")
MY_PID = os.getpid()

ALERT_THRESHOLD = 1

try:
    while True:
        time.sleep(1)
        b.perf_buffer_poll(timeout=100)

        for key, value in stats.items():
            pid = key.value
            comm = value.comm.decode('utf-8', 'replace').rstrip('\x00')

            if pid == MY_PID:
                continue
            else:
                
                if (value.text_poke >= ALERT_THRESHOLD or
                    value.mem_rw >= ALERT_THRESHOLD or
                    value.bpf_calls >= ALERT_THRESHOLD or
                    value.kallsyms >= ALERT_THRESHOLD or
                    value.proc_readdir >= ALERT_THRESHOLD or
                    value.module_load >= ALERT_THRESHOLD or
                    value.module_free >= ALERT_THRESHOLD or
                    value.bpf_attach >= ALERT_THRESHOLD or
                    value.xdp_attach >= ALERT_THRESHOLD or
                    value.map_update >= ALERT_THRESHOLD or
                    value.map_lookup >= ALERT_THRESHOLD or
                    value.map_delete >= ALERT_THRESHOLD or
                    value.sys_kill >= ALERT_THRESHOLD or
                    value.mem_ro >= ALERT_THRESHOLD):

                    print(f"[ALERT] PID {pid} ({comm}): "
                        f"text_poke={value.text_poke}, "
                        f"mem_rw={value.mem_rw}, "
                        f"bpf_calls={value.bpf_calls}, "
                        f"kallsyms={value.kallsyms}, "
                        f"proc_readdir={value.proc_readdir}, "
                        f"module_load={value.module_load}, "
                        f"module_free={value.module_free}, "
                        f"bpf_attach={value.bpf_attach}, "
                        f"xdp_attach={value.xdp_attach}, "
                        f"map_update={value.map_update}, "
                        f"map_lookup={value.map_lookup}, "
                        f"map_delete={value.map_delete}, "
                        f"sys_kill={value.sys_kill}, "
                        f"mem_ro={value.mem_ro}")

        stats.clear()

except KeyboardInterrupt:
    print("\n[*] Stopping monitor...")