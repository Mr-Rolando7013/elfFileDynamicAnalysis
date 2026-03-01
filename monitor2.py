import csv
from collections import defaultdict

# -----------------------
# Config
# -----------------------
KPROBE_CSV = "kernel_trace.csv"
FTRACE_FILE = "test_elf_systemwide.trace"
TIME_WINDOW_SEC = 0.05  # 50ms window for temporal correlation
SENSITIVE_PROBES = {
    "kallsyms_lookup",
    "set_memory_rw",
    "set_memory_ro",
    "bpf_map_update_elem",
    "bpf_map_delete_elem",
    "bpf_map_lookup_elem",
    "bpf_attach",
    "bpf_xdp_attach",
}

# -----------------------
# Step 1: Load kprobe events
# -----------------------
kprobe_events = []
with open(KPROBE_CSV) as f:
    reader = csv.reader(f)
    for row in reader:
        try:
            timestamp = float(row[0])
            probe_name = row[-1]
            pid = row[2] if len(row) > 2 else None  # optional process PID
            comm = row[3] if len(row) > 3 else None # optional process name
            kprobe_events.append((timestamp, probe_name, pid, comm))
        except ValueError:
            continue

# -----------------------
# Step 2: Load ftrace events
# -----------------------
ftrace_events = []
with open(FTRACE_FILE) as f:
    for line in f:
        line = line.strip()
        if not line or ":" not in line:
            continue
        parts = line.split(":")
        try:
            ts_str = parts[0].split()[-1]
            timestamp = float(ts_str)
            event_name = parts[1].split()[0]
            ftrace_events.append((timestamp, event_name))
        except (IndexError, ValueError):
            continue

# -----------------------
# Step 2.5: Align timestamps
# -----------------------
# Use first event to compute offset
first_kprobe_sec = kprobe_events[0][0] / 1_000_000_000
first_ftrace_sec = ftrace_events[0][0]
offset = first_ftrace_sec - first_kprobe_sec
print(f"[INFO] Applying offset: {offset:.6f} seconds")
kprobe_events_sec = [(ts/1_000_000_000 + offset, name, pid, comm)
                     for ts, name, pid, comm in kprobe_events]
ftrace_events_sec = [(ts, event_name, None, None)  # no pid/comm in ftrace
                     for ts, event_name in ftrace_events]

all_events = kprobe_events_sec + ftrace_events_sec

sorted_events = sorted(all_events, key=lambda x: x[0])
# -----------------------
# Step 3: Anomaly detection
# -----------------------
alerts = []
# Track how many times each probe appears in TIME_WINDOW
probe_freq = defaultdict(list)

for k_ts, probe_name, pid, comm in kprobe_events_sec:
    # Record the timestamp for frequency check
    probe_freq[probe_name].append(k_ts)

    # Find ftrace events in TIME_WINDOW
    related = [e for t, e in ftrace_events if abs(t - k_ts) <= TIME_WINDOW_SEC]

    # 1) Sensitive probe fired
    if probe_name in SENSITIVE_PROBES:
        alerts.append({
            "timestamp": k_ts,
            "probe": probe_name,
            "pid": pid,
            "comm": comm,
            "alert": "Sensitive probe fired"
        })
    # 2) Probe appears but no ftrace correlation
    elif not related:
        alerts.append({
            "timestamp": k_ts,
            "probe": probe_name,
            "pid": pid,
            "comm": comm,
            "alert": "Probe without trace correlation"
        })

# 3) Frequency-based anomaly: probes firing too often
for probe, times in probe_freq.items():
    if len(times) > 50:  # arbitrary threshold, tune for your workload
        alerts.append({
            "timestamp": times[0],
            "probe": probe,
            "pid": None,
            "comm": None,
            "alert": f"High frequency probe: {len(times)} times"
        })

process_sequences = defaultdict(list)
WINDOW_SIZE = 5  # Number of events to track per process
SUSPICIOUS_SEQUENCES = [
    ["enter_openat", "exit_openat", "set_memory_ro", "module_load", "kallsyms_lookup"]
]
TIME_WINDOW = 0.5  # seconds to look for nearby ftrace confirmations

process_sequences = defaultdict(list)  # pid -> last N events

for ts, probe, pid, comm in sorted_events:
    seq = process_sequences[pid]
    seq.append(probe)
    if len(seq) > WINDOW_SIZE:
        seq.pop(0)

    # Check for any suspicious sequence
    for pattern in SUSPICIOUS_SEQUENCES:
        if seq[-len(pattern):] == pattern:
            alerts.append({
                "timestamp": ts,
                "pid": pid,
                "comm": comm,
                "sequence": seq[-len(pattern):].copy(),
                "alert": "Suspicious probe sequence detected"
            })
# -----------------------
# Step 4: Print detection table
# -----------------------
print(f"{'Timestamp':15} | {'Probe Name':25} | {'PID':7} | {'Comm':15} | {'Alert'}")
print("-" * 90)
for a in alerts:
    ts = f"{a['timestamp']:15.6f}"
    pid = a['pid'] if a['pid'] else ""
    comm = a['comm'] if a['comm'] else ""
    print(f"{ts} | {a['probe']:25} | {pid:7} | {comm:15} | {a['alert']}")

# -----------------------
# Step 5: Save to CSV
# -----------------------
with open("detection_alerts.csv", "w", newline="") as f:
    fieldnames = ["timestamp", "probe", "pid", "comm", "alert"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for a in alerts:
        writer.writerow(a)

print(f"\n[INFO] Detection complete: {len(alerts)} alerts found.")