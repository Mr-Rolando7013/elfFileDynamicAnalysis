#!/usr/bin/env python3
import csv

# Config
KPROBE_CSV = "kernel_trace.csv"      # your kprobe CSV
FTRACE_FILE = "test_elf_systemwide.trace"   # your ftrace log
TIME_WINDOW = 0.01                 # 10ms window to match events

# -----------------------
# Step 1: Load kprobe events
# -----------------------
kprobe_events = []
with open(KPROBE_CSV) as f:
    reader = csv.reader(f)
    for row in reader:
        try:
            timestamp = float(row[0])
            probe_name = row[-1]  # last column = probe function name
            kprobe_events.append((timestamp, probe_name))
        except ValueError:
            continue  # skip malformed rows

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
            timestamp = float(ts_str)  # ftrace timestamp in seconds
            event_name = parts[1].split()[0]
            ftrace_events.append((timestamp, event_name))
        except (IndexError, ValueError):
            continue
# -----------------------
# Step 2.5: Compute offset between kprobe and ftrace logs
# -----------------------
# Convert first kprobe timestamp from ns -> s
first_kprobe_sec = kprobe_events[0][0] / 1_000_000_000
first_ftrace_sec = ftrace_events[0][0]

offset = first_ftrace_sec - first_kprobe_sec
print(f"[INFO] Applying offset: {offset:.6f} seconds")

# Adjust all kprobe timestamps
kprobe_events_sec = [(ts / 1_000_000_000 + offset, name) for ts, name in kprobe_events]

# -----------------------
# Step 3: Cross-view detection
# -----------------------
alerts = []
for k_ts, probe_name in kprobe_events_sec:
    related = [e for t, e in ftrace_events if abs(t - k_ts) <= TIME_WINDOW]
    if not related:
        alerts.append({
            "timestamp": k_ts,
            "probe": probe_name,
            "alert": "No related trace events"
        })

# -----------------------
# Step 4: Print detection table
# -----------------------
print(f"{'Timestamp':15} | {'Probe Name':25} | {'Alert'}")
print("-" * 70)
for a in alerts:
    print(f"{a['timestamp']:15.6f} | {a['probe']:25} | {a['alert']}")

# Optional: save to CSV
with open("detection_alerts.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["timestamp", "probe", "alert"])
    writer.writeheader()
    for a in alerts:
        writer.writerow(a)

print(kprobe_events[0][0])
print(ftrace_events[0][0])
print(f"\n[INFO] Detection complete: {len(alerts)} alerts found.")