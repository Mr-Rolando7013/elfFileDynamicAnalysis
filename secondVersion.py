from collections import defaultdict
import re
import pandas as pd
import sys
import networkx as nx
import matplotlib.pyplot as plt
from foldStorm import *

def affected_pids(df, storm, delta=0.05):
    return df[
        (df.ts >= storm.start) &
        (df.ts <= storm.end + delta) &
        (df.pid != storm.pid)
    ]["pid"].unique()


line_re = re.compile(
    r'(?P<comm>.+?)-(?P<pid>\d+)\s+\[\d+\].*?'
    r'(?P<ts>\d+\.\d+):\s+(?P<event>.+)'
)

file = sys.argv[1]

events = []

with open(file) as f:
    for line in f:
        m = line_re.search(line)
        if m:
            events.append(m.groupdict())

df = pd.DataFrame(events)
df["pid"] = df["pid"].astype(int)
df["ts"] = df["ts"].astype(float)

#df.to_csv("parsed_trace.csv", index=False)


# Syscall count per type
pid_features = df.groupby("pid")["event"].value_counts().unstack(fill_value=0)

# Number of wakeups
pid_features["wakeups"] = df[df["event"].str.startswith("sched_wakeup")].groupby('pid').size()

# Number of singals sent
pid_features["signals"] = df[df["event"].str.contains("sys_kill|sys_tgkill")].groupby('pid').size()

# Number of clones processes
pid_features["clones"] = df[df["event"].str.contains("sys_clone")].groupby('pid').size()

# Number of mmap calls
pid_features["mmap_calls"] = df[df["event"].str.contains("sys_mmap")].groupby('pid').size()

# Number of mprotect calls
pid_features["mprotect_calls"] = df[df["event"].str.contains("sys_mprotect")].groupby('pid').size()

# Number of munmap calls
pid_features["munmap_calls"] = df[df["event"].str.contains("sys_munmap")].groupby('pid').size()

# Number of openAt calls
pid_features["openAt_calls"] = df[df["event"].str.contains("sys_openat")].groupby('pid').size()

# Number of read calls
pid_features["write_calls"] = df[df["event"].str.contains("sys_write")].groupby('pid').size()

# Number of sendto cals
pid_features["sendto_calls"] = df[df["event"].str.contains("sys_sendto")].groupby("pid").size()

pid_features["recvfrom_calls"] = df[df["event"].str.contains("sys_recvfrom")].groupby("pid").size()

pid_features["socket_calls"] = df[df["event"].str.contains("sys_socket")].groupby("pid").size()

pid_features["execcve_analysis"] = df[df["event"].str.contains("sys_execve")].groupby("pid").size()

df_time = df.copy()
df_time["ts_ns"] = pd.to_timedelta(df_time["ts"], unit="s")
df_time = df_time.set_index("ts_ns")

# Max syscall rate per pid (1ms window)
rate = (
    df_time
    .groupby("pid")
    .resample("10ms")
    .size()
)

# PIDs that exceeded 50 syscalls in a 10ms windows
suspicious_windows = rate[rate > 50]

suspicious_pids = suspicious_windows.index.get_level_values("pid").unique()

for pid in suspicious_pids:
    max_rate = suspicious_windows.xs(pid, level="pid").max()
    print(f"[!] PID {pid} max syscall rate: {max_rate} / 10ms")

max_rate_per_pid = rate.groupby("pid").max()

pid_features["max_syscall_rate"] = max_rate_per_pid
pid_features.fillna(0, inplace=True)

fork_storm = foldStorm(df, "sys_clone", 10, window_s=0.1)
fork_storm["type"] = "fork"
plotStorm(fork_storm, pid_features, "clones")

futex_storm = foldStorm(df, "sys_futex", 100, window_s=0.1)
futex_storm["type"] = "futex"
# scheduler_wakeups_total
plotStorm(futex_storm, pid_features, "wakeups")

# sys_mmap
#print(df[df["event"].str.contains("sys_mmap")].groupby('pid').size())
mmap_analysis = foldStorm(df, "sys_mmap", 5, window_s=0.1)
mmap_analysis["type"] = "mmap"
plotStorm(mmap_analysis, pid_features, "mmap_calls")

mprotect_analysis = foldStorm(df, "sys_mprotect", 5, window_s=0.1)
mprotect_analysis["type"] = "mprotect"
plotStorm(mprotect_analysis, pid_features, "mprotect_calls")

munmap_analysis = foldStorm(df, "sys_munmap", 5, window_s=0.1)
munmap_analysis["type"] = "munmap"
plotStorm(munmap_analysis, pid_features, "munmap_calls")

openat_analysis = foldStorm(df, "sys_openat", 5, window_s=0.1)
openat_analysis["type"] = "openat"
plotStorm(openat_analysis, pid_features, "openAt_calls")

write_analysis = foldStorm(df, "sys_write", 5, window_s=0.1)
write_analysis["type"] = "write"
plotStorm(write_analysis, pid_features, "write_calls")

# unlink()?

sendto_analysis = foldStorm(df, "sys_sendto", 5, window_s=0.1)
sendto_analysis["type"] = "sendto"
plotStorm(sendto_analysis, pid_features, "sendto_calls")

recvfrom_analysis = foldStorm(df, "sys_recvfrom", 5, window_s=0.1)
recvfrom_analysis["type"] = "recvfrom"
plotStorm(recvfrom_analysis, pid_features, "recvfrom_calls")

# connect()?

# rename()?

socket_analysis = foldStorm(df, "sys_socket", 5, window_s=0.1)
socket_analysis["type"] = "socket"
plotStorm(socket_analysis, pid_features, "socket_calls")

execcve_analysis = foldStorm(df, "sys_execve", 5, window_s=0.1)
execcve_analysis["type"] = "execcve"
plotStorm(execcve_analysis, pid_features, "execcve_analysis")

all_storms = pd.concat(
    [socket_analysis, execcve_analysis, openat_analysis, recvfrom_analysis, write_analysis,
     munmap_analysis, mprotect_analysis, mmap_analysis, futex_storm, fork_storm],
    ignore_index=True
)

all_storms = all_storms.sort_values(["pid", "start"])
CORR_WINDOW = 0.05

edges = []

for pid, g in all_storms.groupby("pid"):
    storms = g.reset_index(drop=True)

    for i in range(len(storms) - 1):
        a = storms.loc[i]
        b = storms.loc[i + 1]

        dt = b.start - a.end

        if dt >= 0 and dt <= CORR_WINDOW:
            edges.append({
                "pid": pid,
                "from": a.type,
                "to": b.type,
                "dt": dt,
                "from_calls": a.calls,
                "to_calls": b.calls
            })


edge_df = pd.DataFrame(edges)

print(edge_df.columns)
print(edge_df.head())

edge_stats = (
    edge_df
    .groupby(["from", "to"])
    .agg(
        count=("dt", "count"),
        mean_dt=("dt", "mean"),
        min_dt=("dt", "min")
    )
    .reset_index()
)

storm_pid_stats = (
    all_storms
    .groupby("pid")
    .agg(
        storm_count=("start", "count"),
        total_calls=("calls", "sum"),
        syscall_types=("type", "nunique"),
        mean_duration_ms=("duration_ms", "mean"),
    )
    .reset_index()
)

edge_pid_stats = (
    edge_df
    .groupby("pid")
    .agg(
        transition_count=("dt", "count"),
        mean_transition_dt=("dt", "mean"),
        unique_transitions=("from", "nunique")
    )
    .reset_index()
)

pid_stats = storm_pid_stats.merge(
    edge_pid_stats,
    on="pid",
    how="left"
).fillna(0)

pid_stats["inv_transition_dt"] = (
    1.0 / (pid_stats["mean_transition_dt"] + 1e-6)
).clip(upper=1000)

pid_stats["suspicion_score"] = (
    pid_stats["storm_count"] * 1.5 +
    pid_stats["transition_count"] * 2.0 +
    pid_stats["syscall_types"] * 1.0 +
    pid_stats["inv_transition_dt"] * 0.5
)

pid_stats = pid_stats.sort_values(
    "suspicion_score",
    ascending=False
)

print(pid_stats.head(15))

sus_pid = pid_stats.iloc[0].pid

print("SUS pid:", sus_pid)

all_storms[all_storms.pid == sus_pid].sort_values("start")

storm_span = (
    all_storms
    .groupby("pid")
    .agg(
        first_seen=("start", "min"),
        last_seen=("end", "max")
    )
    .reset_index()
)

storm_span["active_time"] = storm_span["last_seen"] - storm_span["first_seen"]

pid_stats = pid_stats.merge(storm_span, on="pid", how="left")

pid_stats["suspicion_score"] += pid_stats["active_time"] * 10

print("SUSSY", pid_stats[pid_stats.pid == 34861])