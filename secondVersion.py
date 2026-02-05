from collections import defaultdict
import re
import pandas as pd
import sys
import networkx as nx
import matplotlib.pyplot as plt
from foldStorm import *


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
plotStorm(fork_storm, pid_features, "clones")

futex_storm = foldStorm(df, "sys_futex", 100, window_s=0.1)
# scheduler_wakeups_total
plotStorm(futex_storm, pid_features, "wakeups")

# sys_mmap
#print(df[df["event"].str.contains("sys_mmap")].groupby('pid').size())
mmap_analysis = foldStorm(df, "sys_mmap", 5, window_s=0.1)
plotStorm(mmap_analysis, pid_features, "mmap_calls")

temp = df[df["event"].str.contains("sys_mmap")].copy()
temp["ts_norm"] = temp["ts"] - temp["ts"].min()
temp["ts_ns"] = pd.to_timedelta(temp["ts_norm"], unit="s")
temp = temp.set_index("ts_ns").sort_index()

rate = temp.groupby("pid").resample("10ms", level="ts_ns").size()

#print(rate.describe())

