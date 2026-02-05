from collections import defaultdict
import re
import pandas as pd
import sys
import networkx as nx
import matplotlib.pyplot as plt

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

df.to_csv("parsed_trace.csv", index=False)


# Syscall count per type
pid_features = df.groupby("pid")["event"].value_counts().unstack(fill_value=0)

# Number of wakeups
pid_features["wakeups"] = df[df["event"].str.startswith("sched_wakeup")].groupby('pid').size()

# Number of singals sent
pid_features["signals"] = df[df["event"].str.contains("sys_kill|sys_tgkill")].groupby('pid').size()

# Number of clones processes
pid_features["clones"] = df[df["event"].str.contains("sys_clone")].groupby('pid').size()

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

# Futex wake storms
# wake_features = df_time[df_time["event"].str.contains("sys_futex")]
wake_df = df[df["event"].str.contains("sys_futex")].copy()
wake_df["ts_ns"] = pd.to_timedelta(wake_df["ts"], unit="s")
wake_df = wake_df.set_index("ts_ns")


wake_ratio = (
    wake_df
    .groupby("pid")
    .resample("10ms")
    .size()
)

suspicious_futex = wake_ratio[wake_ratio > 100]

suspicious_pids = suspicious_futex.index.get_level_values("pid").unique()
#pid_features["suspicious_futex"] = suspicious_futex
#pid_features["suspicious_pids"] = suspicious_pids 
G_wake = nx.DiGraph()
plt.figure(figsize=(12,6))

for pid in suspicious_pids:
    pid_series = wake_ratio.xs(pid, level="pid")  # select PID
    pid_series.plot(label=f"PID {pid}")

plt.xlabel("Time")
plt.ylabel("Futex syscalls per 10ms")
plt.title("Futex Wake Storms per PID")
plt.legend()
plt.show()

# I cannot  test this jazz, since my dataset has no  wakeup
for idx, row in df.iterrows():
    if row["event"].startswith("sched_wakeup"):
        if "pid=" in row["event"]:
            target = int(row["event"].split("pid=")[1].split()[0])
            G_wake.add_edge(row['pid'], target, weight=G_wake[row['pid']][target]['weight']+1 if G_wake.has_edge(row['pid'], target) else 1)

# -------------------------------------------------------------------------------
# Signal storms
signal_df = df[df["event"].str.contains(
    "sys_kill|sys_tgkill|sys_rt_sigqueueinfo"
)].copy()

print("SIGNAL DFFF: ", signal_df)
signal_df["target_pid"] = (
    signal_df["event"]
    .str.extract(r"pid=(\d+)")
    .astype(float)
)

signal_df["target_tgid"] = (
    signal_df["event"]
    .str.extract(r"tgid=(\d+)")
    .astype(float)
)

signal_df["ts_ns"] = pd.to_timedelta(signal_df["ts"], unit="s")
signal_df = signal_df.set_index("ts_ns")

target_pid_rate = (
    signal_df
    .dropna(subset=["target_pid"])
    .groupby("target_pid")
    .resample("10ms")
    .size()
)

thread_signal_storms = target_pid_rate[target_pid_rate > 50]

tgid_rate = (
    signal_df
    .dropna(subset=["target_tgid"])
    .groupby("target_tgid")
    .resample("10ms")
    .size()
)

process_signal_storms = tgid_rate[tgid_rate > 100]

sender_rate = (
    signal_df
    .groupby("pid")
    .resample("10ms")
    .size()
)

signal_spammers = sender_rate[sender_rate > 50]

pair_rate = (
    signal_df
    .dropna(subset=["target_pid"])
    .groupby(["pid", "target_pid"])
    .resample("10ms")
    .size()
)

pair_storms = pair_rate[pair_rate > 20]

signal_storm_score = (
    sender_rate
    .groupby("pid")
    .max()
)

# Fold per pid
pid_features["signal_storm_score"] = signal_storm_score
pid_features["signal_storm"] = pid_features["signal_storm_score"] > 50

# Fold per target pid
target_pid_storm_score = (
    signal_df
    .dropna(subset=["target_pid"])
    .groupby("target_pid")
    .resample("10ms")
    .size()
)

max_target_pid_storm_score = target_pid_storm_score.groupby("target_pid").max()


pid_features["signal_target_pid_storm_score"] = pid_features.index.map(max_target_pid_storm_score)
pid_features["signal_target_pid"] = pid_features["signal_target_pid_storm_score"] > 50

target_tgid_storm_score = (
    signal_df
    .dropna(subset=["target_tgid"])
    .groupby("target_tgid")
    .resample("10ms")
    .size()
)

max_target_tgid_storm_score = target_tgid_storm_score.groupby("target_tgid").max()

pid_features["signal_target_tpid_storm_score"] = pid_features.index.map(max_target_tgid_storm_score)
pid_features["signal_target_tpid"] = pid_features["signal_target_tpid_storm_score"] > 50

G_signal = nx.DiGraph()

#for idx, row in df[df["event"].str.contains("sys_kill|sys_tgkill|sys_rt_sigqueueinfo")]:
    #target = int(row["event"].split("pid=")[1].split()[0])
    #G_signal.add_edge(row['pid'], target, weight=G_signal[row['pid']][target]['weight']+1 if G_signal.has_edge(row['pid'], target) else 1)

target_pid_rate_df = target_pid_rate.unstack(level=0).fillna(0)
print("TARGET PID RATE: ", target_pid_rate)
plt.figure(figsize=(11, 6))
for pid in target_pid_rate_df.columns:
    plt.plot(target_pid_rate_df.index.total_seconds(), target_pid_rate_df[pid], label=f"PID {int(pid)}")

plt.xlabel("Time (s)")
plt.ylabel("Signals received per 10ms")
plt.title("Signal Reception per Target PID Over Time")
plt.legend()
plt.show()

tgid_rate_df = tgid_rate.unstack(level=0).fillna(0)
plt.figure(figsize=(11,6))
for pid in tgid_rate_df.columns:
    plt.plot(tgid_rate_df.index.total_seconds(), tgid_rate_df[pid], label=f"PID {int(pid)}")
plt.xlabel("Time (s)")
plt.ylabel("Signals received per 10ms")
plt.title("Signal Reception per tgid PID over time")
plt.legend()
plt.show()


# ------------------------------------------------------------------------
# Fork storm -> Clone storm
clone_df = df[df["event"].str.contains("sys_clone")].copy()

# Time analysis
clone_df["ts_ns"] = pd.to_timedelta(clone_df['ts'], unit="s")
clone_df = clone_df.set_index("ts_ns")

# Compute clone rate per PID
clone_rate = (
    clone_df
    .groupby("pid")
    .resample("10ms")
    .size()
)

# Extract the storm score
clone_storm_score = clone_rate.groupby("pid").max()

# Fold the clone score
pid_features["clone_storm_score"] = clone_storm_score
pid_features["clone_storm"] = pid_features["clone_storm_score"] > 10


# Graph impact on other processes.
G = nx.DiGraph()
G_clone = nx.DiGraph()

for idx, row in df[df["event"].str.contains("sys_clone")].iterrows():
    pid_match = re.search(r"pid=(\d+)", row["event"])
    if pid_match:
        child_pid = int(pid_match.group(1))
        parent_pid = row['pid']
        if G_clone.has_edge(parent_pid, child_pid):
            G_clone[parent_pid][child_pid]['weight'] += 1
        else:
            G_clone.add_edge(parent_pid, child_pid, weight=1)

storm_pids = pid_features[
    pid_features["clone_storm"]
].index.tolist()

nodes = set(storm_pids)

for pid in storm_pids:
    if pid in G_clone:
        nodes.update(G_clone.successors(pid))

H = G_clone.subgraph(nodes)

plt.figure(figsize=(11, 11))

pos = nx.spring_layout(H, seed=42)

node_sizes = [
    300 + 10 * pid_features.loc[n, "clone_storm_score"]
    for n in H.nodes()
]

node_colors = [
    "red" if n in storm_pids else "lightgray"
    for n in H.nodes()
]

nx.draw(
    H, pos,
    node_size=node_sizes,
    node_color=node_colors,
    arrows=True,
    with_labels=True,
    font_size=8
)

edge_labels = nx.get_edge_attributes(H, "weight")
nx.draw_networkx_edge_labels(H, pos, edge_labels=edge_labels, font_size=7)

plt.title("Fork Storm Subgraph (folded + visualized)")
plt.show()

print("Number of storm PIDs:", len(storm_pids))
print("Number of nodes in H:", H.number_of_nodes())
print("Number of edges in H:", H.number_of_edges())

# High out-degree in wakeup graph


nx.write_gexf(G, "pid_graph.gexf")
print("PID graph exported to GEXF for visualization")

#plt.figure(figsize=(10, 10))

pos = nx.spring_layout(G, seed=42)

# Unweighted out-degree
#out_deg = dict(G.out_degree())

# Weighted out-degree
#weighted_out_deg = dict(G.out_degree(weight='weight'))

# Sort to find most “impactful” PIDs
#sorted(weighted_out_deg.items(), key=lambda x: x[1], reverse=True)

#nx.draw(G, pos, with_labels=True, node_size=800, node_color="lightblue", arrows=True, font_size=8)

#plt.title("PID Wakeup Graph")
#plt.show()

# Sliding time windows

# 1️⃣ Make sure we have TimedeltaIndex
df_time["ts_ns"] = pd.to_timedelta(df_time["ts"], unit="s")
df_time = df_time.set_index("ts_ns")

# 2️⃣ Resample per PID into 1ms bins
binned = df_time.groupby("pid").resample("1ms")["event"].count()

# 3️⃣ Apply sliding window of 10 bins (10ms)
sliding_rate = binned.groupby("pid").rolling(window=10, min_periods=1).sum()

# 4️⃣ Reset index for plotting
sliding_rate = sliding_rate.reset_index(level=0, drop=True)

pid_example = 2312
sliding_rate.loc[pid_example].plot(figsize=(10,5))  # selects all times for this PID
plt.title(f"Sliding 10ms event rate for PID {pid_example}")
plt.xlabel("Time")
plt.ylabel("Events per 10ms")
plt.show()