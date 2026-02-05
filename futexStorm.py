from collections import defaultdict
import re
import pandas as pd
import sys
import networkx as nx
import matplotlib.pyplot as plt

def td_to_seconds(td):
    return td.total_seconds()

def futexStorm(df, pid_features):
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

    storm_threshold = 100
    storms = []

    for pid, series in wake_ratio.groupby(level="pid"):
        s = series.droplevel("pid")
        active = s[s > storm_threshold]

        if active.empty:
            continue

        groups = (active.index.to_series().diff() > pd.Timedelta("10ms")).cumsum()

        for _, g in active.groupby(groups):
            storms.append({
                "pid": pid,
                "start": g.index.min(),
                "end": g.index.max(),
                "duration_ms": (g.index.max() - g.index.min()).total_seconds() * 1000,
                "calls": g.sum(),
                "peak_rate": g.max()
            })
    storms_df = pd.DataFrame(storms)

    storms_df["wakeups"] = storms_df["pid"].map(
        pid_features["wakeups"]
    ).fillna(0)

    storms_df["max_syscall_rate"] = storms_df["pid"].map(
        pid_features["max_syscall_rate"]
    )

    storms_df["storm_score"] = (
        storms_df["calls"] *
        storms_df["peak_rate"] *
        storms_df["duration_ms"]
    )

    plt.figure(figsize=(12,4))
    for _, row in storms_df.iterrows():
        plt.hlines(
            y=row["pid"],
            xmin=td_to_seconds(row["start"]),
            xmax=td_to_seconds(row["end"]),
            linewidth=4
        )

    plt.xlabel("Time")
    plt.ylabel("PID")
    plt.title("Folded Futex Storms")
    plt.show()
