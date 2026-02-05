from collections import defaultdict
import re
import pandas as pd
import sys
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np

def td_to_seconds(td):
    return td.total_seconds()

def foldStorm(df, event_filter, threshold, window_s=0.01):
    temp = df[df["event"].str.contains(event_filter)].copy()
    print("TEMPP:", temp)
    if temp.empty:
        return pd.DataFrame()
    
    temp["ts"] = temp["ts"].astype(float)
    storms = []
    
    for pid, g in temp.groupby("pid"):
        times = g["ts"].sort_values().values.astype(float)
        #print("TIMES:", times)
        start_idx = 0
        n = len(times)
        
        while start_idx < n:
            start_time = times[start_idx]
            # find all events in the window
            end_time = start_time + window_s
            in_window = (times >= start_time) & (times < end_time)
            #print("IN WINDOW: ", in_window)
            count = in_window.sum()
            #print("COUNT: ", count)
            
            if count >= threshold:
                storms.append({
                    "pid": pid,
                    "start": start_time,
                    "end": end_time,
                    "calls": count,
                    "peak": count,
                    "duration_ms": window_s * 1000
                })
                #print("STORM: ", storms)
                # slide past this window
                start_idx += np.argmax(in_window[::-1]) + 1
            else:
                start_idx += 1
    
    return pd.DataFrame(storms)




def plotStorm(storms_df, pid_features, columnName):
    if storms_df.empty:
        return None
    
    storms_df[columnName] = storms_df["pid"].map(
        pid_features[columnName]
    ).fillna(0)

    storms_df["max_syscall_rate"] = storms_df["pid"].map(
        pid_features["max_syscall_rate"]
    )

    storms_df["storm_score"] = (
        storms_df["calls"] *
        storms_df["peak"] *
        storms_df["duration_ms"]
    )
    plt.figure(figsize=(12,4))
    for _, row in storms_df.iterrows():
        plt.hlines(
            y=row["pid"],
            xmin=row["start"],
            xmax=row["end"],
            linewidth=4
        )

    plt.xlabel("Time")
    plt.ylabel("PID")
    plt.title(f"Folded {columnName} Storms")
    plt.show()
