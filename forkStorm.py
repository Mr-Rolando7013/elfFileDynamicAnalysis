from collections import defaultdict
import re
import pandas as pd
import sys
import networkx as nx
import matplotlib.pyplot as plt

def forkStorm(df, pid_features):
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