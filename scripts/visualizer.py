import matplotlib
matplotlib.use('Agg')

import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import os

sns.set_theme(style="whitegrid", palette="dark")

def plot_top_talkers(df, output_dir=".", top_n=10):
    output_path = os.path.join(output_dir, "top_talkers.png")
    plt.figure(figsize=(10, 6))

    top_talkers = (
        df.groupby(["src_ip", "dst_ip"])
        .size()
        .reset_index(name="count")
        .sort_values(by="count", ascending=False)
        .head(top_n)
    )

    top_talkers["pair"] = top_talkers["src_ip"] + " -> " + top_talkers["dst_ip"]

    ax = sns.barplot(
        data=top_talkers,
        x="count",
        y="pair",
        hue="pair",
        legend=False,
        palette="Blues_d"
    )

    ax.set_title("Top Communication Pairs", fontsize=14, fontweight="bold")
    ax.set_xlabel("Packet Count", fontsize=12)
    ax.set_ylabel("Source -> Destination", fontsize=12)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def plot_dns_queries(df, output_dir="."):
    '''
    Seaches for top requested domains.
    '''

    output_path = os.path.join(output_dir, "top_domain_queries.png")

    plt.figure(figsize=(10, 5))

    top_dq = df["qname"].value_counts().head(10).reset_index()
    top_dq.columns = ["Domain", "Query Count"]

    ax = sns.barplot(
        data=top_dq,
        x="Query Count",
        y="Domain",
        hue="Domain",
        legend=False,
        palette="Blues_d"
    )

    ax.set_title("Top Requested Domains (DNS)", fontsize=14, fontweight="bold")

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def plot_rare_dns_queries(df, output_dir=".", top_n=10):
    """
    Searches for interesting infrequent DNS queries to spot outliers.
    """

    output_path = os.path.join(output_dir, "rare_domain_queries.png")

    if "qname" not in df.columns:
        print("[-] 'qname' column not found in DataFrame.")
        return

    dq_counts = df["qname"].dropna().value_counts().reset_index()
    dq_counts.columns = ["Domain", "Query Count"]

    rare_dq = dq_counts[dq_counts["Query Count"] == 1]
    if rare_dq.empty:
        rare_dq = dq_counts.tail(top_n)
    else:
        rare_dq = rare_dq.head(top_n)

    plt.figure(figsize=(10, 5))

    ax = sns.barplot(
        data=rare_dq,
        x="Query Count",
        y="Domain",
        hue="Domain",
        legend=False,
        palette="Oranges_r"
    )

    ax.set_title("Infrequent Domain Queries", fontsize=14, fontweight="bold")
    ax.set_xlabel("Query Count", fontsize=12)
    ax.set_ylabel("Domain", fontsize=12)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def detect_and_plot_beacons(df, output_dir=".", min_packets=10, max_std=1.0):
    """
    Scans communication pairs for low standard deviation in time deltas to highlight possible automated beaconing behavior.
    """

    output_path = os.path.join(output_dir, "beacon_analysis.png")

    df = df.sort_values(by="time")
    df["pair_time_delta"] = df.groupby(["src_ip", "dst_ip"])["time"].diff()
   
    grouped = df.groupby(["src_ip", "dst_ip"])["pair_time_delta"]
    
    summary = pd.DataFrame({
        "packet_count": grouped.count(),
        "mean_delta": grouped.mean(),
        "std_delta": grouped.std()
    }).dropna()

    beacons = summary[
        (summary["packet_count"] >= min_packets) & 
        (summary["std_delta"] <= max_std) & 
        (summary["mean_delta"] > 0.5)
    ].sort_values(by="std_delta")
    
    if beacons.empty:
        plt.close()
        return beacons

    top_beacon_pair = beacons.index[0]
    src, dst = top_beacon_pair
    
    beacon_data = df[(df["src_ip"] == src) & (df["dst_ip"] == dst)]

    plt.figure(figsize=(10, 5))
    ax = sns.histplot(data=beacon_data, x="pair_time_delta", bins=30, kde=True, color="crimson")
    
    ax.set_title(f"Potential C2 Beaconing Detected\n{src} -> {dst} (Mean Interval: {beacons.loc[top_beacon_pair, 'mean_delta']:.2f}s)", fontsize=13, fontweight="bold")
    ax.set_xlabel("Inter-Arrival Time Delta (Seconds)", fontsize=12)
    ax.set_ylabel("Frequency", fontsize=12)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

    return beacons

def plot_unusal_ports(df, output_dir=".", top_n=10):
    """
    Visualizes the top destination ports to help spot unusual services.
    """

    output_path = os.path.join(output_dir, "top_destination_ports.png")

    if "dport" not in df.columns:
        print("[-] 'dport' column not found in DataFrame")
        return

    plt.figure(figsize=(10, 5))
    
    port_counts = df["dport"].dropna().value_counts().head(top_n).reset_index()
    port_counts.columns = ["port", "count"]
    port_counts["port_str"] = port_counts["port"].astype(str)

    ax = sns.barplot(
        data=port_counts, 
        x="count", 
        y="port_str", 
        hue="port_str", 
        legend=False, 
        palette="Blues_d"
    )
    
    ax.set_title("High Destination Port Count", fontsize=14, fontweight="bold")
    ax.set_xlabel("Packet Count", fontsize=12)
    ax.set_ylabel("Destination Port", fontsize=12)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def plot_sni(df, output_dir=".", top_n=10):
    '''
    Searches for interesting TLS hostnames for potential outliers.
    '''

    output_path = os.path.join(output_dir, "sni_domains.png")

    if "sni" not in df.columns:
        print("[-] 'sni' column not found in DataFrame.")
        return

    sni_df = df["sni"].dropna()

    if sni_df.empty:
        print("[-] No TLS SNI data to plot.")
        return

    sni_counts = sni_df.value_counts().reset_index()
    sni_counts.columns = ["domain", "count"]

    rare_sni = sni_counts[sni_counts["count"] == 1]
    if rare_sni.empty:
        rare_sni = sni_counts.tail(top_n)
    else:
        rare_sni = rare_sni.head(top_n)

    plt.figure(figsize=(10, 5))

    ax = sns.barplot(
        data=rare_sni,
        x="count",
        y="domain",
        hue="domain",
        legend=False,
        palette="Purples_r"
    )

    ax.set_title("Interesting TLS SNI Hostnames - Outliers", fontsize=14, fontweight="bold")
    ax.set_xlabel("Connection Count", fontsize=12)
    ax.set_ylabel("SNI Domain", fontsize=12)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def plot_uris(df, output_dir=".", top_n=10):
    '''
    Searches for interesting URIs.
    '''

    output_path = os.path.join(output_dir, "interesting_uris.png")

    if "path" not in df.columns:
        print("[-] 'uri' column not found in DataFrame.")
        return

    uri_df = df["path"].dropna()
    
    if uri_df.empty:
        print("[-] No URI data to plot.")
        return

    uri_counts = uri_df.value_counts().reset_index()
    uri_counts.columns = ["uri", "count"]

    top_uris = uri_counts[uri_counts["uri"] != "/"].head(top_n)
    
    if top_uris.empty:
        top_uris = uri_counts.head(top_n)

    plt.figure(figsize=(10, 5))

    ax = sns.barplot(
        data=top_uris, 
        x="count", 
        y="uri", 
        hue="uri", 
        legend=False, 
        palette="Blues_d"
    )
    
    ax.set_title("Top Requested URIs", fontsize=14, fontweight="bold")
    ax.set_xlabel("Request Count", fontsize=12)
    ax.set_ylabel("URI Path", fontsize=12)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def plot_rare_uris(df, output_dir=".", top_n=10):
    """
    Searches for interesting infequent URIs for potential outliers.
    """

    output_path = os.path.join(output_dir, "rare_uris.png")

    if "path" not in df.columns:
        print("[-] 'path' column not found in DataFrame.")
        return

    uri_df = df["path"].dropna()
    
    if uri_df.empty:
        print("[-] No URI data to plot.")
        return

    uri_counts = uri_df.value_counts().reset_index()
    uri_counts.columns = ["uri", "count"]

    filtered_uris = uri_counts[uri_counts["uri"] != "/"]
    if filtered_uris.empty:
        filtered_uris = uri_counts

    rare_uris = filtered_uris[filtered_uris["count"] == 1]
    if rare_uris.empty:
        rare_uris = filtered_uris.tail(top_n)
    else:
        rare_uris = rare_uris.head(top_n)

    plt.figure(figsize=(10, 5))

    ax = sns.barplot(
        data=rare_uris, 
        x="count", 
        y="uri", 
        hue="uri", 
        legend=False, 
        palette="Oranges_r"
    )
    
    ax.set_title("Infrequent URIs", fontsize=14, fontweight="bold")
    ax.set_xlabel("Request Count", fontsize=12)
    ax.set_ylabel("URI Path", fontsize=12)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()