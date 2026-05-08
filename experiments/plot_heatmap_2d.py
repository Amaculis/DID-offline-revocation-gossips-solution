import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

STRATEGIES  = ["PULL", "PUSH", "GOSSIP", "MIXED"]
COLORS      = {
    "PULL":   "Reds",
    "PUSH":   "Oranges",
    "GOSSIP": "Greens",
    "MIXED":  "Blues",
}
METRIC_LABELS = {
    "far_mean":          "FAR (kļūdainas pieņemšanas līmenis)",
    "delay_mean_mean":   "Izplatīšanas aizkave, vidējā (s)",
    "bandwidth_per_node_kb_mean": "Joslas platums uz mezglu (KB)",
    "coverage_rate_mean": "Pārklājuma līmenis (coverage rate)",
}

def fmt_seconds(val):
    if val < 3600:
        return f"{int(val//60)}min"
    return f"{int(val//3600)}h"

def fmt_metric(val, metric):
    if "far" in metric or "rate" in metric or "coverage" in metric:
        return f"{val*100:.1f}%"
    if "delay" in metric:
        if val >= 3600:
            return f"{val/3600:.1f}h"
        return f"{val:.0f}s"
    if "bandwidth" in metric or "kb" in metric.lower():
        return f"{val:.0f}"
    return f"{val:.2f}"


def plot_heatmaps(csv_path: str, metric: str, shared_scale: bool, output: str):
    df = pd.read_csv(csv_path)

    if metric not in df.columns:
        available = [c for c in df.columns if not c.endswith(("_std","_ci95"))]
        raise ValueError(f"Metric '{metric}' not found. Available: {available}")

    online_vals  = sorted(df["mean_online_duration"].unique())
    offline_vals = sorted(df["mean_offline_duration"].unique())

    x_labels = [fmt_seconds(v) for v in online_vals]
    y_labels = [fmt_seconds(v) for v in offline_vals]

    fig, axes = plt.subplots(2, 2, figsize=(12, 9))
    fig.suptitle(
        f"Stratēģiju salīdzinājums — {METRIC_LABELS.get(metric, metric)}\n"
        f"X: vidējais tiešsaistes ilgums   |   Y: vidējais bezsaistes ilgums",
        fontsize=13, y=1.01
    )

    
    if shared_scale:
        all_vals = df[metric].dropna()
        vmin, vmax = all_vals.min(), all_vals.max()
    else:
        vmin = vmax = None

    for ax, strategy in zip(axes.flat, STRATEGIES):
        sub = df[df["strategy"] == strategy]

        
        matrix = pd.DataFrame(index=offline_vals, columns=online_vals, dtype=float)
        for _, row in sub.iterrows():
            matrix.loc[row["mean_offline_duration"], row["mean_online_duration"]] = row[metric]

     
        annot = matrix.map(lambda v: fmt_metric(v, metric) if pd.notna(v) else "")

        sns.heatmap(
            matrix.astype(float),
            ax=ax,
            annot=annot,
            fmt="",
            cmap=COLORS[strategy],
            linewidths=0.5,
            linecolor="white",
            xticklabels=x_labels,
            yticklabels=y_labels,
            vmin=vmin,
            vmax=vmax,
            cbar_kws={"shrink": 0.8, "label": METRIC_LABELS.get(metric, metric)},
        )
        ax.set_title(strategy, fontsize=12, fontweight="bold")
        ax.set_xlabel("Tiešsaistes ilgums", fontsize=10)
        ax.set_ylabel("Bezsaistes ilgums", fontsize=10)
        ax.tick_params(labelsize=9)

    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches="tight")
    print(f"Saved → {output}")
    plt.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot 2D sweep heatmaps")
    parser.add_argument(
        "--csv",
        default="sweep2d_mean_online_duration_x_mean_offline_duration.csv",
        help="Path to the 2D sweep CSV file",
    )
    parser.add_argument(
        "--metric",
        default="far_mean",
        choices=list(METRIC_LABELS.keys()),
        help="Which metric to visualize",
    )
    parser.add_argument(
        "--shared-scale",
        action="store_true",
        help="Use the same color scale across all 4 heatmaps",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output filename (default: heatmap_<metric>.png)",
    )
    args = parser.parse_args()

    output = args.output or f"heatmap_{args.metric}.png"
    plot_heatmaps(args.csv, args.metric, args.shared_scale, output)