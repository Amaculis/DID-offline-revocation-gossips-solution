from __future__ import annotations
import os
import math
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")

COLORS = {
    "PULL":   "#534AB7",
    "PUSH":   "#D85A30",
    "GOSSIP": "#0F6E56",
    "MIXED":  "#185FA5",
}

STRATEGY_ORDER = ["PULL", "PUSH", "GOSSIP", "MIXED"]

X_LABELS = {
    "dead_ratio":            "Dead ratio",
    "offline_ratio":         "Offline ratio",
    "revocation_rate":       "Revocation rate (events/s)",
    "ttl":                   "TTL (s)",
    "network_size":          "Network size (nodes)",
    "mean_offline_duration": "Mean offline duration (s)",
    "mean_online_duration":  "Mean online duration (s)",
}


def plot_sweep(sweep_dim: str, df: pd.DataFrame, out_path: str):
    fig, axes = plt.subplots(3, 1, figsize=(12, 10))
    fig.suptitle(f"Strategy comparison — sweep: {sweep_dim}", fontsize=14, fontweight="bold")

    x_label = X_LABELS.get(sweep_dim, sweep_dim)

    subplots = [
        ("far",              "False Acceptance Rate",         "FAR",      mticker.PercentFormatter(xmax=1)),
        ("delay_mean",       "Propagation Delay Mean (s)",    "Delay (s)", None),
        ("bandwidth_mb",     "Total Bandwidth (MB)",          "MB",        None),
    ]

    strategies = [s for s in STRATEGY_ORDER if s in df["strategy"].unique()]

    for ax, (col, title, ylabel, formatter) in zip(axes, subplots):
        for strategy in strategies:
            sub = df[df["strategy"] == strategy].sort_values("sweep_value")
            x = sub["sweep_value"]
            y = sub[col]

            # Drop NaN for delay
            mask = y.notna() & y.apply(lambda v: not (isinstance(v, float) and math.isnan(v)))
            x_plot = x[mask]
            y_plot = y[mask]

            if x_plot.empty:
                continue

            ax.plot(
                x_plot, y_plot,
                marker="o", linewidth=2, markersize=5,
                color=COLORS.get(strategy, None),
                label=strategy,
            )

        ax.set_title(title, fontsize=11)
        ax.set_xlabel(x_label)
        ax.set_ylabel(ylabel)
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=9)
        if formatter:
            ax.yaxis.set_major_formatter(formatter)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {out_path}")


def main():
    sweep_dims = [
        "dead_ratio", "offline_ratio", "revocation_rate", "ttl",
        "network_size", "mean_offline_duration", "mean_online_duration",
    ]
    for sweep_dim in sweep_dims:
        csv_path = os.path.join(RESULTS_DIR, f"sweep_{sweep_dim}.csv")
        if not os.path.exists(csv_path):
            print(f"  Skipping {sweep_dim} — CSV not found: {csv_path}")
            continue
        df = pd.read_csv(csv_path)
        out_path = os.path.join(RESULTS_DIR, f"sweep_{sweep_dim}.png")
        plot_sweep(sweep_dim, df, out_path)


if __name__ == "__main__":
    main()
