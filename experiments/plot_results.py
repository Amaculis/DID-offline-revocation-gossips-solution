from __future__ import annotations
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")

COLORS = {
    "PULL":   "#534AB7",
    "PUSH":   "#D85A30",
    "GOSSIP": "#0F6E56",
    "HIBRĪDA":  "#185FA5",
    "MIXED":  "#185FA5",
}

STRATEGY_ORDER = ["PULL", "PUSH", "GOSSIP", "HIBRĪDA","MIXED"]

X_LABELS = {
    "dead_ratio":            "Dead ratio",
    "offline_ratio":         "Offline ratio",
    "revocation_rate":       "Revocation rate (events/s)",
    "ttl":                   "TTL (s)",
    "network_size":          "Network size (nodes)",
    "mean_offline_duration": "Mean offline duration (s)",
    "mean_online_duration":  "Mean online duration (s)",
}

SUBPLOTS = [
    ("far",                   "False Acceptance Rate",      "FAR",       mticker.PercentFormatter(xmax=1)),
    ("delay_mean",            "Propagation Delay Mean (s)", "Delay (s)", None),
    ("bandwidth_mb",          "Total Bandwidth (MB)",       "MB",        None),
    ("bandwidth_per_node_kb", "Bandwidth per Node (KB)",    "KB",        None),
]


def _ci95_col(df: pd.DataFrame, mean_col: str) -> np.ndarray:
    ci_col = mean_col.replace("_mean", "_ci95")
    if ci_col in df.columns:
        return df[ci_col].to_numpy(dtype=float)
    std_col = mean_col.replace("_mean", "_std")
    if std_col not in df.columns:
        return np.full(len(df), np.nan)
    std = df[std_col].to_numpy(dtype=float)
    n = df["n_runs"].to_numpy(dtype=float) if "n_runs" in df.columns else np.full(len(df), 1.0)
    return 1.96 * std / np.sqrt(np.maximum(n, 1))


def _add_pull_linear_fit(ax, x: np.ndarray, y: np.ndarray):
   
    valid = ~np.isnan(y) & ~np.isnan(x) & (x > 0)
    if valid.sum() < 2:
        return
    k = np.mean(y[valid] / x[valid])
    x_line = np.linspace(0, x[valid].max(), 100)
    ax.plot(x_line, k * x_line, linestyle="--", linewidth=1.2,
            color=COLORS["PULL"], alpha=0.6, label=f"PULL fit: FAR≈{k:.2f}·dead_ratio")
    ax.legend(fontsize=8)


def plot_sweep(sweep_dim: str, df: pd.DataFrame, out_path: str):
    strategies = [s for s in STRATEGY_ORDER if s in df["strategy"].unique()]
    fig, axes = plt.subplots(len(SUBPLOTS), 1, figsize=(12, 4 * len(SUBPLOTS)))
    fig.suptitle(f"Strategy comparison — sweep: {sweep_dim}", fontsize=14, fontweight="bold")

    x_label = X_LABELS.get(sweep_dim, sweep_dim)

    for ax, (col, title, ylabel, formatter) in zip(axes, SUBPLOTS):
        mean_col = col + "_mean"
        any_data = False

        for strategy in strategies:
            sub = df[df["strategy"] == strategy].sort_values("sweep_value")
            x   = sub["sweep_value"].to_numpy()
            y   = sub[mean_col].to_numpy(dtype=float)
            ci  = _ci95_col(sub, mean_col)

            valid = ~np.isnan(y)

            nan_x = x[~valid]
            if len(nan_x) > 0:
                color = COLORS.get(strategy)
                for nx in nan_x:
                    ax.axvline(nx, color=color, linewidth=0.5, alpha=0.3, linestyle=":")

            if not valid.any():
                continue
            any_data = True

            color = COLORS.get(strategy)
            ax.plot(x[valid], y[valid], marker="o", linewidth=2, markersize=5,
                    color=color, label=strategy)

            
            lo = y - ci
            hi = y + ci
            finite_ci = ~np.isnan(ci)
            if (valid & finite_ci).any():
                mask = valid & finite_ci
                ax.fill_between(x[mask], lo[mask], hi[mask], alpha=0.15, color=color)

        if sweep_dim == "dead_ratio" and col == "far" and "PULL" in strategies:
            pull_sub = df[df["strategy"] == "PULL"].sort_values("sweep_value")
            _add_pull_linear_fit(ax,
                                 pull_sub["sweep_value"].to_numpy(),
                                 pull_sub[mean_col].to_numpy(dtype=float))

        if not any_data:
            ax.text(0.5, 0.5, "No data", transform=ax.transAxes,
                    ha="center", va="center", fontsize=12, color="gray")
        elif col == "bandwidth_mb":
            ax.text(0.01, 0.98, "Dotted verticals = strategy did not produce data (NaN)",
                    transform=ax.transAxes, ha="left", va="top",
                    fontsize=7, color="gray", style="italic")

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


def plot_2d_sweep(csv_path: str, dim_x: str, dim_y: str):
    df = pd.read_csv(csv_path)
    strategies = [s for s in STRATEGY_ORDER if s in df["strategy"].unique()]

    for metric, metric_label in [("far_mean", "FAR"), ("delay_mean_mean", "Delay mean (s)")]:
        fig, axes = plt.subplots(1, len(strategies), figsize=(5 * len(strategies), 5), squeeze=False)
        fig.suptitle(f"{metric_label} — {dim_x} × {dim_y}", fontsize=13, fontweight="bold")

        values_x = sorted(df[dim_x].unique())
        values_y = sorted(df[dim_y].unique())

        for ax, strategy in zip(axes[0], strategies):
            sub = df[df["strategy"] == strategy]
            grid = np.full((len(values_x), len(values_y)), np.nan)
            for i, vx in enumerate(values_x):
                for j, vy in enumerate(values_y):
                    row = sub[(sub[dim_x] == vx) & (sub[dim_y] == vy)]
                    if not row.empty and metric in row.columns:
                        grid[i, j] = row[metric].values[0]

            X, Y = np.meshgrid(values_y, values_x)
            im = ax.pcolormesh(X, Y, grid, shading="auto", cmap="YlOrRd")
            fig.colorbar(im, ax=ax, label=metric_label)
            ax.set_title(strategy, fontsize=11, color=COLORS.get(strategy, "black"))
            ax.set_xlabel(dim_y)
            ax.set_ylabel(dim_x)
            ax.set_yscale("log")

        plt.tight_layout()
        slug = metric.replace("_mean", "")
        out_path = os.path.join(RESULTS_DIR, f"sweep2d_{dim_x}_x_{dim_y}_{slug}.png")
        plt.savefig(out_path, dpi=150)
        plt.close(fig)
        print(f"  Saved: {out_path}")


def plot_scaling(csv_path: str):
    df = pd.read_csv(csv_path)
    strategies = [s for s in STRATEGY_ORDER if s in df["strategy"].unique()]

    metrics = [
        ("far_mean",                   "far_ci95",                   "False Acceptance Rate",      mticker.PercentFormatter(xmax=1)),
        ("delay_mean_mean",            "delay_mean_ci95",            "Propagation Delay Mean (s)", None),
        ("bandwidth_per_node_kb_mean", "bandwidth_per_node_kb_ci95", "Bandwidth per Node (KB)",    None),
        ("coverage_rate_mean",         "coverage_rate_ci95",         "Coverage Rate (≥95% reach)", mticker.PercentFormatter(xmax=1)),
    ]

    fig, axes = plt.subplots(len(metrics), 1, figsize=(12, 4 * len(metrics)))
    fig.suptitle("Scaling: metrics vs network size (normalised contact_rate)",
                 fontsize=14, fontweight="bold")

    for ax, (col, ci_col, ylabel, formatter) in zip(axes, metrics):
        any_data = False
        for strategy in strategies:
            sub = df[df["strategy"] == strategy].sort_values("network_size")
            x   = sub["network_size"].to_numpy()
            y   = sub[col].to_numpy(dtype=float) if col in sub.columns else np.full(len(x), np.nan)
            ci  = sub[ci_col].to_numpy(dtype=float) if ci_col in sub.columns else np.full(len(x), np.nan)

            valid = ~np.isnan(y)
            nan_x = x[~valid]
            color = COLORS.get(strategy)
            for nx in nan_x:
                ax.axvline(nx, color=color, linewidth=0.5, alpha=0.3, linestyle=":")

            if not valid.any():
                continue
            any_data = True
            ax.plot(x[valid], y[valid], marker="o", linewidth=2, markersize=5,
                    color=color, label=strategy)
            mask = valid & ~np.isnan(ci)
            if mask.any():
                ax.fill_between(x[mask], (y - ci)[mask], (y + ci)[mask],
                                alpha=0.15, color=color)

        if not any_data:
            ax.text(0.5, 0.5, "No data", transform=ax.transAxes,
                    ha="center", va="center", fontsize=12, color="gray")

        ax.set_xscale("log")
        ax.set_xlabel("Network size (nodes)")
        ax.set_ylabel(ylabel)
        ax.set_title(ylabel, fontsize=11)
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=9)
        if formatter:
            ax.yaxis.set_major_formatter(formatter)

    plt.tight_layout()
    out_path = os.path.join(RESULTS_DIR, "scaling_network_size.png")
    plt.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {out_path}")


def main():
    sweep_dims = list(X_LABELS.keys())
    for sweep_dim in sweep_dims:
        csv_path = os.path.join(RESULTS_DIR, f"sweep_{sweep_dim}.csv")
        if not os.path.exists(csv_path):
            print(f"  Skipping {sweep_dim} — CSV not found: {csv_path}")
            continue
        df = pd.read_csv(csv_path)
        out_path = os.path.join(RESULTS_DIR, f"sweep_{sweep_dim}.png")
        plot_sweep(sweep_dim, df, out_path)

    scaling_csv = os.path.join(RESULTS_DIR, "scaling_network_size.csv")
    if os.path.exists(scaling_csv):
        plot_scaling(scaling_csv)
    else:
        print("  Skipping scaling plot — CSV not found: scaling_network_size.csv")
        print("  Run: python experiments/run_scaling.py")

    sweeps_2d = [
        ("ttl", "dead_ratio"),
        ("mean_online_duration", "mean_offline_duration"),
    ]
    for dim_x, dim_y in sweeps_2d:
        csv_2d = os.path.join(RESULTS_DIR, f"sweep2d_{dim_x}_x_{dim_y}.csv")
        if os.path.exists(csv_2d):
            plot_2d_sweep(csv_2d, dim_x, dim_y)
        else:
            print(f"  Skipping 2D heatmap ({dim_x} × {dim_y}) — CSV not found")
            print("  Run: python experiments/run_sweep.py --2d")


if __name__ == "__main__":
    main()
