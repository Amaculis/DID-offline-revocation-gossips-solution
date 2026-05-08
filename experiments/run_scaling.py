
from __future__ import annotations
import argparse
import math
import os
import sys
from multiprocessing import Pool, cpu_count

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
from sim.run_pull import run as run_pull
from sim.run_push import run as run_push
from sim.run_holder_gossip import run as run_gossip
from sim.run_push_holder_gossip import run as run_mixed

RUNNERS = {
    "PULL":   run_pull,
    "PUSH":   run_push,
    "GOSSIP": run_gossip,
    "MIXED":  run_mixed,
}

BASE = dict(
    offline_ratio=0.2,
    dead_ratio=0.1,
    ttl=28800,
    revocation_rate=0.001,
    sim_duration=86400,          # 1 day (instead of 7)
    mean_online_duration=3600,
    mean_offline_duration=14400,
)

BASE_N    = 500
BASE_CR   = 1 / 600              # contact_rate at N=500
BASE_SEEDS = list(range(1, 101))

NETWORK_SIZES = [
    100, 300, 500, 1_000, 2_000, 5_000,
    10_000, 30_000, 100_000, 300_000, 1_000_000,
]

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def _safe(v) -> float:
    return float("nan") if v is None or (isinstance(v, float) and math.isnan(v)) else v


_NO_CONTACT_RATE = {"PULL", "PUSH"}

def _worker(task: tuple) -> dict | None:
    strategy_name, params, seed = task
    runner = RUNNERS[strategy_name]
    run_params = {k: v for k, v in params.items()
                  if not (k == "contact_rate" and strategy_name in _NO_CONTACT_RATE)}
    try:
        return runner(**{**run_params, "seed": seed})
    except Exception as exc:
        print(f"    ERROR {strategy_name} N={params['network_size']} seed={seed}: {exc}")
        return None


def _aggregate(results: list[dict | None]) -> dict:
    rows = []
    for r in results:
        if r is None:
            continue
        rows.append({
            "delay_mean":            _safe(r["propagation_delay_mean_s"]),
            "delay_p95":             _safe(r["propagation_delay_p95_s"]),
            "far":                   _safe(r["false_acceptance_rate"]),
            "bandwidth_per_node_kb": _safe(r["bandwidth"]["mean"] / 1024),
            "coverage_rate": (
                r["revocations_reached_95pct"] / r["total_revocations"]
                if r["total_revocations"] > 0 else 0.0
            ),
        })
    if not rows:
        nan = float("nan")
        return {k + sfx: nan
                for k in ["delay_mean", "delay_p95", "far",
                           "bandwidth_per_node_kb", "coverage_rate"]
                for sfx in ("_mean", "_ci95")}
    df = pd.DataFrame(rows)
    out = {"n_runs": len(rows)}
    for col in df.columns:
        m = df[col].mean()
        s = df[col].std(ddof=1) if len(df) > 1 else float("nan")
        out[col + "_mean"] = m
        out[col + "_ci95"] = 1.96 * s / math.sqrt(len(df)) if len(df) > 1 else float("nan")
    return out


def run_scaling(sizes: list[int], seeds: list[int], pool) -> pd.DataFrame:
    rows = []
    for n in sizes:
        contact_rate = BASE_N * BASE_CR / n
        params = {**BASE, "network_size": n, "contact_rate": contact_rate}
        for strategy in RUNNERS:
            print(f"  {strategy:<8} | N={n:>8,}  contact_rate={contact_rate:.2e}  ({len(seeds)} seeds)",
                  flush=True)
            tasks = [(strategy, params, s) for s in seeds]
            raw = pool.map(_worker, tasks)
            agg = _aggregate(raw)
            rows.append({"network_size": n, "strategy": strategy,
                         "contact_rate": contact_rate, **agg})
    return pd.DataFrame(rows)


def plot_scaling(df: pd.DataFrame, out_dir: str):
    try:
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("  matplotlib not available — skipping plots")
        return

    colors = {"PULL": "#534AB7", "PUSH": "#D85A30", "GOSSIP": "#0F6E56", "MIXED": "#185FA5"}
    strategies = [s for s in ["PULL", "PUSH", "GOSSIP", "MIXED"] if s in df["strategy"].unique()]

    metrics = [
        ("delay_mean_mean", "delay_mean_ci95", "Propagation Delay Mean (s)"),
        ("far_mean",        "far_ci95",        "False Acceptance Rate"),
    ]

    fig, axes = plt.subplots(1, len(metrics), figsize=(7 * len(metrics), 5))
    fig.suptitle("Scaling: propagation vs network size (normalised contact_rate)",
                 fontsize=13, fontweight="bold")

    for ax, (col, ci_col, ylabel) in zip(axes, metrics):
        for strategy in strategies:
            sub = df[df["strategy"] == strategy].sort_values("network_size")
            x   = sub["network_size"].to_numpy()
            y   = sub[col].to_numpy(dtype=float)
            ci  = sub[ci_col].to_numpy(dtype=float) if ci_col in sub.columns else np.full_like(y, np.nan)
            valid = ~np.isnan(y)
            if not valid.any():
                continue
            color = colors.get(strategy)
            ax.plot(x[valid], y[valid], marker="o", linewidth=2, markersize=5,
                    color=color, label=strategy)
            mask = valid & ~np.isnan(ci)
            if mask.any():
                ax.fill_between(x[mask], (y - ci)[mask], (y + ci)[mask],
                                alpha=0.15, color=color)

        # O(log N) reference line 
        if strategies:
            sub0 = df[df["strategy"] == strategies[0]].sort_values("network_size")
            x0 = sub0["network_size"].to_numpy()
            y0 = sub0[col].to_numpy(dtype=float)
            valid0 = ~np.isnan(y0) & (x0 > 0)
            if valid0.sum() >= 2:
                log_x = np.log(x0[valid0])
                coeffs = np.polyfit(log_x, y0[valid0], 1)
                x_ref = np.logspace(np.log10(x0[valid0].min()),
                                    np.log10(x0[valid0].max()), 100)
                y_ref = coeffs[0] * np.log(x_ref) + coeffs[1]
                ax.plot(x_ref, y_ref, "k--", linewidth=1, alpha=0.4, label="O(log N) fit")

        ax.set_xscale("log")
        ax.set_xlabel("Network size (nodes)")
        ax.set_ylabel(ylabel)
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=9)

    plt.tight_layout()
    out_path = os.path.join(out_dir, "scaling_network_size.png")
    plt.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {out_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-n", type=int, default=1_000_000,
                        help="Largest network size to test (default: 1_000_000)")
    parser.add_argument("--runs", type=int, default=3,
                        help="Seeds per point (default: 3)")
    parser.add_argument("--workers", type=int, default=None,
                        help="Parallel workers (default: cpu_count)")
    args = parser.parse_args()

    seeds   = BASE_SEEDS[:args.runs]
    workers = args.workers or cpu_count()
    sizes   = [n for n in NETWORK_SIZES if n <= args.max_n]
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print(f"Workers: {workers}  |  Seeds: {len(seeds)}  |  Sizes: {sizes}")
    print(f"sim_duration: {BASE['sim_duration']}s (1 day)  |  contact_rate normalised to N=500 baseline")

    with Pool(processes=workers) as pool:
        df = run_scaling(sizes, seeds, pool)

    csv_path = os.path.join(RESULTS_DIR, "scaling_network_size.csv")
    df.to_csv(csv_path, index=False)
    print(f"\nSaved: {csv_path}")
    print(df[["network_size", "strategy", "delay_mean_mean", "far_mean", "n_runs"]].to_string(index=False))

    plot_scaling(df, RESULTS_DIR)


if __name__ == "__main__":
    main()
