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
from sim.run_holder_gossip import run as run_holder_gossip
from sim.run_push_holder_gossip import run as run_push_holder_gossip

RUNNERS = {
    "PULL":   run_pull,
    "PUSH":   run_push,
    "GOSSIP": run_holder_gossip,
    "MIXED":  run_push_holder_gossip,
}

BASE = dict(
    network_size=500,
    offline_ratio=0.2,
    dead_ratio=0.1,
    ttl=28800,
    revocation_rate=0.001,
    sim_duration=86400 * 7,
    mean_online_duration=3600,
    mean_offline_duration=14400,
)

BASE_SEEDS = list(range(1, 101))

SWEEPS = {
    "dead_ratio":            [0.0, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0],
    "offline_ratio":         [0.0, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95],
    "revocation_rate":       [0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0],
    "ttl":                   [60, 120, 360, 720, 1440, 2880, 3600, 4320, 7200, 14400, 28800, 43200, 57600, 86400],
    "network_size":          [50, 100, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 7000, 10000, 20000, 30000, 40000, 50000],
    "mean_offline_duration": [600, 1800, 3600, 7200, 14400, 28800, 43200, 86400],
            "mean_online_duration":  [300, 600, 1200, 1800, 3600, 7200, 14400, 28800],
        }

SWEEPS_2D = {
    ("ttl", "dead_ratio"): (
        [3600, 14400, 28800, 86400],
        [0.0, 0.1, 0.2, 0.3, 0.5, 0.7],
    ),
}

SWEEPS_new = {

    "dead_ratio": [0.0, 0.1, 0.2, 0.3, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],

    "offline_ratio": [0.0, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0],

    "revocation_rate": [
        0.00001, 0.0001, 0.001,          
        0.005, 0.01, 0.05,               
        0.1, 0.2, 0.3, 0.5, 0.75, 1.0,  
    ],

    "ttl": [120, 720, 3600, 7200, 14400, 28800, 43200, 86400],


    "network_size": [50, 100, 300, 500, 1000, 3000, 10000, 30000, 50000],

    "mean_offline_duration": [600, 1800, 3600, 7200, 14400, 28800, 86400],

    "mean_online_duration": [300, 600, 1800, 3600, 7200, 14400, 28800],
}

SWEEPS_2D_new = {
    ("ttl", "dead_ratio"): (
        [3600, 14400, 28800, 86400],
        [0.0, 0.2, 0.5, 0.7],
    ),
}

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")



# Worker — must be a top-level function so multiprocessing can pickle it


def _worker(task: tuple) -> dict | None:
    strategy_name, params, seed = task
    runner = RUNNERS[strategy_name]
    try:
        return runner(**{**params, "seed": seed})
    except Exception as exc:
        print(f"    ERROR {strategy_name} seed={seed}: {exc}")
        return None


# Helpers

def _safe(v) -> float:
    return float("nan") if v is None or (isinstance(v, float) and math.isnan(v)) else v


_METRIC_KEYS = ["far", "delay_mean", "bandwidth_mb", "bandwidth_per_node_kb",
                "expired_ttl_rate", "coverage_rate"]


def _extract_row(r: dict) -> dict:
    return {
        "far":                   _safe(r["false_acceptance_rate"]),
        "delay_mean":            _safe(r["propagation_delay_mean_s"]),
        "bandwidth_mb":          _safe(r["bandwidth"]["total"] / 1024 ** 2),
        "bandwidth_per_node_kb": _safe(r["bandwidth"]["mean"] / 1024),
        "expired_ttl_rate":      _safe(r["expired_ttl_verifications"]["rate"]),
        "coverage_rate": (
            r["revocations_reached_95pct"] / r["total_revocations"]
            if r["total_revocations"] > 0 else 0.0
        ),
    }


def _aggregate(rows: list[dict], n_runs: int) -> dict:
    if not rows:
        nan = float("nan")
        out = {k + sfx: nan for k in _METRIC_KEYS for sfx in ("_mean", "_std", "_ci95")}
        out["n_runs"] = 0
        return out
    df = pd.DataFrame(rows)
    out = {"n_runs": n_runs}
    for col in df.columns:
        m = df[col].mean()
        s = df[col].std(ddof=1) if len(df) > 1 else float("nan")
        out[col + "_mean"] = m
        out[col + "_std"]  = s
        out[col + "_ci95"] = 1.96 * s / math.sqrt(len(df)) if len(df) > 1 else float("nan")
    return out


def _run_point(strategy: str, params: dict, seeds: list, pool,
               cv_threshold: float = 1.0, max_seeds: list | None = None) -> dict:
    """Run seeds in parallel; if FAR CV exceeds threshold, add more seeds up to max_seeds."""
    tasks = [(strategy, params, s) for s in seeds]
    raw = [r for r in pool.map(_worker, tasks) if r is not None]
    rows = [_extract_row(r) for r in raw]

    if max_seeds and len(rows) >= 2:
        far_vals = [row["far"] for row in rows if not math.isnan(row["far"])]
        if len(far_vals) >= 2:
            mean_far = sum(far_vals) / len(far_vals)
            std_far  = pd.Series(far_vals).std(ddof=1)
            cv = std_far / mean_far if mean_far > 0 else 0.0
            if cv > cv_threshold:
                extra_seeds = [s for s in max_seeds if s not in seeds]
                if extra_seeds:
                    print(f"    CV={cv:.2f} > {cv_threshold} — adding {len(extra_seeds)} extra seeds")
                    extra_tasks = [(strategy, params, s) for s in extra_seeds]
                    extra_raw = [r for r in pool.map(_worker, extra_tasks) if r is not None]
                    rows += [_extract_row(r) for r in extra_raw]

    return _aggregate(rows, n_runs=len(rows))


# Sweep runners


def _apply_sweep_param(params: dict, sweep_dim: str, value) -> dict:
    params = {**params, sweep_dim: value}
    if sweep_dim == "offline_ratio" and value < 1.0:
        # Adjust mean_offline_duration so steady-state matches the target ratio:
        # ratio = mean_offline / (mean_online + mean_offline)
        mean_online = params.get("mean_online_duration", 3600)
        params["mean_offline_duration"] = mean_online * value / (1.0 - value)
    return params


def run_sweep(sweep_dim: str, sweep_values: list, seeds: list, pool,
              cv_threshold: float, max_seeds: list) -> pd.DataFrame:
    rows = []
    for value in sweep_values:
        params = _apply_sweep_param(BASE.copy(), sweep_dim, value)
        for strategy in RUNNERS:
            print(f"  {strategy:<8} | {sweep_dim}={value}  ({len(seeds)} seeds)", flush=True)
            agg = _run_point(strategy, params, seeds, pool, cv_threshold, max_seeds)
            rows.append({"sweep_dim": sweep_dim, "sweep_value": value, "strategy": strategy, **agg})
    return pd.DataFrame(rows)


def run_2d_sweep(dim_x: str, dim_y: str, values_x: list, values_y: list,
                 seeds: list, pool, cv_threshold: float, max_seeds: list) -> pd.DataFrame:
    rows = []
    for vx in values_x:
        for vy in values_y:
            params = _apply_sweep_param(BASE.copy(), dim_x, vx)
            params = _apply_sweep_param(params, dim_y, vy)
            for strategy in RUNNERS:
                print(f"  {strategy:<8} | {dim_x}={vx}, {dim_y}={vy}  ({len(seeds)} seeds)", flush=True)
                agg = _run_point(strategy, params, seeds, pool, cv_threshold, max_seeds)
                rows.append({dim_x: vx, dim_y: vy, "strategy": strategy, **agg})
    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5,
                        help="Number of seeds per point (default: 5)")
    parser.add_argument("--max-runs", type=int, default=15,
                        help="Max seeds for high-CV points (default: 15)")
    parser.add_argument("--cv-threshold", type=float, default=1.0,
                        help="CV threshold above which extra seeds are added (default: 1.0)")
    parser.add_argument("--workers", type=int, default=None,
                        help="Parallel workers (default: cpu_count)")
    parser.add_argument("--dims", nargs="*", default=None,
                        help="Which sweep dims to run (default: all)")
    parser.add_argument("--2d", dest="run_2d", action="store_true",
                        help="Also run 2D sweeps")
    parser.add_argument("--no-adaptive", dest="no_adaptive", action="store_true",
                        help="Disable adaptive extra seeds for high-CV points (uniform n_runs)")
    args = parser.parse_args()

    seeds     = BASE_SEEDS[:args.runs]
    max_seeds = [] if args.no_adaptive else BASE_SEEDS[args.runs:args.max_runs]
    workers   = args.workers or cpu_count()
    os.makedirs(RESULTS_DIR, exist_ok=True)

    mode = "uniform" if args.no_adaptive else f"adaptive (CV>{args.cv_threshold} → up to {args.max_runs} seeds)"
    print(f"Workers: {workers}  |  Seeds per point: {len(seeds)}  |  Mode: {mode}")

    with Pool(processes=workers) as pool:
        dims = args.dims if args.dims else list(SWEEPS.keys())
        for sweep_dim in dims:
            sweep_values = SWEEPS[sweep_dim]
            print(f"\n{'='*60}")
            print(f"Sweep: {sweep_dim}  ({len(sweep_values)} values × {len(seeds)} seeds × {len(RUNNERS)} strategies)")
            print(f"{'='*60}")
            df = run_sweep(sweep_dim, sweep_values, seeds, pool, args.cv_threshold, max_seeds)
            path = os.path.join(RESULTS_DIR, f"sweep_{sweep_dim}.csv")
            df.to_csv(path, index=False)
            print(f"  Saved: {path}")

        if args.run_2d:
            for (dim_x, dim_y), (values_x, values_y) in SWEEPS_2D.items():
                print(f"\n{'='*60}")
                print(f"2D Sweep: {dim_x} × {dim_y}")
                print(f"{'='*60}")
                df = run_2d_sweep(dim_x, dim_y, values_x, values_y, seeds, pool, args.cv_threshold, max_seeds)
                path = os.path.join(RESULTS_DIR, f"sweep2d_{dim_x}_x_{dim_y}.csv")
                df.to_csv(path, index=False)
                print(f"  Saved: {path}")


if __name__ == "__main__":
    main()
