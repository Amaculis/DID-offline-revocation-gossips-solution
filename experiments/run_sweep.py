from __future__ import annotations
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
from sim.run_pull import run as run_pull
from sim.run_push import run as run_push
from sim.run_holder_gossip import run as run_holder_gossip
from sim.run_push_holder_gossip import run as run_push_holder_gossip

RUNNERS = {
    "PULL": run_pull,
    "PUSH": run_push,
    "GOSSIP": run_holder_gossip,
    "MIXED": run_push_holder_gossip,
}

BASE = dict(
    network_size=500,
    offline_ratio=0.2,
    dead_ratio=0.1,
    ttl=28800,
    revocation_rate=0.001,
    sim_duration=86400 * 7,
    seed=42,
    mean_online_duration=3600,
    mean_offline_duration=14400,
)

SWEEPS = {
    "dead_ratio":      [0.0, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0],
    "offline_ratio":   [0.0, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0],
    "revocation_rate": [0.000001, 0.000005, 0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.15, 0.2, 0.25 ,0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0],
    "ttl":             [60, 120, 360, 720, 1440, 2880,  3600, 4320, 7200, 14400, 28800, 43200, 57600, 86400],
}

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def extract_row(sweep_dim: str, sweep_value, strategy: str, result: dict) -> dict:
    total_rev = result["total_revocations"]
    reached = result["revocations_reached_95pct"]
    coverage = reached / total_rev if total_rev > 0 else 0.0

    delay = result["propagation_delay_mean_s"]
    delay = float("nan") if delay is None else delay

    return {
        "sweep_dim":        sweep_dim,
        "sweep_value":      sweep_value,
        "strategy":         strategy,
        "far":              result["false_acceptance_rate"],
        "delay_mean":       delay,
        "bandwidth_mb":     result["bandwidth"]["total"] / 1024 ** 2,
        "expired_ttl_rate": result["expired_ttl_verifications"]["rate"],
        "coverage_rate":    coverage,
    }


def run_sweep(sweep_dim: str, sweep_values: list) -> pd.DataFrame:
    rows = []
    for value in sweep_values:
        for strategy, runner in RUNNERS.items():
            print(f"  Running {strategy:<22} | {sweep_dim}={value}")
            params = BASE.copy()
            params[sweep_dim] = value
            try:
                result = runner(**params)
                rows.append(extract_row(sweep_dim, value, strategy, result))
            except Exception as exc:
                print(f"    ERROR: {exc}")
                rows.append({
                    "sweep_dim": sweep_dim, "sweep_value": value,
                    "strategy": strategy, "far": float("nan"),
                    "delay_mean": float("nan"), "bandwidth_mb": float("nan"),
                    "expired_ttl_rate": float("nan"), "coverage_rate": float("nan"),
                })
    return pd.DataFrame(rows)


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    for sweep_dim, sweep_values in SWEEPS.items():
        print(f"\n{'='*60}")
        print(f"Sweep: {sweep_dim}")
        print(f"{'='*60}")
        df = run_sweep(sweep_dim, sweep_values)
        path = os.path.join(RESULTS_DIR, f"sweep_{sweep_dim}.csv")
        df.to_csv(path, index=False)
        print(f"  Saved: {path}")


if __name__ == "__main__":
    main()
