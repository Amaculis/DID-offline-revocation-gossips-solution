"""Averaged multi-seed runner.

Runs each strategy N times with different seeds, averages all numeric metrics,
and prints a comparison table in the same format as main.py.

Usage:
    python experiments/run_averaged.py
    python experiments/run_averaged.py --runs 10
"""
from __future__ import annotations
import argparse
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sim.run_pull import run as run_pull
from sim.run_push import run as run_push
from sim.run_holder_gossip import run as run_holder_gossip
from sim.run_push_holder_gossip import run as run_push_holder_gossip

RUNNERS = [
    ("PULL",               run_pull),
    ("PUSH",               run_push),
    ("HOLDER-GOSSIP",      run_holder_gossip),
    ("PUSH-HOLDER-GOSSIP", run_push_holder_gossip),
]

PARAMS = dict(
    network_size=500,
    offline_ratio=0.2,
    dead_ratio=0.01,
    ttl=28800,
    revocation_rate=0.01,
    sim_duration=86400 * 7,
    mean_online_duration=3600,
    mean_offline_duration=14400,
)

# Seeds used across runs — deterministic so results are reproducible
BASE_SEEDS = list(range(1, 101))


# ---------------------------------------------------------------------------
# Averaging logic
# ---------------------------------------------------------------------------

def _safe_mean(values: list) -> float | None:
    """Mean of a list, ignoring None and NaN. Returns None if nothing valid."""
    valid = [v for v in values if v is not None and not (isinstance(v, float) and math.isnan(v))]
    return sum(valid) / len(valid) if valid else None


def average_results(results: list[dict]) -> dict:
    """Merge a list of result dicts into a single averaged dict."""
    n = len(results)

    def mean(key):
        return _safe_mean([r[key] for r in results])

    def mean_nested(key, sub):
        return _safe_mean([r[key][sub] for r in results])

    # Revocations: sum both sides and keep as ints for display
    total_rev = round(sum(r["total_revocations"] for r in results) / n)
    reached   = round(sum(r["revocations_reached_95pct"] for r in results) / n)

    return {
        "strategy":                          results[0]["strategy"],
        "network_size":                      results[0]["network_size"],
        "offline_ratio":                     results[0]["offline_ratio"],
        "ttl_s":                             results[0]["ttl_s"],
        "revocation_rate":                   results[0]["revocation_rate"],

        "propagation_delay_p95_s":           mean("propagation_delay_p95_s"),
        "propagation_delay_mean_s":          mean("propagation_delay_mean_s"),
        "holder_propagation_delay_mean_s":   mean("holder_propagation_delay_mean_s"),
        "revocations_reached_95pct":         reached,
        "total_revocations":                 total_rev,
        "false_acceptance_rate":             mean("false_acceptance_rate"),
        "total_verifications":               round(mean("total_verifications")),
        "presentation_count":                round(mean("presentation_count")),
        "presentation_false_acceptance_rate": mean("presentation_false_acceptance_rate"),

        "bandwidth": {
            "mean":   mean_nested("bandwidth", "mean"),
            "median": mean_nested("bandwidth", "median"),
            "p95":    mean_nested("bandwidth", "p95"),
            "total":  mean_nested("bandwidth", "total"),
        },
        "storage": {
            "mean": mean_nested("storage", "mean"),
            "max":  mean_nested("storage", "max"),
        },
        "list_age": {
            "mean": mean_nested("list_age", "mean"),
            "min":  mean_nested("list_age", "min"),
            "max":  mean_nested("list_age", "max"),
        },
        "expired_ttl_verifications": {
            "rate":  mean_nested("expired_ttl_verifications", "rate"),
            "count": round(mean_nested("expired_ttl_verifications", "count")),
            "total": round(mean_nested("expired_ttl_verifications", "total")),
        },
    }


# ---------------------------------------------------------------------------
# Table printing (mirrors main.py)
# ---------------------------------------------------------------------------

def _fmt(v) -> str:
    return "N/A" if v is None else f"{v:.1f}"


def _print_comparison(results: list[dict], n_runs: int):
    col_w = 18
    header = f"{'Metric':<40}" + "".join(f"{r['strategy']:>{col_w}}" for r in results)
    sep = "=" * len(header)
    print(f"\n{sep}")
    print(f"  Averaged over {n_runs} seeds")
    print(sep)
    print(header)
    print(sep)

    rows = [
        ("Propagation delay p95 (s)",
         lambda r: _fmt(r["propagation_delay_p95_s"])),
        ("Propagation delay mean (s)",
         lambda r: _fmt(r["propagation_delay_mean_s"])),
        ("Holder propagation delay mean (s)",
         lambda r: _fmt(r["holder_propagation_delay_mean_s"])),
        ("Revocations @ 95% coverage",
         lambda r: f"{r['revocations_reached_95pct']}/{r['total_revocations']}"),
        ("False acceptance rate",
         lambda r: f"{r['false_acceptance_rate']:.2%}" if r["false_acceptance_rate"] is not None else "N/A"),
        ("Total verifications",
         lambda r: str(r["total_verifications"])),
        ("Bandwidth/node mean (KB)",
         lambda r: f"{r['bandwidth']['mean']/1024:.1f}" if r["bandwidth"]["mean"] else "N/A"),
        ("Bandwidth/node p95 (KB)",
         lambda r: f"{r['bandwidth']['p95']/1024:.1f}" if r["bandwidth"]["p95"] else "N/A"),
        ("Bandwidth total (MB)",
         lambda r: f"{r['bandwidth']['total']/1024**2:.1f}" if r["bandwidth"]["total"] else "N/A"),
        ("Storage/node mean (KB)",
         lambda r: f"{r['storage']['mean']/1024:.1f}" if r["storage"]["mean"] else "N/A"),
        ("Storage/node max (KB)",
         lambda r: f"{r['storage']['max']/1024:.1f}" if r["storage"]["max"] else "N/A"),
        ("Expired-TTL verifications",
         lambda r: f"{r['expired_ttl_verifications']['rate']:.2%} "
                   f"({r['expired_ttl_verifications']['count']}/"
                   f"{r['expired_ttl_verifications']['total']})"),
        ("List age at verify mean (s)",
         lambda r: _fmt(r["list_age"]["mean"])),
        ("List age at verify min (s)",
         lambda r: _fmt(r["list_age"]["min"])),
        ("List age at verify max (s)",
         lambda r: _fmt(r["list_age"]["max"])),
        ("Presentation verifications",
         lambda r: str(r["presentation_count"])),
        ("Presentation FAR",
         lambda r: f"{r['presentation_false_acceptance_rate']:.2%}" if r["presentation_false_acceptance_rate"] is not None else "N/A"),
    ]

    for label, fn in rows:
        print(f"{label:<40}" + "".join(f"{fn(r):>{col_w}}" for r in results))

    print(sep)
    print("\nParameters:")
    for k, v in PARAMS.items():
        print(f"  {k} = {v}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5,
                        help="Number of seeds to average over (default: 5)")
    args = parser.parse_args()

    n_runs = args.runs
    seeds = BASE_SEEDS[:n_runs]

    averaged = []
    for label, runner in RUNNERS:
        run_results = []
        for i, seed in enumerate(seeds):
            print(f"  {label:<22} seed={seed}  ({i+1}/{n_runs})")
            params = {**PARAMS, "seed": seed}
            run_results.append(runner(**params))
        averaged.append(average_results(run_results))

    _print_comparison(averaged, n_runs)


if __name__ == "__main__":
    main()
