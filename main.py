from sim.run_pull import run as run_pull
from sim.run_push import run as run_push
from sim.run_gossip import run as run_gossip

PARAMS = dict(
    network_size=20000,
    offline_ratio=0.2,
    ttl=3600,
    revocation_rate=0.01,
    sim_duration=86400 * 7,
    seed=42,
)


def main():
    results = []
    for label, runner in [("PULL", run_pull), ("PUSH", run_push), ("GOSSIP", run_gossip)]:
        print(f"Running {label} simulation ...")
        results.append(runner(**PARAMS))

    _print_comparison(results)


def _print_comparison(results: list[dict]):
    header = f"{'Metric':<36}" + "".join(f"{r['strategy']:>16}" for r in results)
    print("\n" + "=" * len(header))
    print(header)
    print("=" * len(header))

    rows = [
        ("Propagation delay p95 (s)",   lambda r: _fmt(r["propagation_delay_p95_s"])),
        ("Propagation delay mean (s)",   lambda r: _fmt(r["propagation_delay_mean_s"])),
        ("Revocations @ 95% coverage",  lambda r: f"{r['revocations_reached_95pct']}/{r['total_revocations']}"),
        ("False acceptance rate",        lambda r: f"{r['false_acceptance_rate']:.2%}"),
        ("Total verifications",          lambda r: str(r["total_verifications"])),
        ("Bandwidth/node mean (KB)",     lambda r: f"{r['bandwidth']['mean']/1024:.1f}"),
        ("Bandwidth/node p95 (KB)",      lambda r: f"{r['bandwidth']['p95']/1024:.1f}"),
        ("Bandwidth total (MB)",         lambda r: f"{r['bandwidth']['total']/1024**2:.1f}"),
        ("Storage/node mean (KB)",       lambda r: f"{r['storage']['mean']/1024:.1f}"),
        ("Storage/node max (KB)",        lambda r: f"{r['storage']['max']/1024:.1f}"),
    ]

    for label, fn in rows:
        print(f"{label:<36}" + "".join(f"{fn(r):>16}" for r in results))

    print("=" * len(header))
    print(f"\nParams: network_size={results[0]['network_size']}, "
          f"offline_ratio={results[0]['offline_ratio']}, "
          f"TTL={results[0]['ttl_s']}s, "
          f"revocation_rate={results[0]['revocation_rate']} ev/s")


def _fmt(v):
    return "N/A" if v is None else f"{v:.1f}"


if __name__ == "__main__":
    main()
