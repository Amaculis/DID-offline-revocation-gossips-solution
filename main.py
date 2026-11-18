from sim.run_pull import run as run_pull
from sim.run_push import run as run_push
from sim.run_gossip import run as run_gossip
from sim.run_holder_gossip import run as run_holder_gossip
from sim.run_push_holder_gossip import run as run_push_holder_gossip
from sim.run_verification_gossip import run as run_verification_gossip

PARAMS = dict(
    network_size=500,
    offline_ratio=0.2,
    dead_ratio=0.9, # nodes that will never come online (no issuer access)
    ttl=28800,#3600,
    revocation_rate=0.1,
    sim_duration=86400 * 7,
    seed=42,
    mean_online_duration=3600,   # 1h
    mean_offline_duration=14400, # 4h
)

PARAMS_for_pull = dict(
    network_size=500,
    offline_ratio=0.5,
    dead_ratio=0.00, # nodes that will never come online (no issuer access)
    ttl=3600,#3600,
    revocation_rate=0.001,
    sim_duration=86400 * 7,
    seed=42,
    mean_online_duration=86400,  
    mean_offline_duration=300, 
)

PARAMS_for_push = dict(
    network_size=500,
    offline_ratio=0.4,
    dead_ratio=0.06, # nodes that will never come online (no issuer access)
    ttl=86400,#3600,
    revocation_rate=0.001,
    sim_duration=86400 * 7,
    seed=42,
    mean_online_duration=1800,  
    mean_offline_duration=21600, 
)

PARAMS_IoT = dict(
    network_size=500,
    offline_ratio=0.5,
    dead_ratio=0.7,       # most nodes have no internet
    ttl=604800,           # TTL = 1 week
    revocation_rate=0.0001,
    mean_online_duration=600,    # 10 minutes online
    mean_offline_duration=86400, # 1 day offline
)

PARAMS_unstable_network = dict(
    network_size=500,
    offline_ratio=0.3,
    dead_ratio=0.5,       # half have no issuer access
    ttl=28800,
    revocation_rate=0.001,
    mean_online_duration=3600,
    mean_offline_duration=14400,
)

PARAMS_wallets = dict(
    network_size=500,
    offline_ratio=0.4,    # many offline
    dead_ratio=0.6,       # most wallets have no issuer access
    ttl=86400,
    revocation_rate=0.001,
    mean_online_duration=1800,   # 30 minutes online
    mean_offline_duration=21600, # 6 hours offline
)

#-------------- Real-world scenarios ----------------
PARAMS_Smartcity = dict(
    network_size=1000,
    offline_ratio=0.1,    # many offline
    dead_ratio=0.05,       # most wallets have no issuer access
    ttl=3600,
    revocation_rate=0.01,
    mean_online_duration=14400,   # 4 hours online
    mean_offline_duration=3600, # 1 hour offline
)

PARAMS_countyside = dict(
    network_size=200,
    offline_ratio=0.6,    
    dead_ratio=0.2,       
    ttl=86400,
    revocation_rate=0.001,
    mean_online_duration=3600,   # 1 hour online
    mean_offline_duration=1800, # 30 minutes offline
)

PARAMS_critical = dict(
    network_size=500,
    offline_ratio=0.05,    
    dead_ratio=0.01,      
    ttl=300,
    revocation_rate=0.1,
    mean_online_duration=3600,   # 1 hour online
    mean_offline_duration=1800, # 0.5 hour offline
)

PARAMS_mobile = dict(
    network_size=500,
    offline_ratio=0.03,    
    dead_ratio=0.05,      
    ttl=7200,
    revocation_rate=0.01,
    mean_online_duration=1800,   # 0.5 hour online
    mean_offline_duration=600, # 10 min offline
)

PARAMS_factory = dict(
    network_size=300,
    offline_ratio=0.4,    
    dead_ratio=0.1,      
    ttl=14400,
    revocation_rate=0.005,
    mean_online_duration=28800,   # 8 hours online
    mean_offline_duration=57600, # 16 hours offline
)

PARAMS_apocalipse = dict(
    network_size=300,
    offline_ratio=0.8,    
    dead_ratio=0.7,      
    ttl=86400,
    revocation_rate=0.05,
    mean_online_duration=600,   # 10 minutes online
    mean_offline_duration=172800, # 2 days offline
)

PARAMS_expedition = dict(
    network_size=50,
    offline_ratio=0.7,    
    dead_ratio=0.3,      
    ttl=604800,
    revocation_rate=0.001,
    mean_online_duration=1800,   # 30 minutes online
    mean_offline_duration=259200, # 3 days offline
)

PARAMS_test = dict(
    network_size=2000,
    offline_ratio=0.6,    
    dead_ratio=0.2,       
    ttl=86400,
    revocation_rate=0.001,
    mean_online_duration=3600,   # 1 hour online
    mean_offline_duration=1800, # 30 minutes offline
)

PARAMS = PARAMS_test 

def main():
    results = []
    for label, runner in [("PULL", run_pull),
                          ("PUSH", run_push),
                          #("GOSSIP", run_gossip),
                          ("HOLDER-GOSSIP", run_holder_gossip),
                          ("PUSH-HOLDER-GOSSIP", run_push_holder_gossip),
                          #("VERIF-GOSSIP", run_verification_gossip),
                          ]:
        print(f"Running {label} simulation ...")
        results.append(runner(**PARAMS))

    _print_comparison(results)


def _print_comparison(results: list[dict]):
    header = f"{'Metric':<36}" + "".join(f"{r['strategy']:>16}" for r in results)
    print("\n" + "=" * len(header))
    print(header)
    print("=" * len(header))

    rows = [
        ("Propagation delay p95 (s)",   lambda r: _fmt(r["propagation_delay_p95_s"])), # 95% of nodes learn about new data within this time
        ("Propagation delay mean (s)",   lambda r: _fmt(r["propagation_delay_mean_s"])), # mean delay until a node learns about a change (mean "blind window")
        ("Holder propagation delay mean (s)",   lambda r: _fmt(r["holder_propagation_delay_mean_s"])), # same, for holder nodes
        ("Revocations @ 95% coverage",  lambda r: f"{r['revocations_reached_95pct']}/{r['total_revocations']}"), # revocations that reached 95% of nodes / total revocations
        ("False acceptance rate",        lambda r: f"{r['false_acceptance_rate']:.2%}"), # share of verifications that wrongly accepted a revoked credential
        ("Total verifications",          lambda r: str(r["total_verifications"])), # total number of verifications
        ("Bandwidth/node mean (KB)",     lambda r: f"{r['bandwidth']['mean']/1024:.1f}"), # mean KB downloaded per node during the simulation
        ("Bandwidth/node p95 (KB)",      lambda r: f"{r['bandwidth']['p95']/1024:.1f}"), # 95th percentile of KB downloaded per node
        ("Bandwidth total (MB)",         lambda r: f"{r['bandwidth']['total']/1024**2:.1f}"), # total traffic
        ("Storage/node mean (KB)",       lambda r: f"{r['storage']['mean']/1024:.1f}"), # mean per-node storage (KB)
        ("Storage/node max (KB)",        lambda r: f"{r['storage']['max']/1024:.1f}"), # max per-node storage (KB)
        ("Expired-TTL verifications",    lambda r: f"{r['expired_ttl_verifications']['rate']:.2%} ({r['expired_ttl_verifications']['count']}/{r['expired_ttl_verifications']['total']})"),
        ("List age at verify mean (s)",  lambda r: _fmt(r["list_age"]["mean"])),  # mean age of the cached list at verification time
        ("List age at verify min (s)",   lambda r: _fmt(r["list_age"]["min"])),   # freshest cache used
        ("List age at verify max (s)",   lambda r: _fmt(r["list_age"]["max"])),   # oldest cache used
        ("Presentation verifications",   lambda r: str(r["presentation_count"])),  # verifications triggered by a holder presentation (HOLDER-GOSSIP only)
        ("Presentation FAR",             lambda r: f"{r['presentation_false_acceptance_rate']:.2%}"),  # FAR of presentation verifications
    ]


    # TODO
    # - Availability metric: successful verifications / total verifications, to see whether a strategy    #   is more sensitive to offline nodes and how that affects user experience.    # - Verification duration.    # - For MIXED: share of verifications that had to go online (trade-off: propagation speed vs. network load).

    for label, fn in rows:
        print(f"{label:<36}" + "".join(f"{fn(r):>16}" for r in results))

    print("=" * len(header))
    #print(f"\nParams: network_size={results[0]['network_size']}, "
    #      f"offline_ratio={results[0]['offline_ratio']}, "
    #      f"TTL={results[0]['ttl_s']}s, "
    #      f"revocation_rate={results[0]['revocation_rate']} ev/s")
    print("\nFull parameters:")
    for k, v in PARAMS.items():
        print(f"  {k} = {v}")


def _fmt(v):
    return "N/A" if v is None else f"{v:.1f}"


if __name__ == "__main__":
    main()
