from sim.run_pull import run as run_pull
from sim.run_push import run as run_push
from sim.run_gossip import run as run_gossip
from sim.run_holder_gossip import run as run_holder_gossip
from sim.run_push_holder_gossip import run as run_push_holder_gossip

PARAMS = dict(
    network_size=500,
    offline_ratio=0.2,
    dead_ratio=0.7, #tie kas jau nekad nebūs online. 
    ttl=28800,#3600,
    revocation_rate=0.01,
    sim_duration=86400 * 7,
    seed=42,
    mean_online_duration=3600,   # 1h
    mean_offline_duration=14400, # 4h
)


def main():
    results = []
    for label, runner in [("PULL", run_pull),
                          ("PUSH", run_push),
                          ("GOSSIP", run_gossip),
                          ("HOLDER-GOSSIP", run_holder_gossip),
                          ("PUSH-HOLDER-GOSSIP", run_push_holder_gossip),
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
        ("Propagation delay p95 (s)",   lambda r: _fmt(r["propagation_delay_p95_s"])), #95 % procenti no mezgliem uzzin par jauniem datiem šī laika ietvaros. Sekundes
        ("Propagation delay mean (s)",   lambda r: _fmt(r["propagation_delay_mean_s"])), # Vidējā aizture sekundēs , līdz brīdim, kad mezgls uzzina par izmaiņu sekundēs. Vidējais "aklums"
        ("Holder propagation delay mean (s)",   lambda r: _fmt(r["holder_propagation_delay_mean_s"])), # Vidējā aizture sekundēs holder mezgliem
        ("Revocations @ 95% coverage",  lambda r: f"{r['revocations_reached_95pct']}/{r['total_revocations']}"), # Cik mezgli uzzināja par revokācijām, kad 95% revokāciju bija izplatītas. Cik revokāciju sasniedza 95% mezglu.
        ("False acceptance rate",        lambda r: f"{r['false_acceptance_rate']:.2%}"), # Cik procentu no revokācijas bija apstiprināti nekorekti. 
        ("Total verifications",          lambda r: str(r["total_verifications"])), # Kopējo verifikāciju skaits
        ("Bandwidth/node mean (KB)",     lambda r: f"{r['bandwidth']['mean']/1024:.1f}"), #Cik KB vidējs katrs mezgls lejuplādēja simulācijas laikā. 
        ("Bandwidth/node p95 (KB)",      lambda r: f"{r['bandwidth']['p95']/1024:.1f}"), # Cik KB 95% mezglu lejuplādēja simulācijas laikā.
        ("Bandwidth total (MB)",         lambda r: f"{r['bandwidth']['total']/1024**2:.1f}"), #Kopējais traffiks
        ("Storage/node mean (KB)",       lambda r: f"{r['storage']['mean']/1024:.1f}"), # Vidējais katra mezgla uzglabāšanas apjoms KB
        ("Storage/node max (KB)",        lambda r: f"{r['storage']['max']/1024:.1f}"), # Maksimālais katra mezgla uzglabāšanas apjoms KB
        ("Expired-TTL verifications",    lambda r: f"{r['expired_ttl_verifications']['rate']:.2%} ({r['expired_ttl_verifications']['count']}/{r['expired_ttl_verifications']['total']})"),
        ("List age at verify mean (s)",  lambda r: _fmt(r["list_age"]["mean"])),  # Cik sena vidēji bija kešatmiņa verifikācijas brīdī
        ("List age at verify min (s)",   lambda r: _fmt(r["list_age"]["min"])),   # Jaunākā kešatmiņa, ko mezgls izmantoja
        ("List age at verify max (s)",   lambda r: _fmt(r["list_age"]["max"])),   # Vecākā kešatmiņa, ko mezgls izmantoja
        ("Presentation verifications",   lambda r: str(r["presentation_count"])),  # Verifikācijas, kas notika prezentācijas laikā (tikai HOLDER-GOSSIP)
        ("Presentation FAR",             lambda r: f"{r['presentation_false_acceptance_rate']:.2%}"),  # Prezentācijas verifikāciju kļūdu līmenis
    ]


    #TODO 
    # pievienot Pieejamības metriku, kas skaitās veiksmīgas verifikācijas/kopējais verifikāciju skaits, lai redzētu, vai kāda stratēģija ir jutīgāka pret offline mezgliem un vai tas ietekmē lietotāju pieredzi.
    # Verifikācijas ilgumu
    # Pie mixed stratēgijas pievienot vēl metriku "Obligāto tīkla verifikāciju", kas norādīs cik % verifikāciju bija jāveic tiešsaistē, lai redzētu, vai tas varētu būt labs kompromiss starp izplatīšanās ātrumu un tīkla slodzi.


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
