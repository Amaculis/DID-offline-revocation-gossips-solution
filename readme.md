# DID Offline Revocation — Gossip Simulation

## Arhitektūra

### Projekta struktūra

```text
sim/
├── common/
│   ├── models.py          # Datu klases: StatusList, RevocationEvent, VerificationAttempt, NodeStats
│   ├── issuer.py          # Issuer — ģenerē revokācijas, apkalpo PUSH abonentus
│   ├── metrics.py         # summarize(), propagation_delay(), false_acceptance_rate(), bandwidth_per_node()
│   └── network.py         # build_graph(), assign_initial_states(), assign_dead_nodes()
├── strategies/
│   ├── pull.py            # PullNode — periodiski fetch no Issuer (TTL-balstīts)
│   ├── push.py            # PushNode — saņem push no Issuer pie reconnect
│   ├── gossip.py          # GossipNode — P2P gossip starp verifikatoriem
│   ├── holder_gossip.py   # HolderGossipNode + HolderNode — gossip + holder prezentācijas
│   ├── push_holder_gossip.py  # PushHolderGossipNode — PUSH + P2P gossip + holder
│   └── verification_gossip.py # VerificationGossipNode — verifikācijas gossip (eksperimentāls)
├── run_pull.py            # Runner: PULL stratēģija
├── run_push.py            # Runner: PUSH stratēģija
├── run_gossip.py          # Runner: tīrs P2P gossip
├── run_holder_gossip.py   # Runner: GOSSIP + holder prezentācijas
├── run_push_holder_gossip.py  # Runner: MIXED (PUSH + GOSSIP + holder)
└── run_verification_gossip.py # Runner: verifikācijas gossip
experiments/
├── run_sweep.py           # 1D/2D parametru slaucījumi ar multiprocessing
├── run_scaling.py         # Tīkla izmēru skalēšanas testi (līdz 1M mezgliem)
├── run_averaged.py        # Ātrs N-seed vidējo rādītāju tests
├── plot_results.py        # Vizualizācija no CSV failiem
└── results/               # CSV un PNG izejas faili
```

### Simulācijas mehānisms

Simulācija izmanto **SimPy** — diskrētā laika notikumu simulācijas bibliotēku. Katrs mezgls ir neatkarīgs SimPy process.

```text
Issuer
  │  revokācija (Poisson process, rate = revocation_rate)
  │  → StatusList (versija, revoked_ids, issued_at, ttl)
  │
  ├── PULL:  mezgli periodiski fetch (ik CHECK_INTERVAL=300s, ja online un saraksts beidzies)
  ├── PUSH:  Issuer push pie revokācijas → tikai online + nav dead mezgļi
  └── GOSSIP: seed mezgli fetch → izplata P2P (eksponenciāls kontaktu ātrums, contact_rate)
```

### Mezgla stāvokļi

Katram mezglam ir divi neatkarīgi bināri atribūti:

| Atribūts | Vērtības | Nozīme |
| --- | --- | --- |
| `is_online` | True/False | Savienojums ar Issuer. Pārslēdzas eksponenciāli (mean_online / mean_offline) |
| `is_dead` | True/False | Nav Issuer piekļuves **nekad** — tikai P2P gossip. Pastāvīgs visas simulācijas laikā |

`is_online` ietekmē tikai Issuer saziņu (PULL fetch, PUSH saņemšana). P2P gossip notiek neatkarīgi no `is_online`.

### Sēklas mezgli (seed nodes)

GOSSIP un MIXED stratēģijās `seed_ratio` (noklusēti 1%) mezglu ir tieša Issuer piekļuve. Tikai šie mezgli periodiski fetch jauno StatusList un tad izplata to pārējiem caur gossip. Tas modelē reālo scenāriju, kur lielākā daļa mezglu nav tieši savienoti ar Issuer.

### Holder prezentācijas (GOSSIP, MIXED)

HolderNode periodiski (mean_presentation_interval) piesakās pie nejaušu verifikātoru (~6 kaimiņi). Notikumā:

1. Ja holder versija > verifikatora versija un saraksts vēl nav beidzies → holder pārsūta savu sarakstu verifikatoram
2. Ja verifikatora versija > holder versija → verifikators pārsūta savu sarakstu holderim
3. Verifikators reģistrē verifikācijas mēģinājumu (`is_presentation=True`)

### Galvenie mērījumi

| Metrika | Apraksts |
| --- | --- |
| `false_acceptance_rate` (FAR) | Daļa no verifikācijām, kur mezgls nepareizi pieņēma atceltus akreditācijas datus |
| `propagation_delay_mean_s` | Vidējais laiks no revokācijas līdz 95% mezglu informētībai (izslēdzot dead mezglus) |
| `bandwidth_per_node_kb` | Vidējais pārsūtīto baitu skaits uz mezglu (tikai saņēmēja puse) |
| `coverage_rate` | Daļa revokāciju, kas sasniedza 95% pārklājumu simulācijas laikā |

### Parametri

| Parametrs | Noklusējums | Apraksts |
| --- | --- | --- |
| `network_size` | 500 | Verifikatoru skaits |
| `dead_ratio` | 0.1 | Daļa mezglu bez Issuer piekļuves |
| `offline_ratio` | 0.2 | Sākotnējā daļa offline mezglu (arī nosaka steady-state) |
| `ttl` | 28800 | StatusList derīguma laiks (sekundēs) |
| `revocation_rate` | 0.001 | Revokāciju biežums (notikumi/s) |
| `mean_online_duration` | 3600 | Vidējais online periods (s) |
| `mean_offline_duration` | 14400 | Vidējais offline periods (s) |
| `contact_rate` | 1/600 | Gossip kontaktu biežums uz mezglu (kontakti/s) |
| `seed_ratio` | 0.01 | Daļa mezglu ar tiešu Issuer piekļuvi (GOSSIP/MIXED) |

---

## Noklusētās simulācijas

Vienu reizi palaiž visas aktīvās stratēģijas un izdrukā salīdzināšanas tabulu.

```bash
python main.py
```

Jālabo `PARAMS` iekš [main.py](main.py) lai mainītu tīkla lielumu, TTL, dead_ratio utt.

!!! NAV IETEICAMS laist ļoti lielus tīkla izmērus, ja ir velme iepazīties ar sistēmas darbību. 500 mezgli izgriežas par aptuveni 30 sekundēm katrais stratēģijai, bet, piemēram, 5000, mezgli būs jāgaida jau 20 min katrai. To var samazinot ar daudzpavedienu izpildi, bet par to tālāk. 

---

## Vairāku seed simulācijas

Katru stratēģiju palaiž N reizes ar dažādiem sākotnējiem rādītājiem un aprēķina visu rādītāju vidējo vērtību.
Noderīgi ātrai saprāta pārbaudei pirms pilnas pārbaudes.

```bash
# Noklusēti: 5 seeds
python experiments/run_averaged.py

# Custom seed skaits
python experiments/run_averaged.py --runs 20
```

---

## Parameterizēts tests

Izslauka katru parametra dimensiju atsevišķi, saglabā CSV failus mapē `experiments/results/`.

```bash
# Pilns slaucījums, 10 seed katrā punktā, vienmērīgs (bez adaptīvas)
python experiments/run_sweep.py --runs 10 --no-adaptive --workers 8

# Izvēles dimensijas
python experiments/run_sweep.py --runs 10 --no-adaptive --dims dead_ratio offline_ratio ttl

# Divu parametru atbilstība (ttl x dead ration)
python experiments/run_sweep.py --runs 10 --no-adaptive --2d --workers 8

# LV adaptīvs režīms, automātiski pievieno sēklas augstas dispersijas punktiem (VK > 1,0 → līdz 15 sēklām)
python experiments/run_sweep.py --runs 5 --max-runs 15 --cv-threshold 1.0 --workers 8
```

**Galvenās atslēgas pie palaišanas:**

| Flag | Default | Description |
| --- | --- | --- |
| `--runs N` | 5 | Seeds per sweep point |
| `--max-runs N` | 15 | Max seeds for high-CV points (adaptive mode) |
| `--cv-threshold F` | 1.0 | CV above which extra seeds are added |
| `--no-adaptive` | off | Disable adaptive seeds — uniform n_runs everywhere |
| `--workers N` | cpu_count | Parallel workers |
| `--dims` | all | Space-separated list of dimensions to sweep |
| `--2d` | off | Also run 2D sweep (TTL × dead_ratio) |

**Pieejamās dimensijas:** `dead_ratio`, `offline_ratio`, `revocation_rate`, `ttl`, `network_size`, `mean_offline_duration`, `mean_online_duration`

**Piezīmes:**

- `offline_ratio` Automatiski pielāgo `mean_offline_duration`  lai nodrošinātu izvelēto atbilstību : `mean_offline = mean_online × ratio / (1 − ratio)`
- `network_size` automatiski normalizē `contact_rate`  lai būtu realistiski dati par mijiedarbības biežumu

---

## Tīkla izmēru eksperemennti 

Testē izplatīšanās aizkavi un FAR tīklos līdz pat 1 000 000 mezgliem.
Izmanto 1 dienas sim_duration un normalizētu contact_rate, lai noteiktu iespējamos izpildes laikus.

```bash
# Līdz 100 000 mezgliem (dažas min)
python experiments/run_scaling.py --max-n 100000 --runs 3 --workers 8

# Pilna līdz 1 000 000 mezgli (20–40 min )
python experiments/run_scaling.py --runs 3 --workers 8

# Custom
python experiments/run_scaling.py --max-n 10000 --runs 5 --workers 4
```

Saglabā `experiments/results/scaling_network_size.csv` un `scaling_network_size.png`.

---

## Vizualizēt rezultātus

Ģenerē PNG diagrammas no visiem esošajiem CSV failiem `experiments/results/`.

```bash
python experiments/plot_results.py
```

Izveido PNG failus pa dimensijām ar 95 % ticamības intervāla (CI) joslām, NaN anotācijām un lineāru pielāgojumu PULL FAR un dead_ratio vērtībām. Ja pastāv 2D slaucīšanas CSV fails, ģenerē arī
`sweep2d_far.png` un `sweep2d_delay.png` .

---

## Izejas faili

Visu pieglabā iekš `experiments/results/`:

| Fails | Apraksts |
| --- | --- |
| `sweep_{dim}.csv` | 1D tstu rezultāti ar vidējo vērtību, standartu, CI95 katram rādītājam |
| `sweep_{dim}.png` | Diagrammas ar 95% CI joslām |
| `sweep2d_ttl_x_dead_ratio.csv` | 2D testu rezultāti |
| `sweep2d_far.png` | FAR testi |
| `sweep2d_delay.png` | Aizkaves testi |
| `scaling_network_size.csv` | Tīkla izmēru testi |
| `scaling_network_size.png` | Testi prret o(log n) līkni |


## 2D testu labota vizualizācija 

# FAR noklusēti
python plot_heatmap_2d.py

# Aizkave
python plot_heatmap_2d.py --metric delay_mean_mean

# Joslas platums
python plot_heatmap_2d.py --metric bandwidth_per_node_kb_mean

# Vienota vvizualizācija 4 stratēģijām
python plot_heatmap_2d.py --metric far_mean --shared-scale

# Var mainīt faila nosaukumu, lai nepārrakstīt
python plot_heatmap_2d.py --csv mani_dati.csv --output rezultats.png