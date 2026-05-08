# DID Offline Revocation — Gossip Simulation

## Noklusētās simulācijas

Vienu reizi palaiž visas aktīvās stratēģijas un izdrukā salīdzināšanas tabulu.

```bash
python main.py
```

Jālabo `PARAMS` iekš [main.py](main.py) lai mainītu tīkla lielumu, TTL, dead_ratio utt.

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