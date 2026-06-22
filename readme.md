# 1MPD — Transportlīdzekļu maršrutēšanas problēma ar Simulētās dzesēšanas algoritmu

> **Mazais praktiskais darbs** — Praktiskā kombinatoriālā optimizācija  
> Students: `am21169`

---

## 🇱🇻 Latviešu valodā

### Apraksts

Šis projekts risina **Transportlīdzekļu maršrutēšanas problēmu (VRP)** izmantojot **Simulētās dzesēšanas (Simulated Annealing, SA)** metaheiristisko algoritmu.

Programma ģenerē nejaušus piegādes punktus 2D plaknē un meklē optimālus maršrutus vienam vai vairākiem transportlīdzekļiem, ievērojot katram transportlīdzeklim noteikto degvielas ierobežojumu. Galvenais mērķis — apmeklēt pēc iespējas vairāk punktu ar minimālu kopējo nobraukumu.

### Kā darbojas algoritms

1. **Sākumrisinājums** — punkti tiek sadalīti starp transportlīdzekļiem, ievērojot degvielas limitus.
2. **Kaimiņrisinājumu ģenerēšana** — katrā iterācijā tiek nejauši piemērota viena no operācijām:
   - `add_unvisited` — pievieno neapmeklētu punktu kādam maršrutam
   - `move` — pārvieto punktu no viena maršruta uz citu
   - `remove` — izņem punktu no maršruta
   - `swap` — maina divus punktus vietām vienā maršrutā
   - `2-opt` — apgriež maršruta apakšsegmentu, samazinot krustošanās
3. **Pieņemšanas kritērijs** — labāks risinājums vienmēr tiek pieņemts; sliktāks — ar varbūtību `exp(-Δ/T)`.
4. **Temperatūras samazināšana** — `T = T * cooling_rate` pēc katras iterācijas.
5. **Apstāšanās** — kad temperatūra nokrītas zem `MIN_TEMP` vai sasniegts `MAX_ITERATIONS`.

### Izmaksas

Kopējās izmaksas = kopējais maršruta garums + sodi:
- **Sods par neapmeklētu punktu**: `PENALTY_PER_POINT` par katru izlaisto punktu
- **Sods par limita pārsniegšanu**: `300 × (garums - limits)` par katru pārsniegumu

### Prasības

- Python 3.8+
- `matplotlib`

Instalēšana:
```bash
pip install matplotlib
```

### Palaišana

```bash
python am21169.py
```

Programma nolasa parametrus no `config.json` faila, kas atrodas tajā pašā mapē.

### Konfigurācija (`config.json`)

| Parametrs | Noklusējums | Apraksts |
|---|---|---|
| `N_POINTS` | `20` | Piegādes punktu skaits |
| `N_VEHICLES` | `1` | Transportlīdzekļu skaits |
| `VEHICLE_LIMITS` | `[1500]` | Degvielas ierobežojums katram transportlīdzeklim |
| `PENALTY_PER_POINT` | `100` | Sods par katru neapmeklētu punktu |
| `DEPOT` | `[0, 0]` | Depo koordinātes |
| `INITIAL_TEMP` | `10000` | Sākuma temperatūra SA algoritmam |
| `COOLING_RATE` | `0.999` | Atvēsināšanas koeficients (0–1) |
| `MIN_TEMP` | `1` | Minimālā temperatūra, pie kuras apstājas |
| `MAX_ITERATIONS` | `15000` | Maksimālais iterāciju skaits |
| `VISUAL` | `false` | Vizualizācija ar matplotlib (`true`/`false`) |
| `ADD_DESCRIPTION` | `false` | Detalizēta izdruka par katru mašīnu (`true`/`false`) |

**Piemērs ar vairākiem transportlīdzekļiem:**
```json
{
  "N_POINTS": 30,
  "N_VEHICLES": 3,
  "VEHICLE_LIMITS": [800, 800, 800],
  "PENALTY_PER_POINT": 100,
  "DEPOT": [0, 0],
  "INITIAL_TEMP": 10000,
  "COOLING_RATE": 0.999,
  "MIN_TEMP": 1,
  "MAX_ITERATIONS": 20000,
  "VISUAL": true,
  "ADD_DESCRIPTION": true
}
```

### Failu struktūra

```
1mpd_am21169/
├── am21169.py          # Galvenais skripts ar SA algoritmu
├── config.json         # Konfigurācijas parametri
└── 1mpd_am21169.pdf    # Uzdevuma apraksts
```

---

## 🇬🇧 English

### Description

This project solves the **Vehicle Routing Problem (VRP)** using the **Simulated Annealing (SA)** metaheuristic algorithm.

The program generates random delivery points on a 2D plane and searches for optimal routes for one or more vehicles, respecting per-vehicle fuel (distance) limits. The primary goal is to visit as many points as possible with minimum total travel distance.

### How the algorithm works

1. **Initial solution** — points are greedily distributed among vehicles while respecting fuel limits.
2. **Neighbour generation** — at each iteration, one random operation is applied:
   - `add_unvisited` — insert an unvisited point into a route
   - `move` — transfer a point from one vehicle's route to another
   - `remove` — drop a point from a route (it becomes unvisited)
   - `swap` — swap two points within the same route
   - `2-opt` — reverse a sub-segment of a route to eliminate crossings
3. **Acceptance criterion** — a better solution is always accepted; a worse one is accepted with probability `exp(-Δ/T)`.
4. **Cooling** — `T = T * cooling_rate` after each iteration.
5. **Termination** — when temperature drops below `MIN_TEMP` or `MAX_ITERATIONS` is reached.

### Cost function

Total cost = total route length + penalties:
- **Unvisited point penalty**: `PENALTY_PER_POINT` per skipped point
- **Limit violation penalty**: `300 × (length - limit)` per vehicle over its limit

### Requirements

- Python 3.8+
- `matplotlib`

Install dependencies:
```bash
pip install matplotlib
```

### Running

```bash
python am21169.py
```

The program reads all parameters from `config.json` in the same directory.

### Configuration (`config.json`)

| Parameter | Default | Description |
|---|---|---|
| `N_POINTS` | `20` | Number of delivery points |
| `N_VEHICLES` | `1` | Number of vehicles |
| `VEHICLE_LIMITS` | `[1500]` | Max distance (fuel) per vehicle |
| `PENALTY_PER_POINT` | `100` | Penalty per unvisited point |
| `DEPOT` | `[0, 0]` | Depot coordinates |
| `INITIAL_TEMP` | `10000` | Starting temperature for SA |
| `COOLING_RATE` | `0.999` | Cooling coefficient (0–1) |
| `MIN_TEMP` | `1` | Minimum temperature before stopping |
| `MAX_ITERATIONS` | `15000` | Maximum number of iterations |
| `VISUAL` | `false` | Show matplotlib visualization (`true`/`false`) |
| `ADD_DESCRIPTION` | `false` | Print per-vehicle detailed stats (`true`/`false`) |

**Example with multiple vehicles:**
```json
{
  "N_POINTS": 30,
  "N_VEHICLES": 3,
  "VEHICLE_LIMITS": [800, 800, 800],
  "PENALTY_PER_POINT": 100,
  "DEPOT": [0, 0],
  "INITIAL_TEMP": 10000,
  "COOLING_RATE": 0.999,
  "MIN_TEMP": 1,
  "MAX_ITERATIONS": 20000,
  "VISUAL": true,
  "ADD_DESCRIPTION": true
}
```

### File structure

```
1mpd_am21169/
├── am21169.py          # Main script with SA algorithm
├── config.json         # Configuration parameters
└── 1mpd_am21169.pdf    # Assignment description
```

### Output

The program prints a comparison between the initial and optimised solution costs, total distance, penalty breakdown, execution time, and — if `ADD_DESCRIPTION` is enabled — a per-vehicle breakdown showing route sequence, distance used, and remaining fuel capacity. If `VISUAL` is enabled, a colour-coded route map is rendered showing each vehicle's path and any unvisited points.