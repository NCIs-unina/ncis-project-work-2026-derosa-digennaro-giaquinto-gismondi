# Adaptive and Policy-Aware DoS Detection and Mitigation in an SDN Network

## Autori

- De Rosa — matricola: **DE9000164**
- Di Gennaro — matricola: **DE9000051**
- Giaquinto — matricola: **DE9000142**
- Gismondi — matricola: **DE9000188**

Repository GitHub:

`https://github.com/NCIs-unina/ncis-project-work-2026-derosa-digennaro-giaquinto-gismondi`

---

## 1. Obiettivo

Il progetto realizza un sistema di **rilevazione e mitigazione reattiva di attacchi DoS volumetrici** in una rete Software Defined Networking.

La rete è emulata con **Mininet** e **Open vSwitch**; il piano di controllo utilizza **Ryu** e **OpenFlow 1.3**.

Il lavoro parte da un prototipo baseline semplice, basato su soglia statica e DROP dell'intera porta, e lo evolve correggendo cinque criticità progettuali e introducendo una funzionalità aggiuntiva:

| Fase | Problema / funzionalità | Soluzione implementata |
|---|---|---|
| **M1** | Lack of Modular Detection and Mitigation Design | Separazione in moduli di monitoraggio, detection, tracking, mitigazione, logging e policy |
| **M2** | Over-blocking | DROP mirato per `ipv4_src`, senza bloccare tutte le sorgenti presenti sull'uplink |
| **M3** | Static Threshold | Baseline adattiva con training + EWMA e soglia dinamica |
| **M4** | Controller-Centric Blocking Decisions | Blocklist amministrativa esterna caricata da file JSON |
| **M5** | Inflexible Blocking/Unblocking | Sblocco automatico traffic-aware, senza `hard_timeout` fisso |
| **M6** | Extra feature: External Allowlist | Allowlist amministrativa che può sopprimere la mitigazione automatica per sorgenti trusted |

La versione finale mantiene inoltre una protezione contro il decadimento artificiale della baseline EWMA durante i periodi idle o nei piccoli residui di traffico post-flusso.

---

## 2. Topologia finale

La topologia utilizzata per la validazione finale è definita in:

```text
topology/overblocking_topo.py
```

Schema:

```text
                    +------ h2 10.0.0.2
                    |
h1 10.0.0.1 --+     |
              +-- s2 -- shared uplink -- s1 -- h4 10.0.0.4
h5 10.0.0.5 --+                    |      victim
                                   |
                                   +------ h3 10.0.0.3
```

Più precisamente:

```text
h1 attacker ── s2-eth2
                  |
h5 legitimate ─ s2-eth3
                  |
               s2-eth4
                  |
               s1-eth1   <- uplink condiviso monitorato
              /   |   \
             /    |    \
          h2     h3    h4 victim
                      5 Mbit/s
```

Mapping principale:

| Nodo | Ruolo | IP | Collegamento |
|---|---|---|---|
| `h1` | attacker | `10.0.0.1` | `s2` port 2 |
| `h5` | legitimate shared host | `10.0.0.5` | `s2` port 3 |
| `h2` | legitimate host | `10.0.0.2` | `s1` port 2 |
| `h3` | legitimate host | `10.0.0.3` | `s1` port 3 |
| `h4` | victim/server | `10.0.0.4` | `s1` port 4 |
| `s2` → `s1` | shared uplink | — | `s2` port 4 → `s1` port 1 |

Caratteristiche:

- link host/access: **100 Mbit/s**;
- uplink `s2 ↔ s1`: **100 Mbit/s**;
- link `s1 ↔ h4`: **5 Mbit/s**, usato come bottleneck;
- `s1` DPID = `1`;
- `s2` DPID = `2`;
- OpenFlow 1.3;
- controller remoto `127.0.0.1:6653`.

La presenza di `h1` e `h5` dietro lo stesso uplink consente di verificare esplicitamente il problema dell'**over-blocking**: un DROP generico su `s1-eth1` colpirebbe entrambe le sorgenti.

---

## 3. Architettura del controller

Il controller finale è:

```text
controller/dos_controller.py
```

La logica non è più concentrata in un singolo blocco, ma è suddivisa in componenti con responsabilità separate:

```text
TrafficMonitor
      |
      v
AdaptiveDetector
      |
      v
SourceTracker ---> SourceSelector
      |                 |
      +--------+--------+
               |
               v
           Mitigator
               |
               v
           OpenFlow

ExternalPolicyStore ---> PolicyEnforcer ---> Mitigator

Blocklist automatic state ---> Intelligent Unblock
StatsLogger -----------------> CSV
```

Componenti principali:

- **TrafficMonitor**: richiede e processa le PortStats OpenFlow;
- **AdaptiveDetector**: training, baseline EWMA, threshold dinamico e conteggio degli hit;
- **SourceTracker**: apprende IP/MAC osservati sulle porte;
- **SourceSelector**: individua la sorgente ad alto rate candidata alla mitigazione;
- **Blocklist**: mantiene lo stato delle mitigazioni automatiche attive;
- **Mitigator**: installa e rimuove le regole OpenFlow;
- **StatsLogger**: salva rate, baseline, threshold, stato e azioni in CSV;
- **ExternalPolicyStore**: legge `blocked_ipv4` e `allowlisted_ipv4` dal JSON;
- **PolicyEnforcer**: riconcilia le policy amministrative con le flow OpenFlow;
- **DosController**: orchestra tutti i moduli.

---

## 4. Detection adattiva

Parametri principali della versione finale:

```python
POLL_INTERVAL = 2
POLICY_POLL_INTERVAL = 1

MIN_THRESHOLD_MBPS = 1.5
THRESHOLD_MULTIPLIER = 1.5
EWMA_ALPHA = 0.2

TRAINING_SAMPLES = 5
TRAINING_MIN_MBPS = 0.1
BASELINE_UPDATE_MIN_RATIO = 0.25

REQUIRED_HITS = 3
MONITORED_PORTS = {1}
```

### Calcolo del rate

Il controller legge i byte cumulativi ricevuti sulla porta:

```text
rx_bytes(t)
```

e calcola:

```text
rate [Mbit/s] =
    8 * (rx_bytes(t) - rx_bytes(t-1))
    ---------------------------------
       (t - t-1) * 1,000,000
```

### Training

Per ogni porta monitorata vengono raccolti **5 campioni attivi** con rate almeno:

```text
0.1 Mbit/s
```

Durante il training, la baseline è la media dei campioni osservati.

### Threshold adattivo

Terminato il training:

```text
threshold = max(
    MIN_THRESHOLD_MBPS,
    THRESHOLD_MULTIPLIER * baseline
)
```

con:

```text
MIN_THRESHOLD_MBPS = 1.5
THRESHOLD_MULTIPLIER = 1.5
```

La baseline viene aggiornata tramite EWMA:

```text
baseline_new =
    alpha * rate +
    (1 - alpha) * baseline_old
```

con:

```text
alpha = 0.2
```

### Protezione della baseline

La baseline non viene aggiornata:

1. mentre `rate > threshold`, per evitare threshold poisoning durante l'attacco;
2. quando il traffico è troppo basso per rappresentare traffico benigno attivo.

Dopo il training, il floor dinamico è:

```text
active_floor = max(
    TRAINING_MIN_MBPS,
    BASELINE_UPDATE_MIN_RATIO * baseline
)
```

dove:

```text
BASELINE_UPDATE_MIN_RATIO = 0.25
```

In questo modo piccoli residui post-flusso e campioni idle non trascinano artificialmente la baseline verso zero.

### Detection

Un'anomalia diventa attacco dopo:

```text
3 campioni consecutivi
```

con:

```text
rate > threshold
```

---

## 5. Mitigazione automatica mirata

Il controller non installa più:

```text
match(in_port=1) -> DROP
```

perché tale regola provocherebbe over-blocking su un uplink condiviso.

Il `SourceTracker` apprende invece la posizione delle sorgenti e il `SourceSelector` seleziona la sorgente ad alto rate.

Per esempio, se `h1 = 10.0.0.1` è identificato come offender, su `s1` viene installata una regola:

```text
priority=100
in_port=1
eth_type=IPv4
ipv4_src=10.0.0.1
actions=drop
```

La flow è quindi mirata alla singola sorgente IPv4.

La regola automatica usa:

```text
hard_timeout = 0
idle_timeout = 0
```

e non viene rimossa da un timer fisso.

---

## 6. Intelligent Unblock

La versione baseline rimuoveva il DROP dopo un `hard_timeout` fisso. La versione finale usa invece il traffico reale della sorgente.

Parametri:

```python
UNBLOCK_RATE_MBPS = 0.1
UNBLOCK_QUIET_SAMPLES = 3
```

Quando una sorgente è bloccata, il controller continua a monitorare la sua porta host-facing, ad esempio:

```text
h1 -> s2 port 2
```

Se il rate della sorgente è:

```text
<= 0.1 Mbit/s
```

per **3 campioni consecutivi**, il controller rimuove esplicitamente la flow automatica tramite:

```text
OFPFC_DELETE_STRICT
```

Questo evita sia:

- uno sblocco prematuro mentre l'attacco è ancora attivo;
- un blocco inutilmente lungo dopo la fine dell'attacco.

---

## 7. Policy amministrative esterne

Il file:

```text
policy/blocklist.json
```

ha il formato:

```json
{
  "blocked_ipv4": [],
  "allowlisted_ipv4": []
}
```

Il controller lo rilegge ogni:

```text
1 s
```

### Blocklist

Esempio:

```json
{
  "blocked_ipv4": ["10.0.0.5"],
  "allowlisted_ipv4": []
}
```

Il controller individua una porta dove quella sorgente è l'unico host appreso e installa una policy amministrativa persistente con:

```text
priority=110
```

Esempio per `h5`:

```text
priority=110,ip,in_port=3,nw_src=10.0.0.5 actions=drop
```

sullo switch `s2`.

La policy resta installata finché l'indirizzo rimane in `blocked_ipv4`.

### Allowlist

Esempio:

```json
{
  "blocked_ipv4": [],
  "allowlisted_ipv4": ["10.0.0.5"]
}
```

Il monitoraggio e la detection continuano normalmente, ma il controller non installa un DROP automatico sulla sorgente trusted.

L'evento viene registrato come:

```text
ALLOWLIST_SUPPRESSED
```

### Conflitto

Se un indirizzo compare contemporaneamente in:

```text
blocked_ipv4
```

e:

```text
allowlisted_ipv4
```

ha precedenza la **blocklist amministrativa**.

---

## 8. Logging

Con la variabile:

```bash
RUN_ID=<nome>
```

il controller crea:

```text
results/raw/<nome>_controller.csv
```

Campi principali:

```text
timestamp
dpid
port
rx_mbps
hits
blocked
action
baseline_mbps
threshold_mbps
training_count
trained
```

Azioni significative:

```text
DROP_INSTALLED
DROP_REMOVED
ALLOWLIST_SUPPRESSED
TARGET_NOT_FOUND
```

Le policy amministrative vengono inoltre riportate nel log Ryu tramite eventi:

```text
POLICY ADD
POLICY REMOVE
ALLOWLIST UPDATE
```

---

## 9. Requisiti

Ambiente utilizzato:

- Ubuntu 22.04 su WSL2;
- Python 3.10;
- Mininet 2.3.0;
- Open vSwitch;
- OpenFlow 1.3;
- Ryu 4.34;
- iperf3;
- matplotlib per i grafici finali.

Il virtual environment Ryu viene mantenuto separato:

```bash
python3 -m venv ~/ryuenv
source ~/ryuenv/bin/activate
pip install -r requirements-lock.txt
```

L'ambiente Ryu utilizzato comprende:

```text
Ryu 4.34
eventlet 0.33.2
dnspython 2.2.1
setuptools 67.6.1
packaging 20.9
```

Matplotlib non è necessario all'esecuzione del controller e può essere utilizzato con il Python di sistema.

---

## 10. Avvio

### Pulizia iniziale

Eseguire il cleanup **prima** di Ryu:

```bash
cd ~/ncis-project
sudo mn -c
```

> `sudo mn -c` può terminare processi `ryu-manager`; per questo non deve essere eseguito mentre il controller deve restare attivo.

### Controller

Terminale 1:

```bash
cd ~/ncis-project
source ~/ryuenv/bin/activate
RUN_ID=FINAL_A ryu-manager --ofp-tcp-listen-port 6653 controller/dos_controller.py
```

### Mininet

Terminale 2:

```bash
cd ~/ncis-project
sudo python3 topology/overblocking_topo.py
```

Verifica:

```text
pingall
```

Risultato atteso:

```text
*** Results: 0% dropped
```

---

## 11. Validazione finale

Le evidenze finali sono conservate in:

```text
results/final/
```

### FINAL-A — Adaptive detection, targeted mitigation e intelligent unblock

FINAL-A verifica congiuntamente:

- stabilità della baseline adattiva;
- threshold dinamico;
- detection;
- targeted DROP;
- assenza di over-blocking;
- persistenza del blocco mentre l'attacco continua;
- intelligent unblock dopo la cessazione del traffico.

Risultati:

| Metrica | Risultato |
|---|---:|
| Baseline dopo training | **2.044 Mbit/s** |
| Threshold adattivo | **3.066 Mbit/s** |
| Detection delay | **5.608 s** |
| Durata della flow di DROP | **58.919 s** |
| Unblock dopo la fine del traffico | **4.526 s** |
| Packet loss `h1` durante mitigazione | **100%** |
| Packet loss `h5` durante mitigazione | **0%** |
| Packet loss `h2` durante mitigazione | **0%** |
| Packet loss `h1` dopo unblock | **0%** |

Flow automatica osservata:

```text
priority=100,ip,in_port=1,nw_src=10.0.0.1 actions=drop
```

La regola resta presente ben oltre il vecchio timeout fisso di 20 s quando l'attacco continua e viene rimossa solo dopo l'osservazione di traffico quiet.

### FINAL-B — Allowlist e blocklist runtime

FINAL-B verifica le policy amministrative sulla sorgente `h5 = 10.0.0.5`.

| Condizione | Packet loss h5 | Comportamento |
|---|---:|---|
| Allowlist ON + high-rate traffic | **0%** | `ALLOWLIST_SUPPRESSED`, nessun DROP automatico |
| Allowlist OFF + stesso high-rate traffic | **100%** | DROP automatico `priority=100` |
| Blocklist ON | **100%** | DROP amministrativo `priority=110` |
| Blocklist OFF | **0%** | policy amministrativa rimossa |

Durante il blocco amministrativo di `h5`:

```text
h1 packet loss = 0%
h2 packet loss = 0%
```

La policy è quindi selettiva.

---

## 12. Dataset e grafici finali

Dataset:

```text
results/final/summary.csv
results/final/improvements.csv
results/final/raw/FINAL_A_controller.csv
results/final/raw/FINAL_B_controller.csv
```

Generazione grafici:

```bash
python3 scripts/generate_final_plots.py
```

Output:

```text
results/final/plots/final_a_adaptive_detection.png
results/final/plots/final_a_adaptive_threshold_zoom.png
results/final/plots/final_a_selectivity.png
results/final/plots/final_b_policy_effects.png
```

### Adaptive detection

`final_a_adaptive_detection.png` mostra:

- rate misurato;
- baseline adattiva;
- threshold;
- `DROP_INSTALLED`;
- `DROP_REMOVED`.

### Adaptive threshold zoom

`final_a_adaptive_threshold_zoom.png` usa una vista verticale 0–6 Mbit/s per rendere leggibili baseline e threshold.

### Selective mitigation

`final_a_selectivity.png` mostra:

```text
h1 attacker     100% loss
h5 legitimate     0% loss
h2 legitimate     0% loss
```

### Runtime policies

`final_b_policy_effects.png` mostra:

```text
Allowlist ON      0%
Allowlist OFF   100%
Blocklist ON    100%
Blocklist OFF     0%
```

---

## 13. Struttura del repository

File principali:

```text
controller/
  dos_controller.py

topology/
  overblocking_topo.py
  simple_dos_topo.py

policy/
  blocklist.json

scripts/
  generate_final_plots.py

results/
  final/
    summary.csv
    improvements.csv
    raw/
      FINAL_A_controller.csv
      FINAL_B_controller.csv
    plots/
      final_a_adaptive_detection.png
      final_a_adaptive_threshold_zoom.png
      final_a_selectivity.png
      final_b_policy_effects.png

requirements-lock.txt
README.md
```

I file e gli esperimenti della baseline rimangono nel repository come traccia dell'evoluzione del progetto.

---

## 14. Evoluzione rispetto alla baseline

La versione iniziale utilizzava:

```text
threshold statico = 1.5 Mbit/s
3 hit consecutivi
DROP generico per in_port
hard_timeout = 20 s
```

La versione finale utilizza invece:

```text
training benigno
        |
        v
adaptive baseline + EWMA
        |
        v
dynamic threshold
        |
        v
3 hit consecutivi
        |
        v
source identification
        |
        v
targeted DROP per IPv4
        |
        v
traffic-aware intelligent unblock
```

A questa pipeline automatica si affianca:

```text
external JSON policy
      |
      +--> blocked_ipv4 ----> persistent admin DROP
      |
      +--> allowlisted_ipv4 -> suppress automatic mitigation
```

---

## 15. Limiti

Il progetto rimane un proof of concept didattico.

La validazione finale è focalizzata su:

- attacchi DoS volumetrici;
- identificazione di una sorgente heavy-hitter;
- porte host-facing con una singola sorgente appresa;
- topologia a due switch;
- controllo centralizzato Ryu/OpenFlow.

Non vengono affrontati in questa versione:

- DDoS distribuito multi-sorgente;
- attacchi stealthy / low-rate;
- classificazione ML;
- entropy-based detection;
- autenticazione o firma del file di policy;
- deployment multi-controller;
- valutazioni su topologie di larga scala.

Questi aspetti rappresentano possibili estensioni future.

---

## 16. Cleanup

A fine esperimento:

1. uscire da Mininet:

```text
exit
```

2. terminare Ryu con:

```text
Ctrl+C
```

3. eseguire:

```bash
sudo mn -c
```

La sequenza consigliata è:

```text
sudo mn -c
    |
    v
start Ryu
    |
    v
start Mininet
    |
    v
experiment
    |
    v
exit Mininet
    |
    v
Ctrl+C Ryu
    |
    v
sudo mn -c
```
