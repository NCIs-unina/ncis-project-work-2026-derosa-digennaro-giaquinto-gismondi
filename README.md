# Reactive DoS Detection and Mitigation in an SDN Network using Ryu and OpenFlow

## Autori

- De Rosa — matricola: **DE9000164**
- Di Gennaro — matricola: **DE9000051**
- Giaquinto — matricola: **DE9000142**
- Gismondi — matricola: **DE9000188**

Repository GitHub:

https://github.com/NCIs-unina/ncis-project-work-2026-derosa-digennaro-giaquinto-gismondi

---

## 1. Obiettivo

Il progetto realizza un semplice meccanismo di **rilevazione e mitigazione reattiva di un attacco DoS volumetrico** in una rete Software Defined Networking.

La rete viene emulata con **Mininet** e **Open vSwitch**, mentre il piano di controllo è implementato con **Ryu** e **OpenFlow 1.3**.

La logica del controller segue la pipeline:

```text
monitor -> detect -> block
```

Il controller:

1. richiede periodicamente le statistiche delle porte dello switch;
2. calcola il rate di ingresso sulla porta monitorata;
3. rileva un traffico anomalo quando il rate supera una soglia statica per più campioni consecutivi;
4. installa una regola OpenFlow di DROP sulla porta dell'attaccante;
5. lascia che la regola venga rimossa automaticamente tramite `hard_timeout`.

Il progetto è volutamente un **proof of concept** semplice: non utilizza classificatori, machine learning, entropy, flow-level inspection o tecniche di mitigazione avanzate.

---

## 2. Architettura

Topologia:

```text
h1 attacker ─┐
h2 legit ────┼── s1 ── 5 Mbit/s ── h4 victim
h3 legit ────┘
                 ↑
                Ryu
```

Indirizzamento e mapping delle porte:

| Host | Ruolo | IP | Porta su `s1` |
|---|---|---|---:|
| `h1` | Attacker | `10.0.0.1` | 1 |
| `h2` | Legitimate client | `10.0.0.2` | 2 |
| `h3` | Legitimate client | `10.0.0.3` | 3 |
| `h4` | Victim/server | `10.0.0.4` | 4 |

I link di accesso di `h1`, `h2` e `h3` sono configurati a 100 Mbit/s.

Il link:

```text
s1-eth4 <-> h4-eth0
```

è limitato a **5 Mbit/s** e rappresenta il bottleneck condiviso.

---

## 3. Requisiti

Ambiente usato durante lo sviluppo:

- Ubuntu 22.04 su WSL2;
- Python 3.10;
- Mininet 2.3.0;
- Open vSwitch;
- OpenFlow 1.3;
- Ryu 4.34;
- iperf3;
- pandas;
- matplotlib.

Per Mininet sono necessari anche i normali strumenti installati dal relativo script di setup.

Esempio di installazione Mininet 2.3.0:

```bash
git clone https://github.com/mininet/mininet
cd mininet
git checkout 2.3.0
sudo PYTHON=python3 util/install.sh -nv
```

Verifica:

```bash
sudo mn --switch ovsbr --test pingall
```

Per gli strumenti di analisi:

```bash
sudo apt update
sudo apt install -y python3-pandas python3-matplotlib
```

Verifica:

```bash
python3 -c 'import pandas, matplotlib; print("analysis environment OK")'
```

---

## 4. Setup di Ryu

Il controller viene eseguito in un virtual environment separato.

Creazione del virtual environment:

```bash
python3 -m venv ~/ryuenv
source ~/ryuenv/bin/activate
```

Installare le dipendenze del progetto:

```bash
pip install -r requirements-lock.txt
```

L'ambiente utilizzato durante lo sviluppo comprende:

```text
Ryu 4.34
eventlet 0.33.2
dnspython 2.2.1
setuptools 67.6.1
packaging 20.9
```

> **Importante:** l'ambiente Ryu e l'ambiente usato per l'analisi dei dati sono separati. `pandas` e `matplotlib` possono essere eseguiti con il Python di sistema.

### Nota importante sul cleanup di Mininet

Eseguire:

```text
sudo mn -c
```

**prima di avviare Ryu, non dopo**, perché il cleanup di Mininet termina anche processi `ryu-manager`.

La sequenza corretta è:

```text
sudo mn -c
    ↓
start Ryu
    ↓
start Mininet
    ↓
esperimento
    ↓
exit Mininet
    ↓
Ctrl+C Ryu
    ↓
sudo mn -c
```

---

## 5. Topologia

Il file della topologia è:

```text
topology/simple_dos_topo.py
```

Avvio:

```bash
cd ~/ncis-project
sudo python3 topology/simple_dos_topo.py
```

Dentro la CLI Mininet verificare la connettività:

```text
pingall
```

Il risultato atteso è:

```text
*** Results: 0% dropped
```

Per verificare il bottleneck:

```text
sh tc class show dev s1-eth4
```

La classe deve riportare:

```text
rate 5Mbit ceil 5Mbit
```

---

## 6. Controller

Il controller custom è:

```text
controller/dos_controller.py
```

Parametri principali:

```python
POLL_INTERVAL = 2
THRESHOLD_MBPS = 1.5
REQUIRED_HITS = 3
BLOCK_SECONDS = 20
MONITORED_PORTS = {1}
```

Il prototipo monitora quindi la porta 1, alla quale è collegato `h1`.

Ogni 2 secondi il controller invia una `OFPPortStatsRequest`.

Il rate viene calcolato usando la differenza tra due valori cumulativi di `rx_bytes`:

```text
rate [bit/s] =
    8 * (rx_bytes(t) - rx_bytes(t-1))
    ---------------------------------
             t - (t-1)
```

Il valore viene poi convertito in Mbit/s.

Quando:

```text
rate > 1.5 Mbit/s
```

per **3 campioni consecutivi**, il controller installa:

```text
match(in_port=1) -> DROP
```

con:

```text
priority = 100
hard_timeout = 20 s
```

### Avvio del controller custom

```bash
cd ~/ncis-project
source ~/ryuenv/bin/activate

RUN_ID=E3 \
ryu-manager \
    --ofp-tcp-listen-port 6653 \
    controller/dos_controller.py
```

Il controller salva automaticamente:

```text
results/raw/E3_controller.csv
```

---

## 7. Controller standard per E1 ed E2

Gli scenari senza protezione usano il learning switch standard di Ryu:

```bash
cd ~/ncis-project
source ~/ryuenv/bin/activate

ryu-manager \
    --ofp-tcp-listen-port 6653 \
    ryu.app.simple_switch_13
```

---

## 8. Scenario E1 — Baseline

E1 misura il comportamento della rete senza attacco.

Traffico:

```text
h2 -> h4 = 2 Mbit/s UDP
h3 -> h4 = 2 Mbit/s UDP
durata = 30 s
```

Usare il controller standard.

Dentro Mininet:

```text
sh pkill iperf3

h4 iperf3 -s -p 5201 -D
h4 iperf3 -s -p 5202 -D

h2 sh -c 'ping -D -i 0.5 -c 60 10.0.0.4 > /tmp/E1_ping_h2.txt 2>&1 &'

h2 sh -c 'iperf3 -c 10.0.0.4 -u -b 2M -t 30 -p 5201 > /tmp/E1_h2.txt 2>&1 &'
h3 sh -c 'iperf3 -c 10.0.0.4 -u -b 2M -t 30 -p 5202 > /tmp/E1_h3.txt 2>&1 &'

sh sleep 32

sh cp /tmp/E1_ping_h2.txt results/raw/E1_ping_h2.txt
sh cp /tmp/E1_h2.txt results/raw/E1_h2.txt
sh cp /tmp/E1_h3.txt results/raw/E1_h3.txt
```

---

## 9. Scenario E2 — DoS senza protezione

E2 utilizza lo stesso controller standard di E1.

Timeline prevista:

```text
t = 0 s   partono h2 e h3
t = 10 s  parte h1
t = 25 s  termina h1
t = 30 s  terminano h2 e h3
```

Traffico:

```text
h2 -> h4 = 2 Mbit/s UDP
h3 -> h4 = 2 Mbit/s UDP
h1 -> h4 = offered load configurato a 20 Mbit/s UDP
```

Dentro Mininet:

```text
sh pkill iperf3

h4 iperf3 -s -p 5201 -D
h4 iperf3 -s -p 5202 -D
h4 iperf3 -s -p 5203 -D

h2 sh -c 'ping -D -i 0.5 -c 70 10.0.0.4 > /tmp/E2_ping_h2.txt 2>&1 &'

h2 sh -c 'iperf3 -c 10.0.0.4 -u -b 2M -t 30 -p 5201 > /tmp/E2_h2.txt 2>&1 &'
h3 sh -c 'iperf3 -c 10.0.0.4 -u -b 2M -t 30 -p 5202 > /tmp/E2_h3.txt 2>&1 &'

sh sleep 10

sh date +%s.%N > /tmp/E2_attack_start.txt

h1 sh -c 'iperf3 -c 10.0.0.4 -u -b 20M -t 15 -p 5203 > /tmp/E2_h1_attack.txt 2>&1 &'

sh sleep 15
sh sleep 12

sh cp /tmp/E2_ping_h2.txt results/raw/E2_ping_h2.txt
sh cp /tmp/E2_h2.txt results/raw/E2_h2.txt
sh cp /tmp/E2_h3.txt results/raw/E2_h3.txt
sh cp /tmp/E2_h1_attack.txt results/raw/E2_h1_attack.txt
sh cp /tmp/E2_attack_start.txt results/raw/E2_attack_start.txt
```

Per il dataset finale, la fine canonica dell'attacco E2 è:

```text
attack_end = attack_start + 15 s
```

perché il timestamp di fine della prima esecuzione sperimentale era stato raccolto manualmente in ritardo.

---

## 10. Scenario E3 — DoS con protezione

E3 mantiene la stessa topologia, lo stesso traffico e la stessa durata di E2.

L'unica differenza concettuale è il controller custom.

Avviare:

```bash
RUN_ID=E3 \
ryu-manager \
    --ofp-tcp-listen-port 6653 \
    controller/dos_controller.py
```

Poi, dentro Mininet:

```text
sh pkill iperf3

h4 iperf3 -s -p 5201 -D
h4 iperf3 -s -p 5202 -D
h4 iperf3 -s -p 5203 -D

h2 sh -c 'ping -D -i 0.5 -c 70 10.0.0.4 > /tmp/E3_ping_h2.txt 2>&1 &'

h2 sh -c 'iperf3 -c 10.0.0.4 -u -b 2M -t 30 -p 5201 > /tmp/E3_h2.txt 2>&1 &'
h3 sh -c 'iperf3 -c 10.0.0.4 -u -b 2M -t 30 -p 5202 > /tmp/E3_h3.txt 2>&1 &'

sh sleep 10

h1 sh -c 'date +%s.%N > /tmp/E3_attack_start.txt; (sleep 15; date +%s.%N > /tmp/E3_attack_end.txt) & iperf3 -c 10.0.0.4 -u -b 20M -t 15 -p 5203 > /tmp/E3_h1_attack.txt 2>&1 &'

sh sleep 27

sh cp /tmp/E3_ping_h2.txt results/raw/E3_ping_h2.txt
sh cp /tmp/E3_h2.txt results/raw/E3_h2.txt
sh cp /tmp/E3_h3.txt results/raw/E3_h3.txt
sh cp /tmp/E3_h1_attack.txt results/raw/E3_h1_attack.txt
sh cp /tmp/E3_attack_start.txt results/raw/E3_attack_start.txt
sh cp /tmp/E3_attack_end.txt results/raw/E3_attack_end.txt
```

Verifica della detection:

```text
sh grep DROP_INSTALLED results/raw/E3_controller.csv
```

Deve esistere almeno una riga con:

```text
DROP_INSTALLED
```

---

## 11. Analisi dei dati

Disattivare il virtual environment Ryu:

```bash
deactivate 2>/dev/null || true
```

Eseguire il parser:

```bash
cd ~/ncis-project
python3 experiments/parse_results.py
```

Il parser genera:

```text
results/rtt_samples.csv
results/controller_port1.csv
results/events.csv
results/summary.csv
```

Controllo:

```bash
column -s, -t < results/summary.csv
column -s, -t < results/events.csv
```

---

## 12. Grafici

Generazione:

```bash
python3 experiments/plots.py
```

Output:

```text
results/plots/rtt_over_time.png
results/plots/goodput_summary.png
results/plots/attacker_port_rate.png
```

### `rtt_over_time.png`

Confronta E2 ed E3 usando l'inizio dell'attacco come riferimento temporale.

E1 viene rappresentato tramite la propria baseline media.

Il grafico evidenzia:

- forte aumento dell'RTT durante il DoS;
- detection e DROP in E3;
- recupero progressivo del traffico legittimo dopo la mitigazione.

### `goodput_summary.png`

Confronta:

- goodput aggregato di `h2 + h3`;
- goodput dell'attaccante effettivamente ricevuto da `h4`.

### `attacker_port_rate.png`

Mostra il rate RX misurato sulla porta `s1-eth1`, la soglia e l'istante di `DROP_INSTALLED`.

Il rate RX della porta 1 **non deve necessariamente diminuire dopo il DROP**: i pacchetti vengono prima ricevuti sulla porta fisica e conteggiati nei relativi contatori, quindi scartati dalla pipeline OpenFlow.

---

## 13. Risultati

Risultati delle esecuzioni utilizzate nel progetto:

| Scenario | RTT medio h2→h4 | RTT max | Goodput legittimo totale | Attacker goodput ricevuto da h4 |
|---|---:|---:|---:|---:|
| E1 | 0.127 ms | 3.56 ms | 4.00 Mbit/s | N/A |
| E2 | 114.947 ms | 339 ms | 3.74 Mbit/s | 2.05 Mbit/s |
| E3 | 91.341 ms | 339 ms | 4.00 Mbit/s | 0.348 Mbit/s |

In E3:

```text
detection delay ≈ 5.549 s
```

La mitigazione porta quindi:

- il goodput legittimo da **3.74 Mbit/s a 4.00 Mbit/s**;
- il traffico dell'attaccante ricevuto da `h4` da **2.05 Mbit/s a 0.348 Mbit/s**;
- una riduzione del traffico dell'attaccante ricevuto dalla vittima di circa **83%**;
- un recupero progressivo dell'RTT del traffico legittimo dopo il DROP.

L'RTT massimo rimane elevato anche in E3 perché la detection non è istantanea e la coda già accumulata sul bottleneck deve essere smaltita.

---

## 14. Interpretazione della mitigazione

Il comportamento osservato in E3 è:

```text
attacco
   ↓
congestione del bottleneck
   ↓
RTT elevato
   ↓
3 campioni sopra soglia
   ↓
DROP_INSTALLED su in_port=1
   ↓
nuovo traffico di h1 non raggiunge più h4
   ↓
svuotamento della coda
   ↓
recupero del traffico legittimo
```

Il controller utilizza statistiche **ingress** sulla porta 1.

Pertanto, dopo il DROP, `rx_bytes` può continuare ad aumentare: il DROP viene applicato nella pipeline OpenFlow dopo che il frame è già arrivato fisicamente sulla porta.

La riuscita della mitigazione va quindi valutata considerando congiuntamente:

- presenza di `DROP_INSTALLED`;
- riduzione dell'attacker goodput ricevuto da `h4`;
- recupero del goodput legittimo;
- recupero dell'RTT nel tempo.

---

## 15. Limiti

Il progetto presenta volutamente alcune semplificazioni:

- soglia statica;
- topologia nota a priori;
- porta dell'attaccante nota (`s1-eth1`);
- singolo attaccante;
- solo traffico UDP volumetrico;
- nessuna distinzione tra heavy hitter legittimo e attaccante;
- nessuna classificazione avanzata;
- nessun machine learning;
- nessun meccanismo distribuito per DDoS;
- mitigazione coarse-grained: viene bloccato tutto il traffico proveniente da `in_port=1`;
- il threshold è calibrato sullo specifico scenario sperimentale.

Il sistema deve quindi essere considerato un **proof of concept didattico**, non un IDS/IPS general-purpose.

---

## 16. Struttura della repository

```text
ncis-project/
├── controller/
│   └── dos_controller.py
├── topology/
│   └── simple_dos_topo.py
├── traffic/
│   └── mark_event.sh
├── experiments/
│   ├── parse_results.py
│   └── plots.py
├── results/
│   ├── raw/
│   ├── plots/
│   │   ├── rtt_over_time.png
│   │   ├── goodput_summary.png
│   │   └── attacker_port_rate.png
│   ├── rtt_samples.csv
│   ├── controller_port1.csv
│   ├── events.csv
│   └── summary.csv
├── requirements-lock.txt
└── README.md
```

---

## 17. Sequenza operativa raccomandata

### Inizio test

Terminale 1:

```bash
sudo mn -c
cd ~/ncis-project
source ~/ryuenv/bin/activate
ryu-manager ...
```

Terminale 2:

```bash
cd ~/ncis-project
sudo python3 topology/simple_dos_topo.py
```

### Fine test

Dentro Mininet:

```text
exit
```

Nel terminale Ryu:

```text
Ctrl+C
```

Poi:

```bash
sudo mn -c
```

**Non eseguire `sudo mn -c` mentre Ryu deve rimanere attivo.**
