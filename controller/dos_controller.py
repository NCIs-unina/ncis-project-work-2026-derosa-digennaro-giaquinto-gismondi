#!/usr/bin/env python3
"""
DoS controller - versione modulare (Fase 1).

Il COMPORTAMENTO e' identico alla versione precedente: stessi parametri,
stessa logica di detection, stesso identico output CSV (consumato da
experiments/parse_results.py). Cambia solo l'ORGANIZZAZIONE del codice,
ora separato in componenti con responsabilita' singola:

    TrafficMonitor -> raccolta statistiche e calcolo del rate di ingresso
    Detector       -> decisione (soglia + campioni consecutivi)
    Blocklist      -> stato condiviso delle porte bloccate
    Mitigator      -> enforcement (installa la regola OpenFlow di DROP)
    StatsLogger    -> log CSV
    DosController  -> app Ryu che orchestra i componenti

Questa separazione (Fase 1, risolve la "mancanza di modularita'") e' la base
su cui si innestano i fix successivi senza toccare il resto:
DROP mirato -> Mitigator, soglia adattiva -> Detector,
blocklist verso l'esterno -> Blocklist.
"""

import csv
import os
import time
from pathlib import Path

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import packet, ipv4


# ==========================================================================
# Blocklist - stato condiviso delle porte bloccate.
# (dpid, port) -> istante monotonic in cui il blocco termina.
# Punto di estensione per la Fase 4 (blocklist condivisa verso l'esterno).
# ==========================================================================
class Blocklist:

    def __init__(self):
        self._blocked_until = {}

    def block(self, key, seconds, now):
        self._blocked_until[key] = now + seconds

    def is_blocked(self, key, now):
        return now < self._blocked_until.get(key, 0)


# ==========================================================================
# Detector - decide se una porta e' sotto attacco.
# Conta i campioni consecutivi sopra soglia; scatta a REQUIRED_HITS.
# Punto di estensione per la Fase 3 (soglia adattiva).
# ==========================================================================
class Detector:

    def __init__(self, threshold_mbps, required_hits):
        self.threshold_mbps = threshold_mbps
        self.required_hits = required_hits
        self._hits = {}

    def update(self, key, rx_mbps):
        """Aggiorna il contatore e ritorna True se e' ora di bloccare."""
        if rx_mbps > self.threshold_mbps:
            self._hits[key] = self._hits.get(key, 0) + 1
        else:
            self._hits[key] = 0
        return self._hits[key] >= self.required_hits

    def reset(self, key):
        self._hits[key] = 0

    def hits(self, key):
        return self._hits.get(key, 0)


# ==========================================================================
# TrafficMonitor - raccolta statistiche e calcolo del rate di ingresso.
# Conserva i contatori cumulativi precedenti per farne la differenza.
# ==========================================================================
class TrafficMonitor:

    def __init__(self, monitored_ports):
        self.monitored_ports = set(monitored_ports)
        # (dpid, port) -> (rx_bytes_precedenti, timestamp monotonic)
        self._previous = {}

    def is_monitored(self, port):
        return port in self.monitored_ports

    def request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def rate_mbps(self, key, rx_bytes, now):
        """Rate in Mbit/s dai byte cumulativi; None se non calcolabile."""
        previous = self._previous.get(key)

        # Salva sempre il contatore piu' recente.
        self._previous[key] = (rx_bytes, now)

        # Il primo campione non puo' produrre un rate.
        if previous is None:
            return None

        prev_bytes, prev_time = previous
        delta_bytes = rx_bytes - prev_bytes
        delta_time = now - prev_time

        if delta_bytes < 0 or delta_time <= 0:
            return None

        return delta_bytes * 8.0 / delta_time / 1_000_000.0


# ==========================================================================
# Mitigator - enforcement: installa la regola OpenFlow di DROP.
# Punto di estensione per la Fase 2 (DROP mirato per flusso/ipv4_src).
# ==========================================================================
class Mitigator:

    def __init__(self, logger):
        self.logger = logger

    def install_drop(self, datapath, port, block_seconds, ipv4_src=None):
        parser = datapath.ofproto_parser

        if ipv4_src is not None:
            # DROP mirato: solo il traffico IPv4 dell'host colpevole.
            # Gli altri host sulla stessa porta NON vengono toccati.
            match = parser.OFPMatch(
                in_port=port,
                eth_type=0x0800,        # IPv4
                ipv4_src=ipv4_src,
            )
            target = "ip_src=%s (in_port=%d)" % (ipv4_src, port)
        else:
            # Fallback: sorgente non ancora nota -> blocco l'intera porta
            # (comportamento della versione precedente).
            match = parser.OFPMatch(in_port=port)
            target = "in_port=%d" % port

        # Un FlowMod senza istruzioni scarta i pacchetti che fanno match.
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=[],
            hard_timeout=block_seconds,
        )
        datapath.send_msg(mod)

        self.logger.warning(
            "ATTACK DETECTED: dpid=%s %s -> DROP for %d seconds",
            datapath.id,
            target,
            block_seconds,
        )


# ==========================================================================
# StatsLogger - log CSV. Schema INVARIATO: e' letto da parse_results.py.
# ==========================================================================
class StatsLogger:

    HEADER = [
        "timestamp", "dpid", "port", "rx_mbps", "hits", "blocked", "action",
    ]

    def __init__(self, run_id):
        project_root = Path(__file__).resolve().parents[1]
        log_dir = project_root / "results" / "raw"
        log_dir.mkdir(parents=True, exist_ok=True)

        self.path = log_dir / f"{run_id}_controller.csv"

        if not self.path.exists():
            with self.path.open("w", newline="") as f:
                csv.writer(f).writerow(self.HEADER)

    def log(self, timestamp, dpid, port, rx_mbps, hits, blocked, action):
        with self.path.open("a", newline="") as f:
            csv.writer(f).writerow([
                f"{timestamp:.6f}",
                dpid,
                port,
                f"{rx_mbps:.3f}",
                hits,
                int(blocked),
                action,
            ])


# ==========================================================================
# HostTable - impara quale IP sorgente sta su ciascuna porta.
# Popolata dai packet-in; serve al Mitigator per il DROP mirato (Fase 2).
# ==========================================================================
class HostTable:

    def __init__(self):
        # (dpid, port) -> ultimo ipv4_src osservato su quella porta.
        self._by_port = {}

    def observe(self, key, ipv4_src):
        self._by_port[key] = ipv4_src

    def source_on(self, key):
        return self._by_port.get(key)


# ==========================================================================
# DosController - app Ryu che ORCHESTRA i componenti.
# ==========================================================================
class DosController(simple_switch_13.SimpleSwitch13):

    # Parametri di detection.
    POLL_INTERVAL = 2
    THRESHOLD_MBPS = 1.5
    REQUIRED_HITS = 3

    # Durata della mitigazione.
    BLOCK_SECONDS = 20

    # Solo le porte lato client vengono monitorate.
    # La porta 4 (lato vittima) e' volutamente ignorata.
    MONITORED_PORTS = {1}

    def __init__(self, *args, **kwargs):
        super(DosController, self).__init__(*args, **kwargs)

        # Switch OpenFlow connessi.
        self.datapaths = {}

        # Componenti, ciascuno con una responsabilita' singola.
        self.monitor = TrafficMonitor(self.MONITORED_PORTS)
        self.detector = Detector(self.THRESHOLD_MBPS, self.REQUIRED_HITS)
        self.blocklist = Blocklist()
        self.mitigator = Mitigator(self.logger)
        self.stats_log = StatsLogger(os.environ.get("RUN_ID", "manual"))
        self.hosts = HostTable()

        # Avvio del monitoraggio periodico (green thread).
        self.monitor_thread = hub.spawn(self._monitor)

        self.logger.info(
            "DoS controller started: threshold=%.1f Mbps, "
            "required_hits=%d, block=%ds",
            self.THRESHOLD_MBPS,
            self.REQUIRED_HITS,
            self.BLOCK_SECONDS,
        )

    # ---- registro dei datapath ----
    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER],
    )
    def _state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info("Registered datapath %016x", datapath.id)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info("Unregistered datapath %016x", datapath.id)

    # ---- packet-in: reachability (learning switch) + apprende gli IP ----
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # 1) comportamento del learning switch (garantisce la connettivita').
        super(DosController, self)._packet_in_handler(ev)

        # 2) in piu': registra l'IP sorgente visto su questa porta,
        #    cosi' il Mitigator puo' fare un DROP mirato sull'attaccante.
        msg = ev.msg
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is not None:
            self.hosts.observe((msg.datapath.id, in_port), ip.src)

    # ---- loop di monitoraggio periodico ----
    def _monitor(self):
        while True:
            for datapath in list(self.datapaths.values()):
                self.monitor.request_stats(datapath)
            hub.sleep(self.POLL_INTERVAL)

    # ---- ricezione delle statistiche di porta ----
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id

        now_monotonic = time.monotonic()
        now_epoch = time.time()

        for stat in ev.msg.body:
            port = int(stat.port_no)

            if not self.monitor.is_monitored(port):
                continue

            key = (dpid, port)
            rx_mbps = self.monitor.rate_mbps(key, stat.rx_bytes, now_monotonic)

            # Primo campione o valore non valido: niente da decidere.
            if rx_mbps is None:
                continue

            self._handle_rate(
                datapath, port, rx_mbps, now_epoch, now_monotonic,
            )

    # ---- orchestrazione: detection -> mitigazione -> log ----
    def _handle_rate(self, datapath, port, rx_mbps, timestamp, now_monotonic):
        key = (datapath.id, port)

        blocked = self.blocklist.is_blocked(key, now_monotonic)
        action = ""

        if blocked:
            # Blocco gia' attivo: azzera i campioni, non ridecidere.
            self.detector.reset(key)
            action = "BLOCK_ACTIVE"
        else:
            attack = self.detector.update(key, rx_mbps)
            if attack:
                ipv4_src = self.hosts.source_on(key)
                self.mitigator.install_drop(
                    datapath, port, self.BLOCK_SECONDS, ipv4_src=ipv4_src,
                )
                self.blocklist.block(key, self.BLOCK_SECONDS, now_monotonic)
                self.detector.reset(key)
                blocked = True
                action = "DROP_INSTALLED"

        hits = self.detector.hits(key)

        self.logger.info(
            "PORT dpid=%s port=%d rate=%.2f Mbps hits=%d blocked=%s action=%s",
            datapath.id,
            port,
            rx_mbps,
            hits,
            blocked,
            action or "-",
        )

        self.stats_log.log(
            timestamp, datapath.id, port, rx_mbps, hits, blocked, action,
        )
