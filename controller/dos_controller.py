#!/usr/bin/env python3
"""
Controller DoS - Fase M2: mitigazione mirata per risolvere l'over-blocking.

M1 resta invariata per:
- polling PortStats ogni 2 s;
- soglia statica 1.5 Mbit/s;
- 3 campioni consecutivi sopra soglia;
- hard_timeout 20 s;
- schema CSV.

M2 aggiunge:
- raccolta del rate su tutte le porte fisiche;
- SourceTracker: associa le sorgenti IP/MAC osservate alle porte;
- SourceSelector: quando l'uplink monitorato supera la soglia, individua
  la sorgente con il rate di ingresso più alto su una porta host-facing;
- Mitigator: installa su s1 un DROP mirato a ipv4_src, non all'intera porta.

Nessuna soglia adattiva, blocklist esterna o unblock intelligente:
queste appartengono alle fasi successive.
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
from ryu.lib.packet import packet, ethernet, arp, ipv4


class TrafficMonitor:
    """Calcola il rate RX delle porte fisiche e conserva l'ultimo rate."""

    def __init__(self, monitored_ports):
        self.monitored_ports = set(monitored_ports)
        self.previous_stats = {}
        self.latest_rates = {}

    def is_detection_port(self, port):
        return port in self.monitored_ports

    def request_port_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        request = parser.OFPPortStatsRequest(
            datapath,
            0,
            ofproto.OFPP_ANY,
        )
        datapath.send_msg(request)

    def calculate_rate_mbps(self, key, rx_bytes, now_monotonic):
        previous = self.previous_stats.get(key)
        self.previous_stats[key] = (
            rx_bytes,
            now_monotonic,
        )

        if previous is None:
            return None

        previous_bytes, previous_time = previous
        delta_bytes = rx_bytes - previous_bytes
        delta_time = now_monotonic - previous_time

        if delta_bytes < 0 or delta_time <= 0:
            return None

        rx_mbps = (
            delta_bytes * 8.0 / delta_time / 1_000_000.0
        )
        self.latest_rates[key] = rx_mbps
        return rx_mbps

    def get_rate(self, key):
        return self.latest_rates.get(key)


class Detector:
    """Stessa detection di M1: soglia statica + hit consecutivi."""

    def __init__(self, threshold_mbps, required_hits):
        self.threshold_mbps = threshold_mbps
        self.required_hits = required_hits
        self.threshold_hits = {}

    def observe(self, key, rx_mbps):
        if rx_mbps > self.threshold_mbps:
            self.threshold_hits[key] = (
                self.threshold_hits.get(key, 0) + 1
            )
        else:
            self.threshold_hits[key] = 0

        return (
            self.threshold_hits[key] >= self.required_hits
        )

    def reset(self, key):
        self.threshold_hits[key] = 0

    def get_hits(self, key):
        return self.threshold_hits.get(key, 0)


class Blocklist:
    """Stesso stato temporaneo di M1, ancora legato alla detection key."""

    def __init__(self):
        self.blocked_until = {}

    def is_blocked(self, key, now_monotonic):
        return (
            now_monotonic
            < self.blocked_until.get(key, 0)
        )

    def block_for(self, key, seconds, now_monotonic):
        self.blocked_until[key] = (
            now_monotonic + seconds
        )


class SourceTracker:
    """
    Tiene traccia delle sorgenti osservate tramite PacketIn.

    Per ogni (dpid, in_port) conserva IP -> MAC.
    Le porte con una sola sorgente appresa sono buoni candidati host-facing.
    """

    def __init__(self):
        self.sources_by_port = {}

    def observe(self, key, src_mac, src_ip):
        if not src_ip or not src_mac:
            return

        sources = self.sources_by_port.setdefault(
            key,
            {},
        )
        sources[src_ip] = src_mac

    def single_source(self, key):
        sources = self.sources_by_port.get(key, {})

        if len(sources) != 1:
            return None

        src_ip, src_mac = next(iter(sources.items()))
        return {
            "ip": src_ip,
            "mac": src_mac,
        }


class SourceSelector:
    """
    Seleziona la sorgente più plausibile dell'attacco.

    Quando la detection avviene su un uplink aggregato, cerca tra le altre
    porte fisiche una porta con una sola sorgente appresa e sceglie quella
    con il rate RX più alto sopra la soglia.

    Nella topologia M2:
      s1-eth1 = uplink condiviso h1+h5
      s2-eth2 = h1
      s2-eth3 = h5
    """

    def __init__(self, minimum_rate_mbps):
        self.minimum_rate_mbps = minimum_rate_mbps

    def select(self, detected_key, monitor, source_tracker):
        candidates = []

        for key, rate in monitor.latest_rates.items():
            if key == detected_key:
                continue

            if rate <= self.minimum_rate_mbps:
                continue

            source = source_tracker.single_source(key)
            if source is None:
                continue

            candidates.append({
                "source_key": key,
                "rate_mbps": rate,
                "ip": source["ip"],
                "mac": source["mac"],
            })

        if not candidates:
            return None

        return max(
            candidates,
            key=lambda candidate: candidate["rate_mbps"],
        )


class Mitigator:
    """Installa un DROP IPv4 mirato alla sorgente identificata."""

    def __init__(self, logger):
        self.logger = logger

    def install_targeted_drop(
        self,
        datapath,
        ingress_port,
        ipv4_src,
        block_seconds,
        source_key,
        source_rate_mbps,
    ):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=ingress_port,
            eth_type=0x0800,
            ipv4_src=ipv4_src,
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=[],
            hard_timeout=block_seconds,
        )

        datapath.send_msg(mod)

        self.logger.warning(
            "ATTACK DETECTED: dpid=%s port=%d "
            "source=%s learned_at=(dpid=%s,port=%s) "
            "source_rate=%.2f Mbps -> TARGETED DROP for %d seconds",
            datapath.id,
            ingress_port,
            ipv4_src,
            source_key[0],
            source_key[1],
            source_rate_mbps,
            block_seconds,
        )


class StatsLogger:
    """Mantiene lo schema CSV usato nelle fasi precedenti."""

    HEADER = [
        "timestamp",
        "dpid",
        "port",
        "rx_mbps",
        "hits",
        "blocked",
        "action",
    ]

    def __init__(self, run_id):
        project_root = Path(__file__).resolve().parents[1]
        log_dir = project_root / "results" / "raw"
        log_dir.mkdir(parents=True, exist_ok=True)

        self.log_path = (
            log_dir / f"{run_id}_controller.csv"
        )

        if not self.log_path.exists():
            with self.log_path.open("w", newline="") as f:
                csv.writer(f).writerow(self.HEADER)

    def write(
        self,
        timestamp,
        dpid,
        port,
        rx_mbps,
        hits,
        blocked,
        action,
    ):
        with self.log_path.open("a", newline="") as f:
            csv.writer(f).writerow([
                f"{timestamp:.6f}",
                dpid,
                port,
                f"{rx_mbps:.3f}",
                hits,
                int(blocked),
                action,
            ])


class DosController(simple_switch_13.SimpleSwitch13):
    POLL_INTERVAL = 2
    THRESHOLD_MBPS = 1.5
    REQUIRED_HITS = 3
    BLOCK_SECONDS = 20

    # Detection ancora sulla porta numero 1.
    # Nella topologia M2 s2 non usa la porta 1, quindi la detection
    # avviene sull'uplink condiviso s1-eth1.
    MONITORED_PORTS = {1}

    def __init__(self, *args, **kwargs):
        super(DosController, self).__init__(
            *args,
            **kwargs,
        )

        self.datapaths = {}

        self.monitor = TrafficMonitor(
            self.MONITORED_PORTS
        )
        self.detector = Detector(
            self.THRESHOLD_MBPS,
            self.REQUIRED_HITS,
        )
        self.blocklist = Blocklist()
        self.source_tracker = SourceTracker()
        self.source_selector = SourceSelector(
            self.THRESHOLD_MBPS
        )
        self.mitigator = Mitigator(self.logger)

        run_id = os.environ.get(
            "RUN_ID",
            "manual",
        )
        self.stats_logger = StatsLogger(run_id)
        self.log_path = self.stats_logger.log_path

        self.monitor_thread = hub.spawn(
            self._monitor
        )

        self.logger.info(
            "DoS controller started: threshold=%.1f Mbps, "
            "required_hits=%d, block=%ds, mitigation=targeted-ipv4-src",
            self.THRESHOLD_MBPS,
            self.REQUIRED_HITS,
            self.BLOCK_SECONDS,
        )

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER],
    )
    def _state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info(
                    "Registered datapath %016x",
                    datapath.id,
                )

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info(
                    "Unregistered datapath %016x",
                    datapath.id,
                )

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER,
    )
    def _packet_in_handler(self, ev):
        # Mantiene il comportamento learning-switch di Ryu.
        super(DosController, self)._packet_in_handler(ev)

        msg = ev.msg
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(
            ethernet.ethernet
        )
        arp_pkt = pkt.get_protocol(
            arp.arp
        )
        ipv4_pkt = pkt.get_protocol(
            ipv4.ipv4
        )

        if eth_pkt is None:
            return

        src_ip = None

        if ipv4_pkt is not None:
            src_ip = ipv4_pkt.src
        elif arp_pkt is not None:
            src_ip = arp_pkt.src_ip

        if src_ip is not None:
            self.source_tracker.observe(
                (msg.datapath.id, in_port),
                eth_pkt.src,
                src_ip,
            )

    def _monitor(self):
        while True:
            for datapath in list(
                self.datapaths.values()
            ):
                self.monitor.request_port_stats(
                    datapath
                )

            hub.sleep(self.POLL_INTERVAL)

    @set_ev_cls(
        ofp_event.EventOFPPortStatsReply,
        MAIN_DISPATCHER,
    )
    def _port_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        now_monotonic = time.monotonic()
        now_epoch = time.time()

        for stat in ev.msg.body:
            port = int(stat.port_no)

            # Ignora porte OpenFlow riservate (LOCAL, CONTROLLER, ecc.).
            if port >= ofproto.OFPP_MAX:
                continue

            key = (dpid, port)

            rx_mbps = (
                self.monitor.calculate_rate_mbps(
                    key,
                    stat.rx_bytes,
                    now_monotonic,
                )
            )

            if rx_mbps is None:
                continue

            # Il rate viene calcolato per tutte le porte fisiche,
            # ma la detection scatta solo sulle porte monitorate.
            if not self.monitor.is_detection_port(port):
                continue

            self._process_rate(
                datapath=datapath,
                port=port,
                rx_mbps=rx_mbps,
                timestamp=now_epoch,
                now_monotonic=now_monotonic,
            )

    def _process_rate(
        self,
        datapath,
        port,
        rx_mbps,
        timestamp,
        now_monotonic,
    ):
        key = (datapath.id, port)

        blocked = self.blocklist.is_blocked(
            key,
            now_monotonic,
        )
        action = ""

        if blocked:
            self.detector.reset(key)
            action = "BLOCK_ACTIVE"

        else:
            attack_detected = self.detector.observe(
                key,
                rx_mbps,
            )

            if attack_detected:
                offender = self.source_selector.select(
                    key,
                    self.monitor,
                    self.source_tracker,
                )

                if offender is None:
                    # M2 NON torna al vecchio DROP dell'intera porta:
                    # se non sappiamo chi è la sorgente, non over-blockiamo.
                    self.detector.reset(key)
                    action = "TARGET_NOT_FOUND"

                    self.logger.warning(
                        "Attack-like rate on dpid=%s port=%d, "
                        "but no unique high-rate source was identified; "
                        "no broad DROP installed",
                        datapath.id,
                        port,
                    )

                else:
                    self.mitigator.install_targeted_drop(
                        datapath=datapath,
                        ingress_port=port,
                        ipv4_src=offender["ip"],
                        block_seconds=self.BLOCK_SECONDS,
                        source_key=offender["source_key"],
                        source_rate_mbps=offender["rate_mbps"],
                    )

                    self.blocklist.block_for(
                        key,
                        self.BLOCK_SECONDS,
                        now_monotonic,
                    )

                    self.detector.reset(key)
                    blocked = True
                    action = "DROP_INSTALLED"

        hits = self.detector.get_hits(key)

        self.logger.info(
            "PORT dpid=%s port=%d rate=%.2f Mbps "
            "hits=%d blocked=%s action=%s",
            datapath.id,
            port,
            rx_mbps,
            hits,
            blocked,
            action or "-",
        )

        self.stats_logger.write(
            timestamp,
            datapath.id,
            port,
            rx_mbps,
            hits,
            blocked,
            action,
        )
