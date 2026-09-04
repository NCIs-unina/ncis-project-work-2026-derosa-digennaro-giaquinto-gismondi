#!/usr/bin/env python3
"""
Controller DoS - Fase M1: refactor modulare a comportamento invariato.

La logica resta identica alla baseline:
- polling PortStats ogni 2 s;
- monitoraggio della sola porta 1;
- soglia statica 1.5 Mbit/s;
- 3 campioni consecutivi sopra soglia;
- DROP dell'intera in_port;
- hard_timeout di 20 s;
- stesso schema CSV.
"""

import csv
import os
import time
from pathlib import Path

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub


class TrafficMonitor:
    def __init__(self, monitored_ports):
        self.monitored_ports = set(monitored_ports)
        self.previous_stats = {}

    def is_monitored(self, port):
        return port in self.monitored_ports

    def request_port_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        request = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(request)

    def calculate_rate_mbps(self, key, rx_bytes, now_monotonic):
        previous = self.previous_stats.get(key)
        self.previous_stats[key] = (rx_bytes, now_monotonic)

        if previous is None:
            return None

        previous_bytes, previous_time = previous
        delta_bytes = rx_bytes - previous_bytes
        delta_time = now_monotonic - previous_time

        if delta_bytes < 0 or delta_time <= 0:
            return None

        return delta_bytes * 8.0 / delta_time / 1_000_000.0


class Detector:
    def __init__(self, threshold_mbps, required_hits):
        self.threshold_mbps = threshold_mbps
        self.required_hits = required_hits
        self.threshold_hits = {}

    def observe(self, key, rx_mbps):
        if rx_mbps > self.threshold_mbps:
            self.threshold_hits[key] = self.threshold_hits.get(key, 0) + 1
        else:
            self.threshold_hits[key] = 0

        return self.threshold_hits[key] >= self.required_hits

    def reset(self, key):
        self.threshold_hits[key] = 0

    def get_hits(self, key):
        return self.threshold_hits.get(key, 0)


class Blocklist:
    def __init__(self):
        self.blocked_until = {}

    def is_blocked(self, key, now_monotonic):
        return now_monotonic < self.blocked_until.get(key, 0)

    def block_for(self, key, seconds, now_monotonic):
        self.blocked_until[key] = now_monotonic + seconds


class Mitigator:
    def __init__(self, logger):
        self.logger = logger

    def install_drop(self, datapath, port, block_seconds):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=port)

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=[],
            hard_timeout=block_seconds,
        )

        datapath.send_msg(mod)

        self.logger.warning(
            "ATTACK DETECTED: dpid=%s port=%d -> DROP for %d seconds",
            datapath.id,
            port,
            block_seconds,
        )


class StatsLogger:
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

        self.log_path = log_dir / f"{run_id}_controller.csv"

        if not self.log_path.exists():
            with self.log_path.open("w", newline="") as f:
                csv.writer(f).writerow(self.HEADER)

    def write(self, timestamp, dpid, port, rx_mbps, hits, blocked, action):
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
    MONITORED_PORTS = {1}

    def __init__(self, *args, **kwargs):
        super(DosController, self).__init__(*args, **kwargs)

        self.datapaths = {}

        self.monitor = TrafficMonitor(self.MONITORED_PORTS)
        self.detector = Detector(self.THRESHOLD_MBPS, self.REQUIRED_HITS)
        self.blocklist = Blocklist()
        self.mitigator = Mitigator(self.logger)

        run_id = os.environ.get("RUN_ID", "manual")
        self.stats_logger = StatsLogger(run_id)
        self.log_path = self.stats_logger.log_path

        self.monitor_thread = hub.spawn(self._monitor)

        self.logger.info(
            "DoS controller started: threshold=%.1f Mbps, required_hits=%d, block=%ds",
            self.THRESHOLD_MBPS,
            self.REQUIRED_HITS,
            self.BLOCK_SECONDS,
        )

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
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

    def _monitor(self):
        while True:
            for datapath in list(self.datapaths.values()):
                self.monitor.request_port_stats(datapath)
            hub.sleep(self.POLL_INTERVAL)

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

            rx_mbps = self.monitor.calculate_rate_mbps(
                key,
                stat.rx_bytes,
                now_monotonic,
            )

            if rx_mbps is None:
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

        blocked = self.blocklist.is_blocked(key, now_monotonic)
        action = ""

        if blocked:
            self.detector.reset(key)
            action = "BLOCK_ACTIVE"

        else:
            attack_detected = self.detector.observe(key, rx_mbps)

            if attack_detected:
                self.mitigator.install_drop(
                    datapath,
                    port,
                    self.BLOCK_SECONDS,
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
            "PORT dpid=%s port=%d rate=%.2f Mbps hits=%d blocked=%s action=%s",
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
