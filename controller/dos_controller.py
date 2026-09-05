#!/usr/bin/env python3
"""
Controller DoS - Fase M3: soglia adattiva con training benigno + EWMA.

Evoluzione di M2:
- mitigazione mirata per ipv4_src invariata;
- niente threshold fisso come unico criterio di decisione;
- ogni porta di detection costruisce una baseline da campioni di traffico attivo;
- dopo il training, la baseline viene aggiornata con EWMA solo sui campioni
  classificati come normali;
- se un campione supera la soglia adattiva, la baseline viene congelata:
  l'attacco non puo' trascinare verso l'alto la soglia.

Formula:
    baseline_t = alpha * rate_t + (1-alpha) * baseline_(t-1)

    threshold_t = max(MIN_THRESHOLD_MBPS,
                      THRESHOLD_MULTIPLIER * baseline_t)

Parametri M3:
- POLL_INTERVAL = 2 s
- REQUIRED_HITS = 3
- BLOCK_SECONDS = 20 s
- TRAINING_SAMPLES = 5 campioni attivi
- TRAINING_MIN_MBPS = 0.1 Mbit/s
- EWMA_ALPHA = 0.2
- THRESHOLD_MULTIPLIER = 1.5
- MIN_THRESHOLD_MBPS = 1.5 Mbit/s
"""

import csv
import os
import time
from pathlib import Path

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, arp, ipv4


class TrafficMonitor:
    def __init__(self, monitored_ports):
        self.monitored_ports = set(monitored_ports)
        self.previous_stats = {}
        self.latest_rates = {}

    def is_detection_port(self, port):
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

        rx_mbps = delta_bytes * 8.0 / delta_time / 1_000_000.0
        self.latest_rates[key] = rx_mbps
        return rx_mbps


class AdaptiveDetector:
    def __init__(
        self,
        required_hits,
        min_threshold_mbps,
        threshold_multiplier,
        ewma_alpha,
        training_samples,
        training_min_mbps,
    ):
        self.required_hits = required_hits
        self.min_threshold_mbps = min_threshold_mbps
        self.threshold_multiplier = threshold_multiplier
        self.ewma_alpha = ewma_alpha
        self.training_samples = training_samples
        self.training_min_mbps = training_min_mbps

        self._training_values = {}
        self._baseline = {}
        self._trained = set()
        self._hits = {}

    def is_trained(self, key):
        return key in self._trained

    def training_count(self, key):
        return len(self._training_values.get(key, []))

    def baseline(self, key):
        return self._baseline.get(key)

    def threshold(self, key):
        baseline = self.baseline(key)
        if baseline is None:
            return self.min_threshold_mbps

        return max(
            self.min_threshold_mbps,
            self.threshold_multiplier * baseline,
        )

    def get_hits(self, key):
        return self._hits.get(key, 0)

    def reset_hits(self, key):
        self._hits[key] = 0

    def observe(self, key, rx_mbps):
        if not self.is_trained(key):
            self._hits[key] = 0

            if rx_mbps >= self.training_min_mbps:
                values = self._training_values.setdefault(key, [])
                values.append(rx_mbps)
                self._baseline[key] = sum(values) / len(values)

                if len(values) >= self.training_samples:
                    self._trained.add(key)

            return {
                "attack": False,
                "trained": self.is_trained(key),
                "training_count": self.training_count(key),
                "baseline_mbps": self.baseline(key),
                "threshold_mbps": self.threshold(key),
                "hits": 0,
            }

        current_threshold = self.threshold(key)

        if rx_mbps > current_threshold:
            self._hits[key] = self._hits.get(key, 0) + 1
        else:
            self._hits[key] = 0

            # I campioni idle/quasi-zero non cancellano la baseline
            # benigna appresa durante il training.
            if rx_mbps >= self.training_min_mbps:
                old_baseline = self._baseline[key]
                self._baseline[key] = (
                    self.ewma_alpha * rx_mbps
                    + (1.0 - self.ewma_alpha) * old_baseline
                )

        return {
            "attack": self._hits.get(key, 0) >= self.required_hits,
            "trained": True,
            "training_count": self.training_count(key),
            "baseline_mbps": self.baseline(key),
            "threshold_mbps": self.threshold(key),
            "hits": self.get_hits(key),
        }


class Blocklist:
    def __init__(self):
        self.blocked_until = {}

    def is_blocked(self, key, now_monotonic):
        return now_monotonic < self.blocked_until.get(key, 0)

    def block_for(self, key, seconds, now_monotonic):
        self.blocked_until[key] = now_monotonic + seconds


class SourceTracker:
    def __init__(self):
        self.sources_by_port = {}

    def observe(self, key, src_mac, src_ip):
        if not src_ip or not src_mac:
            return

        sources = self.sources_by_port.setdefault(key, {})
        sources[src_ip] = src_mac

    def single_source(self, key):
        sources = self.sources_by_port.get(key, {})
        if len(sources) != 1:
            return None

        src_ip, src_mac = next(iter(sources.items()))
        return {"ip": src_ip, "mac": src_mac}


class SourceSelector:
    def select(
        self,
        detected_key,
        monitor,
        source_tracker,
        minimum_rate_mbps,
    ):
        candidates = []

        for key, rate in monitor.latest_rates.items():
            if key == detected_key:
                continue

            if rate <= minimum_rate_mbps:
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

        return max(candidates, key=lambda candidate: candidate["rate_mbps"])


class Mitigator:
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
    HEADER = [
        "timestamp",
        "dpid",
        "port",
        "rx_mbps",
        "hits",
        "blocked",
        "action",
        "baseline_mbps",
        "threshold_mbps",
        "training_count",
        "trained",
    ]

    def __init__(self, run_id):
        project_root = Path(__file__).resolve().parents[1]
        log_dir = project_root / "results" / "raw"
        log_dir.mkdir(parents=True, exist_ok=True)

        self.log_path = log_dir / f"{run_id}_controller.csv"

        if not self.log_path.exists():
            with self.log_path.open("w", newline="") as f:
                csv.writer(f).writerow(self.HEADER)

    @staticmethod
    def _fmt_optional(value):
        if value is None:
            return ""
        return f"{value:.3f}"

    def write(
        self,
        timestamp,
        dpid,
        port,
        rx_mbps,
        hits,
        blocked,
        action,
        baseline_mbps,
        threshold_mbps,
        training_count,
        trained,
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
                self._fmt_optional(baseline_mbps),
                self._fmt_optional(threshold_mbps),
                training_count,
                int(trained),
            ])


class DosController(simple_switch_13.SimpleSwitch13):
    POLL_INTERVAL = 2

    MIN_THRESHOLD_MBPS = 1.5
    THRESHOLD_MULTIPLIER = 1.5
    EWMA_ALPHA = 0.2
    TRAINING_SAMPLES = 5
    TRAINING_MIN_MBPS = 0.1

    REQUIRED_HITS = 3
    BLOCK_SECONDS = 20
    MONITORED_PORTS = {1}

    def __init__(self, *args, **kwargs):
        super(DosController, self).__init__(*args, **kwargs)

        self.datapaths = {}

        self.monitor = TrafficMonitor(self.MONITORED_PORTS)

        self.detector = AdaptiveDetector(
            required_hits=self.REQUIRED_HITS,
            min_threshold_mbps=self.MIN_THRESHOLD_MBPS,
            threshold_multiplier=self.THRESHOLD_MULTIPLIER,
            ewma_alpha=self.EWMA_ALPHA,
            training_samples=self.TRAINING_SAMPLES,
            training_min_mbps=self.TRAINING_MIN_MBPS,
        )

        self.blocklist = Blocklist()
        self.source_tracker = SourceTracker()
        self.source_selector = SourceSelector()
        self.mitigator = Mitigator(self.logger)

        run_id = os.environ.get("RUN_ID", "manual")
        self.stats_logger = StatsLogger(run_id)
        self.log_path = self.stats_logger.log_path

        self.monitor_thread = hub.spawn(self._monitor)

        self.logger.info(
            "DoS controller started: adaptive threshold, "
            "min=%.1f Mbps, multiplier=%.2f, alpha=%.2f, "
            "training=%d active samples, required_hits=%d, block=%ds",
            self.MIN_THRESHOLD_MBPS,
            self.THRESHOLD_MULTIPLIER,
            self.EWMA_ALPHA,
            self.TRAINING_SAMPLES,
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
                self.logger.info("Registered datapath %016x", datapath.id)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info("Unregistered datapath %016x", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        super(DosController, self)._packet_in_handler(ev)

        msg = ev.msg
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

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
            for datapath in list(self.datapaths.values()):
                self.monitor.request_port_stats(datapath)

            hub.sleep(self.POLL_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        now_monotonic = time.monotonic()
        now_epoch = time.time()

        for stat in ev.msg.body:
            port = int(stat.port_no)

            if port >= ofproto.OFPP_MAX:
                continue

            key = (dpid, port)

            rx_mbps = self.monitor.calculate_rate_mbps(
                key,
                stat.rx_bytes,
                now_monotonic,
            )

            if rx_mbps is None:
                continue

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

        blocked = self.blocklist.is_blocked(key, now_monotonic)
        action = ""

        if blocked:
            self.detector.reset_hits(key)

            status = {
                "attack": False,
                "trained": self.detector.is_trained(key),
                "training_count": self.detector.training_count(key),
                "baseline_mbps": self.detector.baseline(key),
                "threshold_mbps": self.detector.threshold(key),
                "hits": 0,
            }

            action = "BLOCK_ACTIVE"

        else:
            status = self.detector.observe(key, rx_mbps)

            if status["attack"]:
                offender = self.source_selector.select(
                    detected_key=key,
                    monitor=self.monitor,
                    source_tracker=self.source_tracker,
                    minimum_rate_mbps=self.TRAINING_MIN_MBPS,
                )

                if offender is None:
                    self.detector.reset_hits(key)
                    status["hits"] = 0
                    action = "TARGET_NOT_FOUND"

                    self.logger.warning(
                        "Adaptive detector triggered on dpid=%s port=%d "
                        "but no high-rate unique source was identified; "
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

                    self.detector.reset_hits(key)
                    status["hits"] = 0
                    blocked = True
                    action = "DROP_INSTALLED"

        self.logger.info(
            "PORT dpid=%s port=%d rate=%.2f Mbps "
            "baseline=%s threshold=%.2f trained=%s "
            "training=%d/%d hits=%d blocked=%s action=%s",
            datapath.id,
            port,
            rx_mbps,
            (
                "%.2f" % status["baseline_mbps"]
                if status["baseline_mbps"] is not None
                else "-"
            ),
            status["threshold_mbps"],
            status["trained"],
            status["training_count"],
            self.TRAINING_SAMPLES,
            status["hits"],
            blocked,
            action or "-",
        )

        self.stats_logger.write(
            timestamp=timestamp,
            dpid=datapath.id,
            port=port,
            rx_mbps=rx_mbps,
            hits=status["hits"],
            blocked=blocked,
            action=action,
            baseline_mbps=status["baseline_mbps"],
            threshold_mbps=status["threshold_mbps"],
            training_count=status["training_count"],
            trained=status["trained"],
        )
