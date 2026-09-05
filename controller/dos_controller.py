#!/usr/bin/env python3
"""
Controller DoS - Fase M4: policy esterna tramite blocklist JSON condivisa.

Evoluzione di M3:
- detector adattivo EWMA invariato;
- mitigazione automatica mirata per ipv4_src invariata;
- aggiunge una blocklist esterna modificabile da un amministratore/modulo;
- il controller rilegge periodicamente policy/blocklist.json;
- aggiunte/rimozioni vengono tradotte in FlowMod persistenti e mirati.

La policy esterna usa regole priority=110 e hard_timeout=0, distinte
dalle mitigazioni automatiche priority=100 e hard_timeout=20.

Formato del file:
{
  "blocked_ipv4": ["10.0.0.5"]
}
"""

import csv
import ipaddress
import json
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

    def find_single_source_location(self, ipv4_src):
        """
        Restituisce una porta in cui ipv4_src e' l'unica sorgente appresa.

        Nella topologia M2/M4, dopo pingall:
        - h1 -> (dpid=2, port=2)
        - h5 -> (dpid=2, port=3)
        mentre l'uplink s1-eth1 contiene piu' sorgenti e viene escluso.
        """
        candidates = []

        for key, sources in self.sources_by_port.items():
            if ipv4_src in sources and len(sources) == 1:
                candidates.append(key)

        if not candidates:
            return None

        return sorted(candidates)[0]


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

    def install_admin_drop(
        self,
        datapath,
        ingress_port,
        ipv4_src,
        priority,
    ):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=ingress_port,
            eth_type=0x0800,
            ipv4_src=ipv4_src,
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=[],
            hard_timeout=0,
            idle_timeout=0,
        )
        datapath.send_msg(mod)

        self.logger.warning(
            "POLICY ADD: source=%s -> dpid=%s port=%d "
            "persistent targeted DROP priority=%d",
            ipv4_src,
            datapath.id,
            ingress_port,
            priority,
        )

    def remove_admin_drop(
        self,
        datapath,
        ingress_port,
        ipv4_src,
        priority,
    ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=ingress_port,
            eth_type=0x0800,
            ipv4_src=ipv4_src,
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            table_id=0,
            priority=priority,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        datapath.send_msg(mod)

        self.logger.warning(
            "POLICY REMOVE: source=%s -> dpid=%s port=%d "
            "persistent DROP removed",
            ipv4_src,
            datapath.id,
            ingress_port,
        )


class ExternalBlocklist:
    """Legge una blocklist IPv4 condivisa da un file JSON."""

    def __init__(self, path, logger):
        self.path = Path(path)
        self.logger = logger

    def load(self):
        """
        Ritorna:
        - set di IPv4 quando il file e' valido;
        - None se file/formato sono temporaneamente non validi.

        None fa conservare le policy gia' installate: un salvataggio
        parziale del file non deve causare uno sblocco accidentale.
        """
        try:
            with self.path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            self.logger.error(
                "External blocklist missing: %s",
                self.path,
            )
            return None
        except (OSError, json.JSONDecodeError) as exc:
            self.logger.error(
                "Cannot read external blocklist %s: %s",
                self.path,
                exc,
            )
            return None

        raw_entries = data.get("blocked_ipv4")
        if not isinstance(raw_entries, list):
            self.logger.error(
                "Invalid blocklist: 'blocked_ipv4' must be a list"
            )
            return None

        result = set()

        for value in raw_entries:
            if not isinstance(value, str):
                self.logger.warning(
                    "Ignoring non-string blocklist entry: %r",
                    value,
                )
                continue

            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                self.logger.warning(
                    "Ignoring invalid IP in blocklist: %s",
                    value,
                )
                continue

            if address.version != 4:
                self.logger.warning(
                    "Ignoring non-IPv4 blocklist entry: %s",
                    value,
                )
                continue

            result.add(str(address))

        return result


class PolicyEnforcer:
    """
    Converte la blocklist esterna in regole OpenFlow persistenti.

    installed:
        ipv4_src -> (dpid, port)

    La regola viene installata sulla migliore porta single-source
    conosciuta dal SourceTracker, evitando il blocco indiscriminato
    di un uplink condiviso.
    """

    def __init__(self, mitigator, priority, logger):
        self.mitigator = mitigator
        self.priority = priority
        self.logger = logger
        self.installed = {}
        self._waiting_logged = set()

    def forget_datapath(self, dpid):
        stale = [
            ipv4_src
            for ipv4_src, key in self.installed.items()
            if key[0] == dpid
        ]

        for ipv4_src in stale:
            del self.installed[ipv4_src]

    def reconcile(
        self,
        desired_ipv4,
        datapaths,
        source_tracker,
    ):
        # 1) Rimuove policy che l'admin ha cancellato dal file.
        for ipv4_src in sorted(
            set(self.installed) - set(desired_ipv4)
        ):
            key = self.installed.get(ipv4_src)
            if key is None:
                continue

            dpid, port = key
            datapath = datapaths.get(dpid)

            if datapath is not None:
                self.mitigator.remove_admin_drop(
                    datapath=datapath,
                    ingress_port=port,
                    ipv4_src=ipv4_src,
                    priority=self.priority,
                )

            del self.installed[ipv4_src]
            self._waiting_logged.discard(ipv4_src)

        # 2) Installa/riconcilia le policy desiderate.
        for ipv4_src in sorted(desired_ipv4):
            location = source_tracker.find_single_source_location(
                ipv4_src
            )

            if location is None:
                if ipv4_src not in self._waiting_logged:
                    self.logger.info(
                        "POLICY WAIT: source=%s not learned on a "
                        "single-source port yet",
                        ipv4_src,
                    )
                    self._waiting_logged.add(ipv4_src)
                continue

            self._waiting_logged.discard(ipv4_src)

            old_location = self.installed.get(ipv4_src)

            if old_location == location:
                continue

            # Host spostato: rimuove prima l'eventuale vecchia regola.
            if old_location is not None:
                old_dpid, old_port = old_location
                old_datapath = datapaths.get(old_dpid)

                if old_datapath is not None:
                    self.mitigator.remove_admin_drop(
                        datapath=old_datapath,
                        ingress_port=old_port,
                        ipv4_src=ipv4_src,
                        priority=self.priority,
                    )

                del self.installed[ipv4_src]

            dpid, port = location
            datapath = datapaths.get(dpid)

            if datapath is None:
                continue

            self.mitigator.install_admin_drop(
                datapath=datapath,
                ingress_port=port,
                ipv4_src=ipv4_src,
                priority=self.priority,
            )

            self.installed[ipv4_src] = location


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
    POLICY_POLL_INTERVAL = 1
    ADMIN_PRIORITY = 110

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

        project_root = Path(__file__).resolve().parents[1]
        blocklist_path = os.environ.get(
            "BLOCKLIST_FILE",
            str(project_root / "policy" / "blocklist.json"),
        )

        self.external_blocklist = ExternalBlocklist(
            blocklist_path,
            self.logger,
        )
        self.policy_enforcer = PolicyEnforcer(
            mitigator=self.mitigator,
            priority=self.ADMIN_PRIORITY,
            logger=self.logger,
        )

        run_id = os.environ.get("RUN_ID", "manual")
        self.stats_logger = StatsLogger(run_id)
        self.log_path = self.stats_logger.log_path

        self.monitor_thread = hub.spawn(self._monitor)
        self.policy_thread = hub.spawn(self._policy_loop)

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

        self.logger.info(
            "External blocklist enabled: file=%s, poll=%ds, "
            "admin_priority=%d",
            self.external_blocklist.path,
            self.POLICY_POLL_INTERVAL,
            self.ADMIN_PRIORITY,
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
                self.policy_enforcer.forget_datapath(
                    datapath.id
                )
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

    def _policy_loop(self):
        while True:
            desired_ipv4 = self.external_blocklist.load()

            if desired_ipv4 is not None:
                self.policy_enforcer.reconcile(
                    desired_ipv4=desired_ipv4,
                    datapaths=self.datapaths,
                    source_tracker=self.source_tracker,
                )

            hub.sleep(self.POLICY_POLL_INTERVAL)

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
