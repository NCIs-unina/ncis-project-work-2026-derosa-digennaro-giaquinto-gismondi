#!/usr/bin/env python3

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


class DosController(simple_switch_13.SimpleSwitch13):

    # Detection parameters.
    POLL_INTERVAL = 2
    THRESHOLD_MBPS = 8.0
    REQUIRED_HITS = 3

    # Mitigation duration.
    BLOCK_SECONDS = 60

    # Only ingress ports connected to clients are monitored.
    # Port 4 is the victim-facing port and is deliberately ignored.
    MONITORED_PORTS = {1, 2, 3}

    def __init__(self, *args, **kwargs):
        super(DosController, self).__init__(*args, **kwargs)

        # Connected OpenFlow switches.
        self.datapaths = {}

        # (dpid, port) -> (previous_rx_bytes, timestamp)
        self.previous_stats = {}

        # Consecutive samples above threshold.
        self.threshold_hits = {}

        # (dpid, port) -> monotonic time at which blocking ends.
        self.blocked_until = {}

        # CSV log.
        project_root = Path(__file__).resolve().parents[1]
        log_dir = project_root / "results" / "raw"
        log_dir.mkdir(parents=True, exist_ok=True)

        run_id = os.environ.get("RUN_ID", "manual")
        self.log_path = log_dir / f"{run_id}_controller.csv"

        if not self.log_path.exists():
            with self.log_path.open("w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",
                    "dpid",
                    "port",
                    "rx_mbps",
                    "hits",
                    "blocked",
                    "action",
                ])

        # Start periodic monitoring.
        self.monitor_thread = hub.spawn(self._monitor)

        self.logger.info(
            "DoS controller started: threshold=%.1f Mbps, "
            "required_hits=%d, block=%ds",
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

    def _monitor(self):
        while True:
            for datapath in list(self.datapaths.values()):
                self._request_port_stats(datapath)

            hub.sleep(self.POLL_INTERVAL)

    def _request_port_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        request = parser.OFPPortStatsRequest(
            datapath,
            0,
            ofproto.OFPP_ANY,
        )

        datapath.send_msg(request)

    @set_ev_cls(
        ofp_event.EventOFPPortStatsReply,
        MAIN_DISPATCHER,
    )
    def _port_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id

        now_monotonic = time.monotonic()
        now_epoch = time.time()

        for stat in ev.msg.body:
            port = int(stat.port_no)

            if port not in self.MONITORED_PORTS:
                continue

            key = (dpid, port)

            previous = self.previous_stats.get(key)

            # Always save the newest cumulative counter.
            self.previous_stats[key] = (
                stat.rx_bytes,
                now_monotonic,
            )

            # First sample cannot produce a rate.
            if previous is None:
                continue

            previous_bytes, previous_time = previous

            delta_bytes = stat.rx_bytes - previous_bytes
            delta_time = now_monotonic - previous_time

            if delta_bytes < 0 or delta_time <= 0:
                continue

            rx_mbps = (
                delta_bytes * 8.0 / delta_time / 1_000_000.0
            )

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

        block_end = self.blocked_until.get(key, 0)
        blocked = now_monotonic < block_end

        action = ""

        if blocked:
            self.threshold_hits[key] = 0
            action = "BLOCK_ACTIVE"

        else:
            if rx_mbps > self.THRESHOLD_MBPS:
                hits = self.threshold_hits.get(key, 0) + 1
                self.threshold_hits[key] = hits
            else:
                self.threshold_hits[key] = 0

            if self.threshold_hits[key] >= self.REQUIRED_HITS:
                self._install_drop(datapath, port)

                self.blocked_until[key] = (
                    now_monotonic + self.BLOCK_SECONDS
                )

                self.threshold_hits[key] = 0
                blocked = True
                action = "DROP_INSTALLED"

        hits = self.threshold_hits.get(key, 0)

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

        with self.log_path.open("a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                f"{timestamp:.6f}",
                datapath.id,
                port,
                f"{rx_mbps:.3f}",
                hits,
                int(blocked),
                action,
            ])

    def _install_drop(self, datapath, port):
        parser = datapath.ofproto_parser

        # Everything entering from this port is dropped.
        match = parser.OFPMatch(in_port=port)

        # A FlowMod with no instructions drops matching packets.
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=[],
            hard_timeout=self.BLOCK_SECONDS,
        )

        datapath.send_msg(mod)

        self.logger.warning(
            "ATTACK DETECTED: dpid=%s port=%d -> "
            "DROP for %d seconds",
            datapath.id,
            port,
            self.BLOCK_SECONDS,
        )
