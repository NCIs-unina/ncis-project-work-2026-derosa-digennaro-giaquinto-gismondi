#!/usr/bin/env python3

from pathlib import Path
import re
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "results" / "raw"
OUT = ROOT / "results"

SCENARIOS = {
    "E1": ("E1_ping_h2.txt", "E1_h2.txt", "E1_h3.txt", None),
    "E2": ("E2_ping_h2.txt", "E2_h2.txt", "E2_h3.txt", "E2_h1_attack.txt"),
    "E3": ("E3_ping_h2.txt", "E3_h2.txt", "E3_h3.txt", "E3_h1_attack.txt"),
}

PING_RE = re.compile(
    r"^\[(\d+(?:\.\d+)?)\].*?time[=<](\d+(?:\.\d+)?)\s*ms"
)

IPERF_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s+([KMG]?bits/sec).*?"
    r"(\d+)/(\d+)\s+\((\d+(?:\.\d+)?)%\)\s+"
    r"(sender|receiver)\s*$"
)


def require(path):
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")


def to_mbps(value, unit):
    value = float(value)
    if unit == "Kbits/sec":
        return value / 1000.0
    if unit == "Mbits/sec":
        return value
    if unit == "Gbits/sec":
        return value * 1000.0
    raise ValueError(f"Unsupported unit: {unit}")


def parse_ping(filename, scenario):
    path = RAW / filename
    require(path)
    rows = []

    for line in path.read_text().splitlines():
        m = PING_RE.search(line)
        if m:
            rows.append({
                "scenario": scenario,
                "timestamp": float(m.group(1)),
                "rtt_ms": float(m.group(2)),
            })

    if not rows:
        raise RuntimeError(f"No timestamped ping samples in {path}")

    df = pd.DataFrame(rows)
    df["sample_time_s"] = df["timestamp"] - df["timestamp"].iloc[0]
    return df


def parse_iperf(filename, role="receiver"):
    path = RAW / filename
    require(path)
    found = []

    for line in path.read_text().splitlines():
        m = IPERF_RE.search(line)
        if m and m.group(6) == role:
            found.append(m)

    if not found:
        raise RuntimeError(f"No {role} summary in {path}")

    m = found[-1]
    return {
        "mbps": to_mbps(m.group(1), m.group(2)),
        "lost": int(m.group(3)),
        "total": int(m.group(4)),
        "loss_pct": float(m.group(5)),
    }


# ------------------------------------------------------------
# Raw ping samples
# ------------------------------------------------------------

ping = {}
for scenario, (ping_file, _, _, _) in SCENARIOS.items():
    ping[scenario] = parse_ping(ping_file, scenario)

e2_start = float((RAW / "E2_attack_start.txt").read_text().strip())
e2_end = e2_start + 15.0  # canonical: configured attack duration

e3_start = float((RAW / "E3_attack_start.txt").read_text().strip())
e3_end = float((RAW / "E3_attack_end.txt").read_text().strip())

# Use attack-relative time for E2/E3. This avoids treating the manually
# started ping as the exact experiment t=0.
ping["E1"]["attack_relative_s"] = pd.NA
ping["E2"]["attack_relative_s"] = ping["E2"]["timestamp"] - e2_start
ping["E3"]["attack_relative_s"] = ping["E3"]["timestamp"] - e3_start

rtt = pd.concat(ping.values(), ignore_index=True)
rtt = rtt[
    ["scenario", "timestamp", "sample_time_s", "attack_relative_s", "rtt_ms"]
]
rtt.to_csv(OUT / "rtt_samples.csv", index=False)


# ------------------------------------------------------------
# Controller / detection
# ------------------------------------------------------------

controller_path = RAW / "E3_controller.csv"
require(controller_path)
controller = pd.read_csv(controller_path)
controller = controller[controller["port"] == 1].copy()

if controller.empty:
    raise RuntimeError("No port 1 samples in E3_controller.csv")

controller["attack_relative_s"] = controller["timestamp"] - e3_start

drops = controller[controller["action"] == "DROP_INSTALLED"]
if drops.empty:
    raise RuntimeError("DROP_INSTALLED not found in E3_controller.csv")

drop_timestamp = float(drops.iloc[0]["timestamp"])
detection_delay_s = drop_timestamp - e3_start

controller[
    ["attack_relative_s", "timestamp", "dpid", "port", "rx_mbps",
     "hits", "blocked", "action"]
].to_csv(OUT / "controller_port1.csv", index=False)


# ------------------------------------------------------------
# Events: all times relative to attack start
# ------------------------------------------------------------

events = pd.DataFrame([
    ["E2", "attack_start", e2_start, 0.0],
    ["E2", "attack_end", e2_end, 15.0],
    ["E3", "attack_start", e3_start, 0.0],
    ["E3", "drop_installed", drop_timestamp, detection_delay_s],
    ["E3", "attack_end", e3_end, e3_end - e3_start],
], columns=["scenario", "event", "timestamp", "attack_relative_s"])

events.to_csv(OUT / "events.csv", index=False)


# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

summary = []

for scenario, (_, h2_file, h3_file, attacker_file) in SCENARIOS.items():
    h2 = parse_iperf(h2_file)
    h3 = parse_iperf(h3_file)
    p = ping[scenario]

    attacker_mbps = None
    attacker_loss = None

    if attacker_file:
        attacker = parse_iperf(attacker_file)
        attacker_mbps = attacker["mbps"]
        attacker_loss = attacker["loss_pct"]

    summary.append({
        "scenario": scenario,
        "ping_samples": len(p),
        "rtt_avg_ms": p["rtt_ms"].mean(),
        "rtt_max_ms": p["rtt_ms"].max(),
        "h2_receiver_mbps": h2["mbps"],
        "h3_receiver_mbps": h3["mbps"],
        "legit_total_mbps": h2["mbps"] + h3["mbps"],
        "h2_loss_pct": h2["loss_pct"],
        "h3_loss_pct": h3["loss_pct"],
        "attacker_receiver_mbps": attacker_mbps,
        "attacker_loss_pct": attacker_loss,
        "attack_duration_s": (
            None if scenario == "E1"
            else 15.0 if scenario == "E2"
            else e3_end - e3_start
        ),
        "detection_delay_s": (
            detection_delay_s if scenario == "E3" else None
        ),
    })

summary = pd.DataFrame(summary)
summary.to_csv(OUT / "summary.csv", index=False, float_format="%.6f")


# ------------------------------------------------------------
# Console output
# ------------------------------------------------------------

print("\nParsed experiments:\n")
for _, row in summary.iterrows():
    msg = (
        f"{row['scenario']}: ping={int(row['ping_samples'])} | "
        f"RTT avg={row['rtt_avg_ms']:.3f} ms | "
        f"RTT max={row['rtt_max_ms']:.3f} ms | "
        f"legit={row['legit_total_mbps']:.3f} Mbit/s"
    )
    if pd.notna(row["attacker_receiver_mbps"]):
        msg += f" | attacker_rx={row['attacker_receiver_mbps']:.3f} Mbit/s"
    print(msg)

print(f"\nE3 detection delay: {detection_delay_s:.3f} s")
print(f"E3 attack duration: {e3_end - e3_start:.3f} s")
print("\nWrote:")
print(" results/rtt_samples.csv")
print(" results/controller_port1.csv")
print(" results/events.csv")
print(" results/summary.csv")
