#!/usr/bin/env python3
from pathlib import Path
import csv
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "results" / "final" / "raw"
OUT = ROOT / "results" / "final" / "plots"
SUMMARY = ROOT / "results" / "final" / "summary.csv"

OUT.mkdir(parents=True, exist_ok=True)


def load_controller(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_summary():
    with SUMMARY.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def numeric_metric(rows, scenario, metric, subject=None):
    matches = [
        r for r in rows
        if r["scenario"] == scenario
        and r["metric"] == metric
        and (subject is None or r["subject"] == subject)
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected one row for scenario={scenario}, "
            f"metric={metric}, subject={subject}; got {len(matches)}"
        )
    return float(matches[0]["value"])


summary = load_summary()

# ------------------------------------------------------------------
# FINAL-A: adaptive detection
# ------------------------------------------------------------------
a = load_controller(RAW / "FINAL_A_controller.csv")
a = [r for r in a if r["dpid"] == "1" and r["port"] == "1"]

t0 = float(a[0]["timestamp"])
times = [float(r["timestamp"]) - t0 for r in a]
rates = [float(r["rx_mbps"]) for r in a]
baselines = [
    float(r["baseline_mbps"]) if r["baseline_mbps"] else float("nan")
    for r in a
]
thresholds = [
    float(r["threshold_mbps"]) if r["threshold_mbps"] else float("nan")
    for r in a
]

installed = [
    float(r["timestamp"]) - t0
    for r in a
    if r["action"] == "DROP_INSTALLED"
]
removed = [
    float(r["timestamp"]) - t0
    for r in a
    if r["action"] == "DROP_REMOVED"
]

# Manual execution left a long idle tail in the raw CSV. For figures,
# focus on the meaningful experimental window while preserving all
# samples around training, attack, mitigation and unblock.
if installed and removed:
    focus_start = max(0.0, installed[0] - 60.0)
    focus_end = removed[-1] + 20.0
else:
    focus_start = 0.0
    focus_end = max(times)

fig, ax = plt.subplots(figsize=(9, 4.8))
ax.plot(times, rates, label="Ingress rate")
ax.plot(times, baselines, label="Adaptive baseline")
ax.plot(times, thresholds, label="Adaptive threshold")

if installed:
    ax.axvline(
        x=installed[0],
        linestyle="--",
        label="DROP_INSTALLED",
    )
if removed:
    ax.axvline(
        x=removed[-1],
        linestyle=":",
        label="DROP_REMOVED",
    )

ax.set_xlim(focus_start, focus_end)
ax.set_xlabel("Time from controller samples start (s)")
ax.set_ylabel("Rate (Mbit/s)")
ax.set_title("FINAL-A — Adaptive detection and mitigation")
ax.legend()
fig.tight_layout()
fig.savefig(OUT / "final_a_adaptive_detection.png", dpi=180)
plt.close(fig)

# A second view makes the learned ~2 Mbps baseline and ~3 Mbps
# adaptive threshold legible even when attack-rate samples are large.
fig, ax = plt.subplots(figsize=(9, 4.8))
ax.plot(times, rates, label="Ingress rate")
ax.plot(times, baselines, label="Adaptive baseline")
ax.plot(times, thresholds, label="Adaptive threshold")

if installed:
    ax.axvline(
        x=installed[0],
        linestyle="--",
        label="DROP_INSTALLED",
    )
if removed:
    ax.axvline(
        x=removed[-1],
        linestyle=":",
        label="DROP_REMOVED",
    )

ax.set_xlim(focus_start, focus_end)
ax.set_ylim(0, 6)
ax.set_xlabel("Time from controller samples start (s)")
ax.set_ylabel("Rate (Mbit/s)")
ax.set_title("FINAL-A — Adaptive baseline and threshold (zoom)")
ax.legend()
fig.tight_layout()
fig.savefig(OUT / "final_a_adaptive_threshold_zoom.png", dpi=180)
plt.close(fig)

# ------------------------------------------------------------------
# FINAL-A: selective mitigation
# ------------------------------------------------------------------
hosts = ["h1 attacker", "h5 legitimate", "h2 legitimate"]
loss = [
    numeric_metric(
        summary,
        "FINAL_A",
        "packet_loss_during_mitigation",
        "h1",
    ),
    numeric_metric(
        summary,
        "FINAL_A",
        "packet_loss_during_mitigation",
        "h5",
    ),
    numeric_metric(
        summary,
        "FINAL_A",
        "packet_loss_during_mitigation",
        "h2",
    ),
]

fig, ax = plt.subplots(figsize=(7.5, 4.8))
bars = ax.bar(hosts, loss)
ax.bar_label(bars, labels=[f"{v:.0f}%" for v in loss], padding=3)
ax.set_ylabel("Packet loss (%)")
ax.set_ylim(0, 110)
ax.set_title("FINAL-A — Selectivity of automatic mitigation")
fig.tight_layout()
fig.savefig(OUT / "final_a_selectivity.png", dpi=180)
plt.close(fig)

# ------------------------------------------------------------------
# FINAL-B: runtime policy effects
# ------------------------------------------------------------------
policy_cases = [
    "Allowlist ON",
    "Allowlist OFF",
    "Blocklist ON",
    "Blocklist OFF",
]
policy_loss = [
    numeric_metric(
        summary,
        "FINAL_B",
        "packet_loss_high_rate_allowlisted",
        "h5",
    ),
    numeric_metric(
        summary,
        "FINAL_B",
        "packet_loss_high_rate_unallowlisted",
        "h5",
    ),
    numeric_metric(
        summary,
        "FINAL_B",
        "packet_loss_admin_blocked",
        "h5",
    ),
    numeric_metric(
        summary,
        "FINAL_B",
        "packet_loss_after_admin_unblock",
        "h5",
    ),
]

fig, ax = plt.subplots(figsize=(8, 4.8))
bars = ax.bar(policy_cases, policy_loss)
ax.bar_label(
    bars,
    labels=[f"{v:.0f}%" for v in policy_loss],
    padding=3,
)
ax.set_ylabel("h5 packet loss (%)")
ax.set_ylim(0, 110)
ax.set_title("FINAL-B — Runtime policy effects")
fig.tight_layout()
fig.savefig(OUT / "final_b_policy_effects.png", dpi=180)
plt.close(fig)

print("Generated:")
for p in sorted(OUT.glob("*.png")):
    print(" -", p)
