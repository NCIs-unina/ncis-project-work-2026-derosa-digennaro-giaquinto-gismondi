#!/usr/bin/env python3

from pathlib import Path
import math
import pandas as pd
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
PLOTS = RESULTS / "plots"

PLOTS.mkdir(parents=True, exist_ok=True)


def require(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Missing required file: {path}")


summary_path = RESULTS / "summary.csv"
rtt_path = RESULTS / "rtt_samples.csv"
events_path = RESULTS / "events.csv"
controller_path = RESULTS / "controller_port1.csv"

for path in [summary_path, rtt_path, events_path, controller_path]:
    require(path)

summary = pd.read_csv(summary_path)
rtt = pd.read_csv(rtt_path)
events = pd.read_csv(events_path)
controller = pd.read_csv(controller_path)


def event_time(scenario: str, event: str) -> float:
    rows = events[
        (events["scenario"] == scenario)
        & (events["event"] == event)
    ]
    if rows.empty:
        raise RuntimeError(
            f"Event not found: scenario={scenario}, event={event}"
        )
    return float(rows.iloc[0]["attack_relative_s"])


e3_drop_s = event_time("E3", "drop_installed")
e3_attack_end_s = event_time("E3", "attack_end")

e1_row = summary[summary["scenario"] == "E1"].iloc[0]
e1_rtt_avg = float(e1_row["rtt_avg_ms"])


# ============================================================
# 1. RTT over time
# ============================================================

fig, ax = plt.subplots(figsize=(10, 5.5))

for scenario in ["E2", "E3"]:
    data = rtt[rtt["scenario"] == scenario].copy()
    data = data.dropna(subset=["attack_relative_s"])

    ax.plot(
        data["attack_relative_s"],
        data["rtt_ms"],
        label=scenario,
        linewidth=2,
    )

ax.axhline(
    e1_rtt_avg,
    linestyle=":",
    linewidth=2,
    label=f"E1 baseline avg = {e1_rtt_avg:.3f} ms",
)

ax.axvline(
    0.0,
    linestyle="--",
    linewidth=1.6,
    label="Attack start",
)

ax.axvline(
    15.0,
    linestyle=":",
    linewidth=1.8,
    label="Attack end",
)

ax.axvline(
    e3_drop_s,
    linestyle="-.",
    linewidth=1.8,
    label=f"E3 DROP = {e3_drop_s:.2f} s",
)

ax.set_xlim(-10, 20)
ax.set_xlabel("Time relative to attack start (s)")
ax.set_ylabel("RTT h2 → h4 (ms)")
ax.set_title("Legitimate traffic RTT during DoS")
ax.grid(True, alpha=0.25)
ax.legend()
fig.tight_layout()

rtt_plot = PLOTS / "rtt_over_time.png"
fig.savefig(rtt_plot, dpi=180)
plt.close(fig)


# ============================================================
# 2. Goodput summary
# ============================================================

plot_summary = summary.copy()
x = list(range(len(plot_summary)))
width = 0.36

fig, ax = plt.subplots(figsize=(8.5, 5.5))

left_positions = [i - width / 2 for i in x]
right_positions = [i + width / 2 for i in x]

legit_bars = ax.bar(
    left_positions,
    plot_summary["legit_total_mbps"],
    width=width,
    label="Legitimate aggregate goodput",
)

# Keep E1 as NaN so no attacker bar is drawn: in E1 there is no attack.
attacker_values = plot_summary["attacker_receiver_mbps"].copy()

attacker_bars = ax.bar(
    right_positions,
    attacker_values,
    width=width,
    label="Attacker goodput received by h4",
)

ax.set_xticks(x)
ax.set_xticklabels(plot_summary["scenario"])
ax.set_ylabel("Receiver goodput (Mbit/s)")
ax.set_title("Goodput comparison across scenarios")
ax.grid(True, axis="y", alpha=0.25)
ax.legend()

for bar in legit_bars:
    height = bar.get_height()
    ax.annotate(
        f"{height:.3f}",
        xy=(bar.get_x() + bar.get_width() / 2, height),
        xytext=(0, 3),
        textcoords="offset points",
        ha="center",
        va="bottom",
    )

for i, bar in enumerate(attacker_bars):
    height = bar.get_height()

    if math.isnan(height):
        ax.annotate(
            "N/A",
            xy=(right_positions[i], 0),
            xytext=(0, 5),
            textcoords="offset points",
            ha="center",
            va="bottom",
        )
    else:
        ax.annotate(
            f"{height:.3f}",
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
        )

fig.tight_layout()

goodput_plot = PLOTS / "goodput_summary.png"
fig.savefig(goodput_plot, dpi=180)
plt.close(fig)


# ============================================================
# 3. Attacker ingress port rate
# ============================================================

fig, ax = plt.subplots(figsize=(10, 5.5))

ax.plot(
    controller["attack_relative_s"],
    controller["rx_mbps"],
    marker="o",
    linewidth=2,
    label="s1 port 1 RX rate",
)

ax.axhline(
    1.5,
    linestyle="--",
    linewidth=1.6,
    label="Detection threshold = 1.5 Mbit/s",
)

ax.axvline(
    0.0,
    linestyle="--",
    linewidth=1.6,
    label="Attack start",
)

ax.axvline(
    e3_drop_s,
    linestyle="-.",
    linewidth=1.8,
    label=f"DROP installed = {e3_drop_s:.2f} s",
)

ax.axvline(
    e3_attack_end_s,
    linestyle=":",
    linewidth=1.8,
    label="Attack end",
)

ax.set_xlim(-10, 20)
ax.set_xlabel("Time relative to attack start (s)")
ax.set_ylabel("Ingress RX rate on s1 port 1 (Mbit/s)")
ax.set_title("E3 monitored attacker-port rate and mitigation event")
ax.grid(True, alpha=0.25)
ax.legend()
fig.tight_layout()

rate_plot = PLOTS / "attacker_port_rate.png"
fig.savefig(rate_plot, dpi=180)
plt.close(fig)


print(f"Wrote {rtt_plot}")
print(f"Wrote {goodput_plot}")
print(f"Wrote {rate_plot}")
