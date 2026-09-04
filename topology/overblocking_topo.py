#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def run():
    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
    )

    # Hosts
    h1 = net.addHost("h1", ip="10.0.0.1/24")  # attacker
    h2 = net.addHost("h2", ip="10.0.0.2/24")  # legitimate
    h3 = net.addHost("h3", ip="10.0.0.3/24")  # legitimate
    h4 = net.addHost("h4", ip="10.0.0.4/24")  # victim
    h5 = net.addHost("h5", ip="10.0.0.5/24")  # legitimate, shares uplink with h1

    # Core switch: s1 port 1 is the shared uplink from s2.
    s1 = net.addSwitch(
        "s1",
        dpid="0000000000000001",
        protocols="OpenFlow13",
        failMode="secure",
    )

    # Access switch for h1 and h5.
    # Port 1 is deliberately unused so the M1 controller, which monitors
    # port number 1 on every datapath, only sees the shared uplink on s1.
    s2 = net.addSwitch(
        "s2",
        dpid="0000000000000002",
        protocols="OpenFlow13",
        failMode="secure",
    )

    # h1 and h5 share the same uplink toward s1.
    net.addLink(h1, s2, bw=100, port2=2)
    net.addLink(h5, s2, bw=100, port2=3)

    # Shared uplink: s2-eth4 <-> s1-eth1.
    net.addLink(s2, s1, bw=100, port1=4, port2=1)

    # Other legitimate hosts connect directly to the core.
    net.addLink(h2, s1, bw=100, port2=2)
    net.addLink(h3, s1, bw=100, port2=3)

    # Victim-facing bottleneck.
    net.addLink(h4, s1, bw=5, port2=4)

    net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653,
    )

    info("*** Starting network\n")
    net.start()

    info("\n*** M2 over-blocking topology ready\n")
    info("*** h1 = attacker               10.0.0.1 (behind s2)\n")
    info("*** h5 = legitimate shared     10.0.0.5 (behind s2)\n")
    info("*** h2 = legitimate            10.0.0.2\n")
    info("*** h3 = legitimate            10.0.0.3\n")
    info("*** h4 = victim                10.0.0.4\n")
    info("*** shared uplink: s2-eth4 <-> s1-eth1\n")
    info("*** victim bottleneck: s1-eth4 = 5 Mbps\n\n")

    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
