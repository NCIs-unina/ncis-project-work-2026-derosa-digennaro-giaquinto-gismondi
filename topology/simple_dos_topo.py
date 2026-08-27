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

    # OpenFlow 1.3 switch
    s1 = net.addSwitch(
        "s1",
        protocols="OpenFlow13",
        failMode="secure",
    )

    # Explicit switch-port numbering.
    net.addLink(h1, s1, bw=100, port2=1)
    net.addLink(h2, s1, bw=100, port2=2)
    net.addLink(h3, s1, bw=100, port2=3)

    # Victim-facing bottleneck.
    net.addLink(h4, s1, bw=5, port2=4)

    # External Ryu controller.
    net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653,
    )

    info("*** Starting network\n")
    net.start()

    info("\n*** Topology ready\n")
    info("*** h1 = attacker      10.0.0.1\n")
    info("*** h2 = legitimate    10.0.0.2\n")
    info("*** h3 = legitimate    10.0.0.3\n")
    info("*** h4 = victim        10.0.0.4\n")
    info("*** s1-eth4 bottleneck = 5 Mbps\n\n")

    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
