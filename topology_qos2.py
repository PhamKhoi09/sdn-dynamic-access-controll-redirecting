# topology_qos2.py
# Diamond topology for Congestion-Aware Rerouting (QoS Scenario 2)
#
#   h1(guest)  ──┐
#   h2(admin)  ──┤── s1 ──[p4]── s2 ──[p2]── s4 ── h4(server)
#   h3(emp.)   ──┘       └──[p5]── s3 ──[p2]──┘
#
# Port assignments (Mininet assigns ports in addLink order):
#   s1: port1=h1  port2=h2  port3=h3  port4=s2  port5=s3
#   s2: port1=s1  port2=s4
#   s3: port1=s1  port2=s4
#   s4: port1=s2  port2=s3  port3=h4
#
# These port numbers must match the constants in dynamic_access_controller_qos2.py:
#   PRIMARY_EGRESS_PORT   = 4   (s1 → s2)
#   ALTERNATE_EGRESS_PORT = 5   (s1 → s3)

from mininet.topo import Topo


class DiamondTopo(Topo):
    def build(self):
        # ── Hosts ──────────────────────────────────────────────────────────────
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")  # guest
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")  # admin
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")  # employee
        h4 = self.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")  # server

        # ── Switches ───────────────────────────────────────────────────────────
        s1 = self.addSwitch("s1")   # DPID 1 — ingress (hosts h1-h3)
        s2 = self.addSwitch("s2")   # DPID 2 — primary path
        s3 = self.addSwitch("s3")   # DPID 3 — alternate path
        s4 = self.addSwitch("s4")   # DPID 4 — egress (server h4)

        # ── Host links (s1 gets ports 1, 2, 3) ────────────────────────────────
        self.addLink(h1, s1)        # h1-eth0 ↔ s1-port1
        self.addLink(h2, s1)        # h2-eth0 ↔ s1-port2
        self.addLink(h3, s1)        # h3-eth0 ↔ s1-port3

        # ── Primary path: s1(p4) → s2(p1) → s4(p1) ───────────────────────────
        self.addLink(s1, s2)        # s1-port4 ↔ s2-port1
        self.addLink(s2, s4)        # s2-port2 ↔ s4-port1

        # ── Alternate path: s1(p5) → s3(p1) → s4(p2) ─────────────────────────
        self.addLink(s1, s3)        # s1-port5 ↔ s3-port1
        self.addLink(s3, s4)        # s3-port2 ↔ s4-port2

        # ── Server link (s4 gets port 3) ───────────────────────────────────────
        self.addLink(h4, s4)        # h4-eth0 ↔ s4-port3


topos = {"diamondtopo": (lambda: DiamondTopo())}
