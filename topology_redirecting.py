# topology_redirecting.py
# Star topology for role-based traffic steering
#
#   h1 (client, 10.0.0.100) ─── s0 (hub, DPID=10)
#                                  ├── s1 (DPID=1) ─── h2 (web1, 10.0.0.1, guest)
#                                  ├── s2 (DPID=2) ─── h3 (web2, 10.0.0.2, admin)
#                                  └── s3 (DPID=3) ─── h4 (web3, 10.0.0.3, employee)

from mininet.topo import Topo


class StarAccessTopo(Topo):
    def build(self):
        h1 = self.addHost("h1", ip="10.0.0.100/24", mac="00:00:00:00:00:0a")
        h2 = self.addHost("h2", ip="10.0.0.1/24",   mac="00:00:00:00:00:01")
        h3 = self.addHost("h3", ip="10.0.0.2/24",   mac="00:00:00:00:00:02")
        h4 = self.addHost("h4", ip="10.0.0.3/24",   mac="00:00:00:00:00:03")

        s0 = self.addSwitch("s0", dpid="000000000000000a")
        s1 = self.addSwitch("s1", dpid="0000000000000001")
        s2 = self.addSwitch("s2", dpid="0000000000000002")
        s3 = self.addSwitch("s3", dpid="0000000000000003")

        
        self.addLink(h1, s0)

        self.addLink(s0, s1)
        self.addLink(s0, s2)
        self.addLink(s0, s3)

        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s3)


topos = {"staraccesstopo": (lambda: StarAccessTopo())}
