# topology.py
from mininet.topo import Topo


class DynamicAccessTopo(Topo):
    def build(self):
        # Hosts
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")  # guest
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")  # admin
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")  # employee
        h4 = self.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")  # server

        # Switch
        s1 = self.addSwitch("s1")

        # Links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


topos = {"dynamicaccesstopo": (lambda: DynamicAccessTopo())}
