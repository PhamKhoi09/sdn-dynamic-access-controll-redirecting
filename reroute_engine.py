# reroute_engine.py
TOPO_HUB_SWITCH    = 10   # DPID of the central hub switch (s0 / br0)

# GCP port assignments on s0-edgeswitch (verify with: ovs-ofctl -O OpenFlow13 show br0)
# Mininet: CLIENT=1, web1=2, web2=3, web3=4
# GCP:     CLIENT=5, web1=6, web2=7, web3=8
CLIENT_FACING_PORT = 5

ROLE_SERVER_MAP = {
    "guest":    "10.0.0.1",
    "admin":    "10.0.0.2",
    "employee": "10.0.0.3",
}

GUEST_SERVER_IP = "10.0.0.1"

SERVER_EGRESS_PORT = {
    "10.0.0.1": 6,
    "10.0.0.2": 7,
    "10.0.0.3": 8,
}

DEFAULT_ROLE          = "guest"
REDIRECT_PRIORITY     = 10
SESSION_POLL_INTERVAL = 5


class RedirectEngine:
    """Tracks which server each authenticated client is currently routed to.

    An entry in _installed means forward+return flows are active on s0 for that
    client IP.  Absence (or value == GUEST_SERVER_IP) means the client uses the
    default (guest) forwarding path.
    """

    def __init__(self):
        self._installed: dict = {}

    def get_installed_target(self, client_ip: str):
        """Return the server IP for which flows are currently installed, or None."""
        return self._installed.get(client_ip)

    def set_installed(self, client_ip: str, server_ip: str):
        self._installed[client_ip] = server_ip

    def clear_installed(self, client_ip: str):
        self._installed.pop(client_ip, None)

    def all_redirected(self) -> dict:
        """Return a snapshot of the current redirect table {client_ip: server_ip}."""
        return dict(self._installed)
