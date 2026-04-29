# reroute_engine.py
import time
from typing import Optional


# Diamond topology:
#
#   h1(guest)  ──┐
#   h2(admin)  ──┤── s1 ──[p4]── s2 ──[p2]── s4 ── h4(server)
#   h3(emp.)   ──┘       └──[p5]── s3 ──[p2]──┘
#
#   DPID:  s1=1  s2=2  s3=3  s4=4
#   Primary path  : s1(p4) → s2 → s4 → h4
#   Alternate path: s1(p5) → s3 → s4 → h4   (used when primary congested)
#
STATS_INTERVAL        = 5
CONGESTION_BPS        = 500_000
CONGESTION_CLEAR_COUNT = 6         # consecutive below-threshold polls before restoring
REROUTE_PRIORITY      = 10        
ROLES_TO_REROUTE      = {"guest"}  # only these roles are redirected under congestion

TOPO_HOST_SWITCH      = 1          # DPID of s1  (h1, h2, h3 attached)
TOPO_SERVER_SWITCH    = 4          # DPID of s4  (h4 server attached)
PRIMARY_EGRESS_PORT   = 4          
ALTERNATE_EGRESS_PORT = 5          
CONGESTION_MONITOR    = (TOPO_HOST_SWITCH, PRIMARY_EGRESS_PORT)

# Return values of check_congestion()
CONGESTION_DETECTED = "detected"   
CONGESTION_ACTIVE   = "active"     
CONGESTION_CLEARED  = "cleared"    
CONGESTION_NONE     = None


class RerouteEngine:
    """Tracks per-port bandwidth and decides when to activate/deactivate rerouting.

    Usage (inside the Ryu controller):

        self.reroute = RerouteEngine()

        # On each OFPPortStatsReply:
        for stat in ev.msg.body:
            self.reroute.update_port_stats(dpid, stat.port_no, stat.tx_bytes)

        result = self.reroute.check_congestion(dpid)
        if result == CONGESTION_DETECTED:
            self._toggle_reroute(activate=True)
        elif result == CONGESTION_CLEARED:
            self._toggle_reroute(activate=False)
    """

    def __init__(self):
        # Raw counters from previous poll: {(dpid, port_no): {"tx_bytes": int, "ts": float}}
        self._port_prev: dict = {}
        # Smoothed bandwidth per port: {(dpid, port_no): float (bytes/sec)}
        self.port_bps: dict = {}
        # IPs currently forwarded on the alternate path
        self.rerouted_ips: set = set()
        # Whether congestion is currently active
        self.congestion_active: bool = False
        # Consecutive polls where bps was below threshold (hysteresis counter)
        self._below_count: int = 0

    # ── Port-stats ingestion ──────────────────────────────────────────────────

    def update_port_stats(self, dpid: int, port_no: int, tx_bytes: int) -> float:
        """Ingest a single port counter sample.  Returns the computed Bps
        for this port (0.0 on the first call for a given port, before a delta
        can be calculated).
        """
        if port_no >= 0xFFFFFF00:   # skip OVS internal pseudo-ports
            return 0.0

        key  = (dpid, port_no)
        now  = time.time()
        prev = self._port_prev.get(key)
        bps  = 0.0

        if prev is not None:
            delta_bytes = tx_bytes - prev["tx_bytes"]
            delta_t     = now - prev["ts"]
            bps = delta_bytes / delta_t if delta_t > 0 else 0.0
            self.port_bps[key] = bps

        self._port_prev[key] = {"tx_bytes": tx_bytes, "ts": now}
        return bps

    # ── Congestion decision ───────────────────────────────────────────────────

    def check_congestion(self, dpid: int) -> Optional[str]:
        """Evaluate the monitored link after new stats arrive for `dpid`.

        Returns one of: CONGESTION_DETECTED, CONGESTION_ACTIVE,
                        CONGESTION_CLEARED, CONGESTION_NONE (None).
        Only meaningful when called for the switch that owns CONGESTION_MONITOR.
        """
        if dpid != CONGESTION_MONITOR[0]:
            return CONGESTION_NONE

        bps = self.port_bps.get(CONGESTION_MONITOR, 0.0)

        if bps >= CONGESTION_BPS:
            self._below_count = 0
            if not self.congestion_active:
                self.congestion_active = True
                return CONGESTION_DETECTED
            return CONGESTION_ACTIVE

        if self.congestion_active:
            self._below_count += 1
            if self._below_count >= CONGESTION_CLEAR_COUNT:
                self._below_count = 0
                self.congestion_active = False
                return CONGESTION_CLEARED

        return CONGESTION_NONE

    # ── Rerouted-IP tracking ─────────────────────────────────────────────────

    def mark_rerouted(self, ip: str):
        """Record that `ip` is now forwarded on the alternate path."""
        self.rerouted_ips.add(ip)

    def clear_rerouted(self, ip: str):
        """Record that `ip` has been restored to the primary path."""
        self.rerouted_ips.discard(ip)

    def is_rerouted(self, ip: str) -> bool:
        return ip in self.rerouted_ips

    # ── Helpers ──────────────────────────────────────────────────────────────

    def get_bps(self, dpid: int, port_no: int) -> float:
        """Return last computed Bps for a given (dpid, port_no), or 0.0."""
        return self.port_bps.get((dpid, port_no), 0.0)

    def below_count(self) -> int:
        """Current hysteresis counter value (polls below threshold)."""
        return self._below_count
