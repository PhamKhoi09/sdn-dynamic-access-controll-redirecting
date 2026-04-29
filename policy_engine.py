# policy_engine.py
from dataclasses import dataclass, field
from typing import Dict, Optional
import time

WINDOW_SECONDS = 120

ROLE_DEFAULT_QUEUE = {
    "admin": 0,
    "employee": 1,
    "guest": 2,
    "server": 1,
}

QUEUE_NAME = {
    0: "q0",
    1: "q1",
    2: "q2",
    3: "q3",
}


@dataclass
class HostTrafficWindow:
    ip: str = ""
    mac: str = ""
    role: str = "unknown"
    current_queue: int = 1
    default_queue: int = 1

    packet_count: int = 0
    last_packet_count: int = 0

    window_start_ts: float = field(default_factory=time.time)
    variation_score: float = 0.0
    stable_cycles: int = 0
    penalty_cycles: int = 0
    history: list = field(default_factory=list)


class PolicyEngine:
    def __init__(self):
        self.hosts: Dict[str, HostTrafficWindow] = {}

    def register_host(self, ip: str, mac: str, role: str):
        if ip not in self.hosts:
            default_queue = ROLE_DEFAULT_QUEUE.get(role, 1)
            self.hosts[ip] = HostTrafficWindow(
                ip=ip,
                mac=mac,
                role=role,
                current_queue=default_queue,
                default_queue=default_queue,
            )
        else:
            self.hosts[ip].mac = mac
            self.hosts[ip].role = role

    def get_host(self, ip: str) -> Optional[HostTrafficWindow]:
        return self.hosts.get(ip)

    def increment_packet(self, ip: str, count: int = 1):
        host = self.hosts.get(ip)
        if host:
            host.packet_count += count

    def compute_variation(self, host: HostTrafficWindow) -> float:
        prev = max(host.last_packet_count, 1)
        curr = host.packet_count
        return abs(curr - prev) / prev

    def decide_queue(self, host: HostTrafficWindow) -> int:
        # ── Idle window: no packets at all → restore to default, no penalty ──
        if host.packet_count == 0:
            host.variation_score = 0.0
            host.penalty_cycles = 0
            host.stable_cycles = 0
            return host.default_queue

        variation = self.compute_variation(host)
        host.variation_score = variation

        HIGH_VARIATION_THRESHOLD = 0.80
        LOW_VARIATION_THRESHOLD = 0.35

        stable = variation < LOW_VARIATION_THRESHOLD

        if variation >= HIGH_VARIATION_THRESHOLD or host.packet_count > 3000:
            host.penalty_cycles = 2
            host.stable_cycles = 0
            return 3

        if host.penalty_cycles > 0:
            host.penalty_cycles -= 1
            return 3

        if stable:
            host.stable_cycles += 1
        else:
            host.stable_cycles = 0

        if host.stable_cycles >= 2:
            return host.default_queue

        return host.default_queue

    def commit_window(self, ip: str):
        host = self.hosts.get(ip)
        if not host:
            return None

        host.last_packet_count = host.packet_count
        host.packet_count = 0
        host.window_start_ts = time.time()
        host.history.append({
            "ts": time.time(),
            "ip": host.ip,
            "mac": host.mac,
            "role": host.role,
            "packet": host.last_packet_count,
            "queue": host.current_queue,
            "variation": host.variation_score,
            "stable_cycles": host.stable_cycles,
            "penalty_cycles": host.penalty_cycles,
        })
        return host

    def get_queue_name(self, queue_id: int) -> str:
        return QUEUE_NAME.get(queue_id, f"q{queue_id}")
