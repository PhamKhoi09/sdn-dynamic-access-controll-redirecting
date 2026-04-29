# dynamic_access_controller.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp

import logging
import time

from policy_engine import PolicyEngine, WINDOW_SECONDS
from reroute_engine import (
    RerouteEngine,
    STATS_INTERVAL, REROUTE_PRIORITY, ROLES_TO_REROUTE,
    TOPO_HOST_SWITCH, TOPO_SERVER_SWITCH,
    PRIMARY_EGRESS_PORT, ALTERNATE_EGRESS_PORT, CONGESTION_MONITOR,
    CONGESTION_DETECTED, CONGESTION_ACTIVE, CONGESTION_CLEARED,
)


class DynamicAccessController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicAccessController, self).__init__(*args, **kwargs)

        self.logger.setLevel(logging.INFO)

        self.mac_to_port = {}
        self.datapaths = {}
        self.policy = PolicyEngine()

        self.role_by_ip = {
            "10.0.0.1": "guest",     # h1
            "10.0.0.2": "admin",     # h2
            "10.0.0.3": "employee",  # h3
            "10.0.0.4": "server",    # h4
        }

        self.reroute = RerouteEngine()

        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.stats_thread   = hub.spawn(self._stats_loop)

        self.logger.info("DynamicAccessController initialized (QoS v2: queue-shaping + rerouting)")

    def _monitor_loop(self):
        while True:
            try:
                for ip, host in list(self.policy.hosts.items()):
                    elapsed = time.time() - host.window_start_ts
                    if elapsed >= WINDOW_SECONDS:
                        new_queue = self.policy.decide_queue(host)
                        old_queue = host.current_queue

                        host.current_queue = new_queue

                        self.logger.info(
                            "[WINDOW] ip=%s mac=%s role=%s packet:%s var=%.3f stable=%s q%s->q%s",
                            ip,
                            host.mac,
                            host.role,
                            host.last_packet_count,
                            host.variation_score,
                            host.stable_cycles,
                            old_queue,
                            new_queue,
                        )

                        self.policy.commit_window(ip)
                        self._apply_host_policy(ip, host.current_queue)
            except Exception as e:
                self.logger.exception("monitor loop error: %s", e)

            hub.sleep(1)

    def _stats_loop(self):
        """Periodically request port statistics from all connected switches."""
        while True:
            hub.sleep(STATS_INTERVAL)
            for dp in list(self.datapaths.values()):
                self._send_port_stats_request(dp)

    def _send_port_stats_request(self, datapath):
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Ingest port stats into RerouteEngine, then ask it for a decision."""
        dpid = ev.msg.datapath.id

        for stat in ev.msg.body:
            bps = self.reroute.update_port_stats(dpid, stat.port_no, stat.tx_bytes)
            if bps > 0:
                self.logger.info(
                    "[STATS] dpid=%s port=%s tx=%.2f Kbps",
                    dpid, stat.port_no, bps / 1e3,
                )

        result = self.reroute.check_congestion(dpid)
        bps = self.reroute.get_bps(*CONGESTION_MONITOR)

        if result == CONGESTION_DETECTED:
            self.logger.warning(
                "[CONGESTION] Detected dpid=%s port=%s: %.2f Kbps — rerouting roles=%s",
                CONGESTION_MONITOR[0], CONGESTION_MONITOR[1], bps / 1e3, ROLES_TO_REROUTE,
            )
            self._toggle_reroute(activate=True)

        elif result == CONGESTION_ACTIVE:
            self.logger.info(
                "[CONGESTION] Active dpid=%s port=%s: %.2f Kbps",
                CONGESTION_MONITOR[0], CONGESTION_MONITOR[1], bps / 1e3,
            )

        elif result == CONGESTION_CLEARED:
            self.logger.info(
                "[CONGESTION] Cleared dpid=%s port=%s — restoring primary path",
                CONGESTION_MONITOR[0], CONGESTION_MONITOR[1],
            )
            self._toggle_reroute(activate=False)

        elif self.reroute.congestion_active:
            # below threshold but hysteresis not yet satisfied
            self.logger.info(
                "[CONGESTION] Below threshold dpid=%s port=%s: %.2f Kbps (count=%s/%s before clear)",
                CONGESTION_MONITOR[0], CONGESTION_MONITOR[1], bps / 1e3,
                self.reroute.below_count(), 6,
            )

    def _toggle_reroute(self, activate: bool):
        """Install (True) or remove (False) reroute flows on s1 for all ROLES_TO_REROUTE IPs."""
        s1 = self.datapaths.get(TOPO_HOST_SWITCH)
        if not s1:
            self.logger.warning(
                "[REROUTE] s1 (dpid=%s) not connected — skipping", TOPO_HOST_SWITCH
            )
            return

        for ip, role in self.role_by_ip.items():
            if role not in ROLES_TO_REROUTE:
                continue

            if activate:
                self._install_reroute_flow(s1, ip)
                self.reroute.mark_rerouted(ip)
                self.logger.info(
                    "[REROUTE] ip=%s role=%s → ALTERNATE path (egress port %s)",
                    ip, role, ALTERNATE_EGRESS_PORT,
                )
            else:
                self._remove_reroute_flow(s1, ip)
                self._delete_learned_flows(ip)
                self.reroute.clear_rerouted(ip)
                self.logger.info(
                    "[REROUTE] ip=%s role=%s → PRIMARY path restored (egress port %s)",
                    ip, role, PRIMARY_EGRESS_PORT,
                )

    def _install_reroute_flow(self, datapath, ip_src: str):
        """High-priority flow on s1: redirect ip_src traffic out the alternate egress port."""
        parser   = datapath.ofproto_parser
        host     = self.policy.get_host(ip_src)
        queue_id = host.current_queue if host else 2    # fallback: guest queue

        match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        actions = [
            parser.OFPActionSetQueue(queue_id),
            parser.OFPActionOutput(ALTERNATE_EGRESS_PORT),
        ]
        self.add_flow(datapath, REROUTE_PRIORITY, match, actions)

    def _remove_reroute_flow(self, datapath, ip_src: str):
        """Delete the high-priority reroute flow for ip_src on s1."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=REROUTE_PRIORITY,
            match=match,
        )
        datapath.send_msg(mod)

    def _delete_learned_flows(self, ip_src: str):
        """Remove MAC-learning flows for ip_src from ALL switches so they are
        re-learned on the correct path after a rerouting change."""
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser  = dp.ofproto_parser
            match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match,
            )
            dp.send_msg(mod)

    def _get_flood_ports(self, dpid, in_port):
        """Return an explicit list of ports for broadcast/unknown-unicast flooding,
        or None to fall back to standard OFPP_FLOOD.

        Diamond topology loop prevention:
          - s1 (dpid=1): hosts on ports 1-3, primary uplink=port4 (→s2),
                         alternate uplink=port5 (→s3).
            * Traffic from a host: flood to other hosts + PRIMARY uplink only.
              Never flood to BOTH uplinks — that creates a loop via s2→s4→s3→s1.
            * Traffic from an uplink: flood to host-facing ports only.
          - s4 (dpid=4): h4 on port3, uplinks port1 (←s2) and port2 (←s3).
            * From any uplink: only forward to h4 (port3).
            * From h4: only forward upstream via primary (port1→s2).
        """
        if dpid == TOPO_HOST_SWITCH:   # s1
            host_ports = [p for p in (1, 2, 3) if p != in_port]
            if in_port in (1, 2, 3):   # packet from a host
                return host_ports + [PRIMARY_EGRESS_PORT]   # NOT ALTERNATE
            else:                       # packet from s2 or s3
                return host_ports       # only to host-facing ports

        if dpid == TOPO_SERVER_SWITCH:  # s4
            if in_port in (1, 2):       # from s2 or s3
                return [3]              # only to h4
            if in_port == 3:            # from h4
                return [1]              # primary return path only (→s2)

        return None  # s2/s3 have no loop risk — standard flood is fine

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        # Clear stale MAC-table entries from any previous run
        self.mac_to_port[datapath.id].clear()

        # Flush ALL existing flows on this switch so poisoned/stale entries
        # from a previous run cannot interfere.
        del_mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        datapath.send_msg(del_mod)

        # Re-install table-miss → send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info("Switch connected: dpid=%s (flows flushed)", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        eth_type = eth.ethertype

        if eth_type == 0x88cc:
            return

        src = eth.src
        dst = eth.dst

        ip_src = None
        ip_dst = None

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            ip_src = arp_pkt.src_ip
            ip_dst = arp_pkt.dst_ip

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if ip_src and ip_src in self.role_by_ip:
            role = self.role_by_ip[ip_src]
            self.policy.register_host(ip_src, src, role)
            self.policy.increment_packet(ip_src, 1)

            host = self.policy.get_host(ip_src)
            self.logger.info(
    		"[PKT] ip=%s mac=%s role=%s packet:%s Q_ID=%s",
    		ip_src,
    		src,
   		role,
    		host.packet_count if host else 0,
   		host.current_queue if host else "n/a",
		)

        out_port = ofproto.OFPP_FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

        actions = []

        if out_port == ofproto.OFPP_FLOOD:
            # ── Controlled flood: prevent broadcast loops in diamond topology ──
            flood_ports = self._get_flood_ports(dpid, in_port)
            if flood_ports is not None:
                actions = [parser.OFPActionOutput(p) for p in flood_ports]
            else:
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        else:
            # ── Unicast: set QoS queue for source host, then forward ──────────
            if ip_src and ip_src in self.policy.hosts:
                host = self.policy.get_host(ip_src)
                if host:
                    actions.append(parser.OFPActionSetQueue(host.current_queue))
            actions.append(parser.OFPActionOutput(out_port))

            match_fields = {"in_port": in_port, "eth_src": src, "eth_dst": dst}
            if ip_pkt and ip_src:
                match_fields["eth_type"] = 0x0800
                match_fields["ipv4_src"] = ip_src
                if ip_dst:
                    match_fields["ipv4_dst"] = ip_dst

            match = parser.OFPMatch(**match_fields)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
            )
        datapath.send_msg(mod)

    def _apply_host_policy(self, ip, queue_id):
        host = self.policy.get_host(ip)
        if not host:
            return
        self.logger.info(
            "[POLICY] ip=%s mac=%s role=%s queue=q%s rerouted=%s",
            host.ip,
            host.mac,
            host.role,
            queue_id,
            self.reroute.is_rerouted(ip),
        )
        # Re-install flows on all switches so installed queue matches controller state.
        # Iterate over all datapaths and update any flow whose ipv4_src matches this IP.
        for dp in self.datapaths.values():
            parser  = dp.ofproto_parser
            ofproto = dp.ofproto
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=1,
                match=match,
            )
            dp.send_msg(mod)
        if self.reroute.is_rerouted(ip):
            s1 = self.datapaths.get(TOPO_HOST_SWITCH)
            if s1:
                self._install_reroute_flow(s1, ip)
