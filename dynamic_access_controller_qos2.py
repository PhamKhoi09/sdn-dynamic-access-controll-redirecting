# dynamic_access_controller_qos2.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp

import json
import logging
import os
import time

from reroute_engine import (
    RedirectEngine,
    TOPO_HUB_SWITCH, CLIENT_FACING_PORT,
    ROLE_SERVER_MAP, GUEST_SERVER_IP, SERVER_EGRESS_PORT,
    DEFAULT_ROLE, REDIRECT_PRIORITY, SESSION_POLL_INTERVAL,
)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class DynamicAccessController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger.setLevel(logging.DEBUG)

        self.mac_to_port: dict = {}
        self.datapaths:   dict = {}   
        self.ip_to_mac:   dict = {}   

        self.role_by_ip: dict = {}

        self.server_ips = frozenset(ROLE_SERVER_MAP.values())

        self.redirect = RedirectEngine()

        self.sessions_file       = os.path.join(_BASE_DIR, 'sessions.json')
        self._last_sessions_poll = 0.0

        self.poll_thread = hub.spawn(self._poll_loop)

        self.logger.info(
            "DynamicAccessController ready — role-based redirect (no QoS)"
        )

    def _load_portal_sessions(self):
        """Read sessions.json, update role_by_ip, trigger redirect changes."""
        try:
            with open(self.sessions_file, 'r') as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning("[PORTAL] Could not read %s: %s", self.sessions_file, e)
            return

        sessions = data.get('sessions', {})
        now = time.time()
        active_ips: set = set()
        self.logger.debug("[PORTAL] Read %d session(s) from %s", len(sessions), self.sessions_file)

        for ip, entry in sessions.items():
            if ip in self.server_ips:
                continue
            if not isinstance(entry, dict):
                self.logger.warning("[PORTAL] %s: bad entry format (not a dict) — old sessions.json?", ip)
                continue
            try:
                expires_at = float(entry.get('expires_at', 0))
                if now >= expires_at:
                    self.logger.debug(
                        "[PORTAL] %s: skipping expired entry (expired %.0fs ago)",
                        ip, now - expires_at,
                    )
                    continue
            except (TypeError, ValueError):
                continue

            role = entry.get('role', DEFAULT_ROLE)
            active_ips.add(ip)

            old_role         = self.role_by_ip.get(ip)
            expected_target  = ROLE_SERVER_MAP.get(role, GUEST_SERVER_IP)
            installed_target = self.redirect.get_installed_target(ip)

            self.role_by_ip[ip] = role

            # Install/update if role changed or previous install failed (MACs missing)
            if old_role != role or installed_target != expected_target:
                self.logger.info(
                    "[PORTAL] %s: %s → %s (user=%s)",
                    ip, old_role or '(none)', role, entry.get('username', '?'),
                )
                self._update_redirect(ip, role)

        # Evict expired/removed sessions and restore to guest path
        for ip in list(self.role_by_ip.keys()):
            if ip not in active_ips:
                old_role = self.role_by_ip.pop(ip, DEFAULT_ROLE)
                self.logger.info(
                    "[PORTAL] %s: session expired (was %s) —> guest", ip, old_role
                )
                self._update_redirect(ip, DEFAULT_ROLE)

    def _poll_loop(self):
        while True:
            hub.sleep(SESSION_POLL_INTERVAL)
            try:
                self._load_portal_sessions()
                self._retry_pending()
            except Exception as e:
                self.logger.exception("poll loop error: %s", e)

    def _update_redirect(self, client_ip: str, role: str):
        """Install, update, or remove redirect flows on s0 for a client IP."""
        s0 = self.datapaths.get(TOPO_HUB_SWITCH)
        if not s0:
            return 

        target_server_ip = ROLE_SERVER_MAP.get(role, GUEST_SERVER_IP)
        installed_target = self.redirect.get_installed_target(client_ip)

        if target_server_ip != GUEST_SERVER_IP or installed_target:
            ofproto = s0.ofproto
            parser  = s0.ofproto_parser
            s0.send_msg(parser.OFPFlowMod(
                datapath=s0,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=parser.OFPMatch(eth_type=0x0800, ipv4_src=client_ip),
            ))

        if installed_target and installed_target != target_server_ip:
            self._remove_return_flow(s0, installed_target, client_ip)
            self.redirect.clear_installed(client_ip)

        if target_server_ip == GUEST_SERVER_IP:
            self.redirect.clear_installed(client_ip)
            self.logger.info(
                "[REDIRECT] %s → guest (default path → %s)", client_ip, GUEST_SERVER_IP
            )
            return


        server_mac  = self.ip_to_mac.get(target_server_ip)
        guest_mac   = self.ip_to_mac.get(GUEST_SERVER_IP)
        client_mac  = self.ip_to_mac.get(client_ip)
        client_port = (
            self.mac_to_port.get(TOPO_HUB_SWITCH, {}).get(client_mac)
            if client_mac else None
        )
        egress_port = SERVER_EGRESS_PORT.get(target_server_ip)

        if not server_mac:
            self.logger.warning(
                "[REDIRECT] MAC for %s not yet learned → will retry", target_server_ip
            )
            return
        if not guest_mac:
            self.logger.warning(
                "[REDIRECT] MAC for guest server %s not yet learned → will retry",
                GUEST_SERVER_IP,
            )
            return
        if client_port is None:
            self.logger.warning(
                "[REDIRECT] Port for client %s not yet known on s0 → will retry",
                client_ip,
            )
            return
        if egress_port is None:
            self.logger.error(
                "[REDIRECT] No egress port configured for %s", target_server_ip
            )
            return

        self._install_redirect_flows(
            s0, client_ip, target_server_ip,
            server_mac, guest_mac, client_port, egress_port,
        )
        self.redirect.set_installed(client_ip, target_server_ip)
        self.logger.info(
            "[REDIRECT] %s role=%s → %s (fwd_port=%s ret_port=%s)",
            client_ip, role, target_server_ip, egress_port, client_port,
        )

    def _install_redirect_flows(self, datapath, client_ip, server_ip,
                                 server_mac, guest_mac, client_port, egress_port):
        parser = datapath.ofproto_parser

        # Forward: client - target server  (rewrite destination)
        fwd_match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=client_ip)
        fwd_actions = [
            parser.OFPActionSetField(ipv4_dst=server_ip),
            parser.OFPActionSetField(eth_dst=server_mac),
            parser.OFPActionOutput(egress_port),
        ]
        self.add_flow(datapath, REDIRECT_PRIORITY, fwd_match, fwd_actions)

        # Return: target server - client  (rewrite source back to guest server IP)
        ret_match   = parser.OFPMatch(
            eth_type=0x0800, ipv4_src=server_ip, ipv4_dst=client_ip
        )
        ret_actions = [
            parser.OFPActionSetField(ipv4_src=GUEST_SERVER_IP),
            parser.OFPActionSetField(eth_src=guest_mac),
            parser.OFPActionOutput(client_port),
        ]
        self.add_flow(datapath, REDIRECT_PRIORITY, ret_match, ret_actions)

    def _remove_redirect_flows(self, datapath, client_ip: str, installed_server_ip: str):
        """Delete both the forward and return redirect flows for a client from s0."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        for match in [
            parser.OFPMatch(eth_type=0x0800, ipv4_src=client_ip),
            parser.OFPMatch(
                eth_type=0x0800, ipv4_src=installed_server_ip, ipv4_dst=client_ip
            ),
        ]:
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match,
            ))
        self.redirect.clear_installed(client_ip)

    def _remove_return_flow(self, datapath, server_ip: str, client_ip: str):
        """Delete only the return flow (server→client) for a previously active server."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch(
                eth_type=0x0800, ipv4_src=server_ip, ipv4_dst=client_ip
            ),
        ))


    def _retry_pending(self):
        """Install redirect flows for clients where MACs weren't available yet."""
        for ip, role in list(self.role_by_ip.items()):
            if role == DEFAULT_ROLE:
                continue
            target = ROLE_SERVER_MAP.get(role, GUEST_SERVER_IP)
            if self.redirect.get_installed_target(ip) != target:
                self._update_redirect(ip, role)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        ))

        self.add_flow(
            datapath, 0, parser.OFPMatch(),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)],
        )

        self.logger.info("[SWITCH] Connected dpid=%s (flows flushed)", datapath.id)

        if datapath.id == TOPO_HUB_SWITCH:
            self._retry_pending()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id
        in_port  = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x88cc:
            return

        src = eth.src
        dst = eth.dst

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip_src  = None
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        if ip_pkt:
            ip_src = ip_pkt.src
            if ip_src not in ('0.0.0.0',):
                self.ip_to_mac[ip_src] = src
        if arp_pkt:
            ip_src = arp_pkt.src_ip
            if ip_src not in ('0.0.0.0',):
                self.ip_to_mac[ip_src] = src

        if ip_src:
            role = self.role_by_ip.get(ip_src, DEFAULT_ROLE)
            self.logger.info(
                "[PKT] dpid=%s port=%s ip=%s mac=%s role=%s",
                dpid, in_port, ip_src, src, role,
            )
            # A non-guest client appeared; try installing flows if they're pending
            if role != DEFAULT_ROLE and dpid == TOPO_HUB_SWITCH:
                target = ROLE_SERVER_MAP.get(role, GUEST_SERVER_IP)
                if self.redirect.get_installed_target(ip_src) != target:
                    self._update_redirect(ip_src, role)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            # Low-priority unicast flow; redirect flows (priority=10) override it
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        ))

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs  = dict(datapath=datapath, priority=priority,
                       match=match, instructions=inst)
        if buffer_id is not None:
            kwargs['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))
