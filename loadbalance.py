import json
from webob import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4, arp, tcp, udp
from ryu.topology.api import get_link, get_host
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import mac
from member import Member
import ofp_helper

qos_instance_name = 'qos_api_app'
member_list = {}
webserver_list = ["192.168.2.132", "192.168.2.211"]


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(QosControlController, {qos_instance_name: self})
        self.count = 0
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Goto Controller
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        ofp_helper.add_flow(datapath, 0, match, actions)

    def get_member(self, ip):
        for key, member in member_list.iteritems():
            if member.ip == ip:
                return member

    def add_flow_redirect(self, msg, in_port, src_ip, old_dst_ip, old_dst_mac, new_dst_ip, new_dst_mac, new_dst_port):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                ip_proto=inet.IPPROTO_TCP,
                                ipv4_src=src_ip,
                                ipv4_dst=old_dst_ip)

        actions = [parser.OFPActionSetField(ipv4_dst=new_dst_ip),
                   parser.OFPActionSetField(eth_dst=new_dst_mac),
                   parser.OFPActionOutput(new_dst_port)]
        ofp_helper.add_flow(datapath, 200, match, actions)

        # Set Packet header from Server 1 to Server 2 for SYN_ACK
        match_back = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                     ip_proto=inet.IPPROTO_TCP,
                                     ipv4_src=new_dst_ip,
                                     ipv4_dst=src_ip)
        actions_back = [parser.OFPActionSetField(ipv4_src=old_dst_ip),
                        parser.OFPActionSetField(eth_src=old_dst_mac),
                        parser.OFPActionOutput(1)]
        ofp_helper.add_flow(datapath, 200, match_back, actions_back)

        ofp_helper.send_packet_out(msg, in_port, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        # retrieve packet
        pkt = packet.Packet(msg.data)
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_arp = pkt.get_protocol(arp.arp)

        if pkt_arp or pkt_eth.dst not in member_list:
            self._handle_arp(msg, in_port, pkt_eth, pkt_arp)
        elif pkt_ipv4:
            if pkt_eth.dst == mac.BROADCAST_STR:
                self._broadcast_pkt(msg, in_port)
            elif (pkt_ipv4.dst == '255.255.255.255') or (pkt_ipv4.dst == '0.0.0.0'):
                self._broadcast_pkt(msg, in_port)
            else:
                self._handle_ipv4(msg, in_port, pkt, pkt_eth, pkt_ipv4)

    def _handle_arp(self, msg, in_port, pkt_eth, pkt_arp):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        eth_dst = pkt_eth.dst
        eth_src = pkt_eth.src
        dpid = datapath.id

        # update member(host) in member_list
        if pkt_arp is not None:
            member_list.setdefault(eth_src, Member(eth_src))
            member_list[eth_src].port = in_port
            member_list[eth_src].ip = pkt_arp.src_ip

        if eth_dst not in member_list:
            self._broadcast_pkt(msg, in_port)
        else:
            out_port = member_list[eth_dst].port
            actions = [parser.OFPActionOutput(out_port)]
            ofp_helper.send_packet_out(msg, in_port, actions)

    def _handle_ipv4(self, msg, in_port, pkt, pkt_ethernet, pkt_ipv4):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        pkt_tcp = pkt.get_protocol(tcp.tcp)

        eth_dst = pkt_ethernet.dst
        eth_src = pkt_ethernet.src

        # update ip info for members in member_list
        if eth_src not in member_list:
            member_list.setdefault(eth_src, Member(eth_src))
            member_list[eth_src].port = in_port

        dst_member = member_list.get(eth_dst)
        dst_member.ip = pkt_ipv4.dst
        src_member = member_list.get(eth_src)
        src_member.ip = pkt_ipv4.src
        out_port = dst_member.port

        web_count = len(webserver_list)
        self.count %= web_count

        if(pkt_ipv4.dst == webserver_list[0] and self.count != 0 and pkt_tcp is not None and pkt_tcp.dst_port == 8000):
            src_ip = pkt_ipv4.src
            old_dst_ip = pkt_ipv4.dst
            old_dst_mac = eth_dst
            backmember = self.get_member(webserver_list[self.count])
            new_dst_ip = backmember.ip
            new_dst_mac = backmember.mac
            new_dst_port = backmember.port
            self.add_flow_redirect(msg, in_port, src_ip, old_dst_ip, old_dst_mac, new_dst_ip, new_dst_mac, new_dst_port)
            self.count += 1

        else:
            if(pkt_ipv4.dst == webserver_list[0] and pkt_tcp is not None and pkt_tcp.dst_port == 8000):
                self.count += 1
            # install layer4 flow for statitic
            actions = [parser.OFPActionOutput(out_port)]
            actions_back = [parser.OFPActionOutput(in_port)]

            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=pkt_ipv4.src,
                                    ipv4_dst=pkt_ipv4.dst,
                                    ip_proto=pkt_ipv4.proto)
            match_back = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                         ipv4_src=pkt_ipv4.dst,
                                         ipv4_dst=pkt_ipv4.src,
                                         ip_proto=pkt_ipv4.proto)

            ofp_helper.add_flow(datapath, 100, match, actions)
            ofp_helper.add_flow(datapath, 100, match_back, actions_back)
            ofp_helper.send_packet_out(msg, in_port, actions)

    def _broadcast_pkt(self, msg, in_port):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        ofp_helper.send_packet_out(msg, in_port, actions)


class QosControlController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(QosControlController, self).__init__(req, link, data, **config)
        self.qos_control_spp = data[qos_instance_name]

    @route('qos', "/api/topology", methods=['GET'])
    def get_qos_topology(self, req, **kwargs):
        dic = []
        for key, value in member_list.iteritems():
            dic.append({key: value.toJson()})
        body = json.dumps(dic)
        return Response(content_type='application/json', body=body)
