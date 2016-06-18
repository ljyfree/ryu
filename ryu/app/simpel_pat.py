

import logging
import time
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import *
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.icmp import *
from ryu.lib.packet.tcp import *
from ryu.lib.packet.udp import *
from ryu.lib.packet.in_proto import *
from ryu.lib.packet.ether_types import *
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3  import * 
from ryu.ofproto import ether
from ryu.ofproto import inet

LOG = logging.getLogger('SimplePat')
LOG.setLevel(logging.DEBUG)
logging.basicConfig()


INNER_IPADDR_LIST =  ["192.168.0."+str(x) for x in range(2,254)]
OUTER_IPADDR=  "181.27.0.50"
TCP_RESOURCE_LIST = [x for x in range (5000,5005)]
UDP_RESOURCE_LIST = [x for x in range (5000,5005)]
FLOW_IDLE_TIMEOUT = 30
INNER_PORT = 5
OUTTER_PORT = 6

class SimplePat(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimplePat, self).__init__(*args, **kwargs)
        self.id_proto = [IPPROTO_ICMP,IPPROTO_TCP,IPPROTO_UDP]
        self.tcp_pool = TCP_RESOURCE_LIST[:]
        self.udp_pool = UDP_RESOURCE_LIST[:]
        self.tcp_map_io={}
        self.udp_map_io={}
        self.icmp_map_io={}
    
    def process_icmp_pkt(self,msg):
        """
        OpenFlow haven't supported to match and edit ICMP_ID,So ICMP packet have to be dropped
        """
        LOG.debug("Packet was dropped since ICMP could not be PATed yet!")
        return 1         
    
    def process_tcp_pkt(self,msg):
        """
        A new TCP packet should trigger to add two flow entries 
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inPort = msg.match['in_port']
        dpid = datapath.id
        packet = Packet(msg.data)
        
        ipPacket = packet.get_protocol(ipv4)
        tcpPacket = packet.get_protocol(tcp)
        srcIp = ipPacket.src
        srcPort = tcpPacket.src_port
        if len(self.tcp_pool)>0:
            LOG.debug("Receive the first TCP packet (tcp_src=%s) from %s to create flows" % (srcPort,srcIp))
            get_tcp_port = self.tcp_pool.pop(0)
            self.tcp_map_io[(srcIp,srcPort)] = get_tcp_port
            #add flow from inner to outer
            match = parser.OFPMatch(in_port=INNER_PORT,
                                     eth_type = ETH_TYPE_IP,
                                     ip_proto = IPPROTO_TCP,
                                     ipv4_src = srcIp,
                                     tcp_src = srcPort
                                     )
            actions = []
            actions.append(parser.OFPActionSetField(ipv4_src=OUTER_IPADDR))
            actions.append(parser.OFPActionSetField(tcp_src=get_tcp_port))
            actions.append(parser.OFPActionOutput(OUTTER_PORT))
            self.add_flow(datapath, 4000, match, actions,
                                  idle_timeout=FLOW_IDLE_TIMEOUT,flags=ofproto.OFPFF_SEND_FLOW_REM)
            #add flow from outer to inner
            match = parser.OFPMatch(in_port=OUTTER_PORT,
                                     eth_type = ETH_TYPE_IP,
                                     ip_proto = IPPROTO_TCP,
                                     ipv4_dst = OUTER_IPADDR,
                                     tcp_dst = get_tcp_port
                                     )
            actions = []
            actions.append(parser.OFPActionSetField(ipv4_dst=srcIp))
            actions.append(parser.OFPActionSetField(tcp_dst=srcPort))
            actions.append(parser.OFPActionOutput( INNER_PORT))
            self.add_flow(datapath, 4000, match, actions)
            LOG.debug( time.asctime() + " : TCP port %s was assigned to map (%r,%r), left %d avaiable" % (get_tcp_port,srcIp,srcPort,len(self.tcp_pool)))
            if msg.buffer_id == OFPCML_NO_BUFFER:
                actions = [parser.OFPActionOutput( OFPP_TABLE)]
                out = parser.OFPPacketOut(
                             datapath=datapath, buffer_id=OFPCML_NO_BUFFER,
                             in_port=INNER_PORT,
                             actions=actions,data=msg.data)
            else:
                actions = [parser.OFPActionOutput( OFPP_TABLE)]
                out = parser.OFPPacketOut(
                            datapath=datapath, buffer_id=msg.buffer_id,
                             in_port=INNER_PORT,
                            actions=actions,data=None)
                datapath.send_msg(out)
            return 0
        else:
            LOG.debug("Packet was dropped since TCP pool was exhausted!")
            return 1
        
         
    def process_udp_pkt(self,msg):
        """
        A new UDP packet should trigger to add two flow entries 
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inPort = msg.match['in_port']
        dpid = datapath.id
        packet = Packet(msg.data)
        
        ipPacket = packet.get_protocol(ipv4)
        udpPacket = packet.get_protocol(udp)
        srcIp = ipPacket.src
        srcPort = udpPacket.src_port
        if len(self.udp_pool)>0:
            LOG.debug("Receive the first UDP packet (udp_src=%s) from %s to create flows" % (srcPort,srcIp))
            get_udp_port = self.udp_pool.pop(0)
            self.udp_map_io[(srcIp,srcPort)] = get_udp_port
            #add flow from inner to outer
            match = parser.OFPMatch(in_port=INNER_PORT,
                                     eth_type = ETH_TYPE_IP,
                                     ip_proto = IPPROTO_UDP,
                                     ipv4_src = srcIp,
                                     udp_src = srcPort
                                     )
            actions = []
            actions.append(parser.OFPActionSetField(ipv4_src=OUTER_IPADDR))
            actions.append(parser.OFPActionSetField(udp_src=get_udp_port))
            actions.append(parser.OFPActionOutput(OUTTER_PORT))
            self.add_flow(datapath, 4000, match, actions,
                                  idle_timeout=FLOW_IDLE_TIMEOUT,flags=ofproto.OFPFF_SEND_FLOW_REM)
            #add flow from outer to inner
            match = parser.OFPMatch(in_port=OUTTER_PORT,
                                     eth_type = ETH_TYPE_IP,
                                     ip_proto = IPPROTO_UDP,
                                     ipv4_dst = OUTER_IPADDR,
                                     udp_dst = get_udp_port
                                     )
            actions = []
            actions.append(parser.OFPActionSetField(ipv4_dst=srcIp))
            actions.append(parser.OFPActionSetField(udp_dst=srcPort))
            actions.append(parser.OFPActionOutput( INNER_PORT))
            self.add_flow(datapath, 4000, match, actions)
            LOG.debug( time.asctime() + " : UDP port %s was assigned to map (%r,%r), left %d avaiable" % (get_udp_port,srcIp,srcPort,len(self.udp_pool)))
            if msg.buffer_id == OFPCML_NO_BUFFER:
                actions = [parser.OFPActionOutput( OFPP_TABLE)]
                out = parser.OFPPacketOut(
                             datapath=datapath, buffer_id=OFPCML_NO_BUFFER,
                             in_port=INNER_PORT,
                             actions=actions,data=msg.data)
            else:
                actions = [parser.OFPActionOutput( OFPP_TABLE)]
                out = parser.OFPPacketOut(
                            datapath=datapath, buffer_id=msg.buffer_id,
                             in_port=INNER_PORT,
                            actions=actions,data=None)
                datapath.send_msg(out)
            return 0
        else:
            LOG.debug("Packet was dropped since UDP pool was exhausted!")
            return 1      
        
    pkt_switch = {IPPROTO_ICMP:process_icmp_pkt,
                       IPPROTO_TCP:process_tcp_pkt,
                       IPPROTO_UDP:process_udp_pkt}
    

    def process_del_icmp(self,msg):
        return 1
             
    def process_del_tcp(self,msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        get_tcp_port = msg.match['tcp_src']
        get_src_ip = msg.match['ipv4_src']
        map_tcp_port = self.tcp_map_io[(get_src_ip,get_tcp_port)]
        if (map_tcp_port in TCP_RESOURCE_LIST) & (map_tcp_port not in self.tcp_pool):
            match = parser.OFPMatch(in_port=OUTTER_PORT,
                                     eth_type = ETH_TYPE_IP,
                                     ip_proto = IPPROTO_TCP,
                                     ipv4_dst = OUTER_IPADDR,
                                     tcp_dst = map_tcp_port
                                     )
            self.delete_flow(datapath,match)
            self.tcp_pool.append(map_tcp_port)
            LOG.debug(time.asctime() + " : TCP port %s was released , left %d avaiable" % (get_tcp_port,len(self.tcp_pool)))
            return 0

    def process_del_udp(self,msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        get_udp_port = msg.match['udp_src']
        get_src_ip = msg.match['ipv4_src']
        map_udp_port = self.udp_map_io[(get_src_ip,get_udp_port)]
        if (map_udp_port in UDP_RESOURCE_LIST) & (map_udp_port not in self.udp_pool):
            match = parser.OFPMatch(in_port=OUTTER_PORT,
                                     eth_type = ETH_TYPE_IP,
                                     ip_proto = IPPROTO_UDP,
                                     ipv4_dst = OUTER_IPADDR,
                                     udp_dst = map_udp_port
                                     )
            self.delete_flow(datapath,match)
            self.udp_pool.append(map_tcp_port)
            LOG.debug(time.asctime() + " : UDP port %s was released , left %d avaiable" % (get_udp_port,len(self.udp_pool)))
            return 0
    
    msg_switch = {IPPROTO_ICMP:process_del_icmp,
                       IPPROTO_TCP:process_del_tcp,
                       IPPROTO_UDP:process_del_udp}
    

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        datapath.id = msg.datapath_id
        ofproto_parser = datapath.ofproto_parser

        set_config = ofproto_parser.OFPSetConfig(
            datapath,
            datapath.ofproto.OFPC_FRAG_NORMAL,
            datapath.ofproto.OFPCML_MAX
        )
        datapath.send_msg(set_config)
        self.install_table_miss(datapath, datapath.id)
        self.install_arp_trans_flow(datapath, datapath.id)
        LOG.debug("It is ready to perform PAT!")

    def install_table_miss(self, datapath, dpid):
        datapath.id = dpid
        match = datapath.ofproto_parser.OFPMatch()
        actions = [datapath.ofproto_parser.OFPActionOutput(
                datapath.ofproto.OFPP_CONTROLLER,
                datapath.ofproto.OFPCML_NO_BUFFER)]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath,
                priority=0,
                buffer_id=0xffffffff,
                match=match,
                instructions=inst)
        datapath.send_msg(mod)
    
    def install_arp_trans_flow(self, datapath, dpid):
        datapath.id = dpid
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=INNER_PORT,
                                eth_type = ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(OUTTER_PORT)]
        self.add_flow(datapath, 65535, match, actions)
        match = parser.OFPMatch(in_port=OUTTER_PORT,
                                 eth_type = ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(INNER_PORT)]
        self.add_flow(datapath, 65535, match, actions)

    def add_flow(self, datapath, priority, match, actions,idle_timeout=0,flags=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,idle_timeout=idle_timeout,flags=flags)
        datapath.send_msg(mod)
        
    def delete_flow(self, datapath,match,out_port=OFPP_ANY, out_group=OFPP_ANY):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
        datapath=datapath, match=match, cookie=0,
        command=ofproto.OFPFC_DELETE,out_port=out_port, out_group=out_group)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        inPort = msg.match['in_port']

        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet)
        if (etherFrame.ethertype == ether.ETH_TYPE_IP) & (inPort==INNER_PORT):
            ipPacket = packet.get_protocol(ipv4)
            srcIp = ipPacket.src
            proto = ipPacket.proto
            assert(proto in self.id_proto)
            if  srcIp in INNER_IPADDR_LIST:
                if proto == IPPROTO_ICMP:
                    self.process_icmp_pkt(msg)
                elif proto == IPPROTO_TCP:
                    self.process_tcp_pkt(msg)
                elif proto == IPPROTO_UDP:
                    self.process_udp_pkt(msg)
            else:        
                LOG.debug("Packet was dropped since source IP %s is illegal!" % srcIp)
                return 1
            

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """
        If the flow entry about inner to outer was timeout  , no doubt that the other flows should be removed immediately.
        """
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            inner_ip = msg.match['ipv4_src']
            proto = msg.match['ip_proto']
            if (inner_ip in INNER_IPADDR_LIST) &  (proto in self.id_proto):
                if proto == IPPROTO_ICMP:
                    self.process_del_icmp(msg)
                elif proto == IPPROTO_TCP:
                    self.process_del_tcp(msg)
                elif proto == IPPROTO_UDP:
                    self.process_del_udp(msg)
     
        
        
        
        
   
