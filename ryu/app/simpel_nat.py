

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
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import *
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.icmp import *
from ryu.lib.packet.in_proto import *
from ryu.lib.packet.ether_types import *
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3  import * 
from ryu.ofproto import ether
from ryu.ofproto import inet

LOG = logging.getLogger('SimpleNat')
LOG.setLevel(logging.DEBUG)
logging.basicConfig()


INNER_IPADDR_LIST =  ["192.168.0."+str(x) for x in range(2,254)]
OUTER_IPADDR_LIST =  ["181.27.0."+str(x) for x in range(2,5)]
FLOW_IDLE_TIMEOUT = 60
INNER_PORT = 5
OUTTER_PORT = 6


class SimpleNat(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleNat, self).__init__(*args, **kwargs)
        self.address_pool = OUTER_IPADDR_LIST[:]
        self.inner_map_outer={}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        datapath.id = msg.datapath_id
        ofproto_parser = datapath.ofproto_parser
        self.inner_map_outer.setdefault(datapath.id, {})

        set_config = ofproto_parser.OFPSetConfig(
            datapath,
            datapath.ofproto.OFPC_FRAG_NORMAL,
            datapath.ofproto.OFPCML_MAX
        )
        datapath.send_msg(set_config)
        self.install_table_miss(datapath, datapath.id)
        self.install_arp_trans_flow(datapath, datapath.id)
        LOG.debug("It is ready to perform NAT!")

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
                                                                    eth_type = ETH_TYPE_ARP
                                                                    )
        actions = [parser.OFPActionOutput(OUTTER_PORT,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 65535, match, actions)
        match = parser.OFPMatch(in_port=OUTTER_PORT,
                                                                    eth_type = ETH_TYPE_ARP
                                                                    )
        actions = [parser.OFPActionOutput(INNER_PORT,ofproto.OFPCML_NO_BUFFER)]
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
        
    def delete_flow(self,datapath,match,out_port=OFPP_ANY, out_group=OFPP_ANY):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
        datapath=datapath, match=match, cookie=0,
        command=ofproto.OFPFC_DELETE,out_port=out_port, out_group=out_group)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inPort = msg.match['in_port']
        dpid = datapath.id

        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet)
        if (etherFrame.ethertype == ether.ETH_TYPE_IP) & (inPort==INNER_PORT):
            ipPacket = packet.get_protocol(ipv4)
            srcIp = ipPacket.src
            dstIp = ipPacket.dst
            if srcIp in INNER_IPADDR_LIST:
                if len(self.address_pool)>0:
                    LOG.debug("Receive the first IP pacekt %s => %s to create flows" % (srcIp,dstIp))
                    get_ip = self.address_pool.pop(0)
                    self. inner_map_outer[dpid][srcIp] = get_ip
                    #add flow from inner to outer
                    match = parser.OFPMatch(in_port=INNER_PORT,
                                            eth_type = ETH_TYPE_IP,
                                            ipv4_src = srcIp
                                            )
                    actions = []
                    actions.append(parser.OFPActionSetField(ipv4_src=get_ip))
                    actions.append(parser.OFPActionOutput(OUTTER_PORT))
                    self.add_flow(datapath, 4000, match, actions,
                                  idle_timeout=FLOW_IDLE_TIMEOUT,flags=ofproto.OFPFF_SEND_FLOW_REM)
                    #add flow from outer to inner
                    match = parser.OFPMatch(in_port=OUTTER_PORT,
                                            eth_type = ETH_TYPE_IP,
                                            ipv4_dst = get_ip
                                            )
                    actions = []
                    actions.append(parser.OFPActionSetField(ipv4_dst=srcIp))
                    actions.append(parser.OFPActionOutput( INNER_PORT))
                    self.add_flow(datapath, 4000, match, actions)
                    LOG.debug( time.asctime() + " : IP %s was assigned , left %d avaiable" % (get_ip,len(self.address_pool)))
                    #packet_out the original data with the same buffer_id as it was packet_in,so it could goto table
                    if msg.buffer_id == OFPCML_NO_BUFFER:
                        actions = [parser.OFPActionOutput( OFPP_TABLE) ]
                        out = parser.OFPPacketOut(
                                                                   datapath=datapath, buffer_id=msg.buffer_id,
                                                                    in_port=INNER_PORT,
                                                                   actions=actions,data=msg.data)
                    else:
                        actions = [parser.OFPActionOutput( OFPP_TABLE) ]
                        out = parser.OFPPacketOut(
                                                                   datapath=datapath, buffer_id=msg.buffer_id,
                                                                    in_port=INNER_PORT,
                                                                   actions=actions,data=None)
                        datapath.send_msg(out)
                    return 0
                else:
                    LOG.debug("Packet %s => %s was dropped since NAT pool was exhausted!" % (srcIp,dstIp))
                    return 1
            else:        
                LOG.debug("Packet was dropped since source IP %s is illegal!" % srcIp)
                return 1

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """
        If the flow entry about inner to outer was timeout  , no doubt that the other flows should be removed immediately.
        """
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            inner_ip = msg.match['ipv4_src']
            if inner_ip in INNER_IPADDR_LIST:
                outer_ip = self.inner_map_outer[dpid].pop(inner_ip)
                self.address_pool.append(outer_ip)
                match = parser.OFPMatch(in_port=OUTTER_PORT,
                                            eth_type = ETH_TYPE_IP,
                                            ipv4_dst = outer_ip
                                            )
                self.delete_flow(datapath,match)
                LOG.debug( time.asctime() + " : IP %s was released , left %d avaiable" % (outer_ip,len(self.address_pool)))

   
   
