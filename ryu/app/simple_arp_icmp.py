
import logging

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
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet

LOG = logging.getLogger('simple_arp_icmp')
LOG.setLevel(logging.DEBUG)
logging.basicConfig()

HOST_IPADDR1 = "192.168.0.1"
HOST_IPADDR_LIST1 =  ["192.168.0."+str(x) for x in range(2,254)]
ROUTER_IPADDR1 = "192.168.0.1"
ROUTER_MACADDR1 = "00:00:00:00:00:01"
ROUTER_PORT1 = 1
ROUTER_PORT2 = 2


class SimpleArpIcmp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    HOST_MACADDR1 = None
    HOST_MACADDR2 = None

    def __init__(self, *args, **kwargs):
        super(SimpleArpIcmp, self).__init__(*args, **kwargs)
        self.ip_to_mac = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        datapath.id = msg.datapath_id
        ofproto_parser = datapath.ofproto_parser

        set_config = ofproto_parser.OFPSetConfig(
            datapath,
            datapath.ofproto.OFPC_FRAG_NORMAL,
            datapath.ofproto.OFPCML_MAX
        )
        datapath.send_msg(set_config)
        self.install_table_miss(datapath, datapath.id)


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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        inPort = msg.match['in_port']
        dpid = datapath.id
        self.ip_to_mac.setdefault(dpid, {})

        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet)
        srcMAC = etherFrame.src
        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            self.receive_arp(datapath, packet, etherFrame, inPort)
            return 0
        elif etherFrame.ethertype == ether.ETH_TYPE_IP:
            ipPacket = packet.get_protocol(ipv4)
            srcIp = ipPacket.src
            if (ipPacket.proto==IPPROTO_ICMP) & (self.ip_to_mac[dpid][srcIp] == srcMAC):
                self.receive_icmp(datapath, packet, etherFrame, inPort)
                return 0
            elif (ipPacket.proto==IPPROTO_ICMP) :
                self.send_arp(datapath, ARP_REQUEST,ROUTER_MACADDR1, ROUTER_IPADDR1,  "ff:ff:ff:ff:ff:ff", srcIp, inPort)
        else:
            LOG.debug("Drop packet")
            return 1

    def receive_arp(self, datapath, packet, etherFrame, inPort):
        arpPacket = packet.get_protocol(arp)
        dpid = datapath.id
        if arpPacket.opcode == ARP_REQUEST:
            arp_dstIp = arpPacket.dst_ip
            arp_srcIp = arpPacket.src_ip
            src_mac  = arpPacket.src_mac
            LOG.debug("receive ARP request %s => %s (port%d)"
                       %(etherFrame.src, etherFrame.dst, inPort))
            self.reply_arp(datapath, etherFrame, arpPacket,inPort)
        elif arpPacket.opcode == ARP_REPLY:
            pass
        self.ip_to_mac[dpid][arp_srcIp] = src_mac

    def receive_icmp(self, datapath, packet, etherFrame, inPort):
        ipPacket = packet.get_protocols(ipv4)[0]
        icmpPacket = packet.get_protocols(icmp)[0]
        icmpPacket.type = icmpPacket.type
        if icmpPacket.type == ICMP_ECHO_REQUEST:
            LOG.debug("receive ICMP request %s => %s (port%d)"
                       %(ipPacket.src,  ipPacket.dst, inPort))
            self.reply_icmp(datapath, etherFrame,ipPacket, icmpPacket,inPort)
        else:
            pass

    def reply_icmp(self, datapath, etherFrame, ipPacket,icmpPacket,inPort):
        dstIp = ipPacket.dst
        srcIp = ipPacket.src
        dstMac = etherFrame.src
        if (dstIp == ROUTER_IPADDR1) & (srcIp in HOST_IPADDR_LIST1):
            srcMac = ROUTER_MACADDR1
            outPort = ROUTER_PORT1
        else:
            LOG.debug("unknown arp requst received !")
        self.send_icmp(datapath,  etherFrame,ipPacket, icmpPacket,inPort)
        LOG.debug("send ICMP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))

    def reply_arp(self, datapath, etherFrame, arpPacket,inPort):
        dstIp = arpPacket.dst_ip
        srcIp = arpPacket.src_ip
        dstMac = etherFrame.src
        if (dstIp == ROUTER_IPADDR1) & (srcIp in HOST_IPADDR_LIST1):
            LOG.debug("receive ARP request from %s  to request %s " %(srcIp, dstIp))
            srcMac = ROUTER_MACADDR1
            outPort = ROUTER_PORT1
        else:
            LOG.debug("unknown arp requst received !")

        self.send_arp(datapath, 2, srcMac, dstIp, dstMac, srcIp, outPort)
        LOG.debug("send ARP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)
        
    def send_icmp(self, datapath,  etherFrame,ipPacket, icmpPacket,inPort):
        e = ethernet(dst=etherFrame.src ,
                                     src=etherFrame.dst,
                                     ethertype=ether.ETH_TYPE_IP)
        a = ipv4(version=ipPacket.version, header_length=ipPacket.header_length, tos=ipPacket.tos,
                 total_length=ipPacket.total_length, identification=ipPacket.identification, flags=ipPacket.flags,
                 offset=ipPacket.offset, ttl=ipPacket.ttl, proto=ipPacket.proto, csum=ipPacket.csum,
                 src=ipPacket.dst,
                 dst= ipPacket.src,
                 option=None)
        b = icmp( type_=ICMP_ECHO_REPLY, code=icmpPacket.code, csum=icmpPacket.csum, data=icmpPacket.data)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.add_protocol(b)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(inPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)
