from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import *

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
	
    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        #self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=data)
        datapath.send_msg(out)
	
    def _find_outport(self, src, dst, sw_id, protocol):
        path = [[0,2,0,3],[3,0,2,0],[0,3,0,2],[2,0,3,0]]
        if dst == sw_id:
            out_port=1
            return out_port
        if protocol == "TCP" or "ICMP":
            out_port = path[src-1][dst-1]
            if out_port == 0:
                out_port = 2
        if protocol == "UDP":
            out_port = path[src-1][dst-1]
            if out_port == 0:
                out_port = 3
        return out_port

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src       

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        address = ['10:00:00:00:00:01','10:00:00:00:00:02', '10:00:00:00:00:03','10:00:00:00:00:04','ff:ff:ff:ff:ff:ff']
        if ( src not in address ) or ( dst not in address ):
            return

        pkt_arp = pkt.get_protocol(arp.arp)    
        pkt_ipv4= pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        


        if pkt_arp:    
            print("[ARP] arrive at ", datapath.id, dst)        
            if pkt_arp.opcode==arp.ARP_REQUEST:
                mac_dst="10:00:00:00:00:0"+pkt_arp.dst_ip[-1]
	   
                mypkt = packet.Packet()
                mypkt.add_protocol(ethernet.ethernet(ethertype = eth.ethertype, src = mac_dst, dst = src ))
                mypkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=mac_dst, dst_mac=pkt_arp.src_mac, src_ip=pkt_arp.dst_ip, dst_ip=pkt_arp.src_ip))
                self._send_packet(datapath, 1, mypkt)
	
        elif pkt_icmp:
            print("[ICMP] arrive at", datapath.id, dst)
            
            out_port=self._find_outport(int(src[-1]), int(dst[-1]), datapath.id, 'ICMP')
            icmp_match = parser.OFPMatch(eth_type=0x0800,in_port=in_port, ip_proto=1, eth_dst= dst, eth_src = src)
            icmp_actions=[parser.OFPActionOutput(port=out_port)]
            self.add_flow(datapath, 1, icmp_match,icmp_actions)
            self._send_packet(datapath, out_port, pkt)
        elif pkt_tcp:
            if (int(src[-1])==2 or int(src[-1])==4) and (pkt_tcp.dst_port == 80):
                mypkt = packet.Packet()
                mypkt.add_protocol(ethernet.ethernet(ethertype = eth.ethertype, src = dst, dst = src ))
                mypkt.add_protocol(ipv4.ipv4(src=pkt_ipv4.dst,dst=pkt_ipv4.src,proto=6))
                mypkt.add_protocol(tcp.tcp(src_port=pkt_tcp.dst_port,dst_port=pkt_tcp.src_port,ack=pkt_tcp.seq+1,bits=0b010100))
                self._send_packet(datapath, 1, mypkt)
                print("TCP: Reject connection")
            else:
                print("[TCP] arrive at", datapath.id, dst)
                out_port=self._find_outport(int(src[-1]), int(dst[-1]), datapath.id, 'TCP')
                match = parser.OFPMatch(eth_type=0x0800,in_port=in_port, ip_proto=6, eth_dst= dst, eth_src = src)
                actions=[parser.OFPActionOutput(port=out_port)]
                self.add_flow(datapath, 1, match,actions)
                self._send_packet(datapath, out_port, pkt)
        elif pkt_udp:
            if (int(src[-1])==1 or int(src[-1])==4):
                print("[UDP] drop!")
                match = parser.OFPMatch(eth_type=0x0800,in_port=in_port, ip_proto=17, eth_dst= dst, eth_src = src)
                actions=[]
                self.add_flow(datapath, 1, match,actions)
            else:
                print("[UDP] arrive at", datapath.id, dst)
                out_port=self._find_outport(int(src[-1]), int(dst[-1]), datapath.id, 'UDP')
                match = parser.OFPMatch(eth_type=0x0800,in_port=in_port, ip_proto=17, eth_dst= dst, eth_src = src)
                actions=[parser.OFPActionOutput(port=out_port)]
                self.add_flow(datapath, 1, match,actions)
                self._send_packet(datapath, out_port, pkt)





