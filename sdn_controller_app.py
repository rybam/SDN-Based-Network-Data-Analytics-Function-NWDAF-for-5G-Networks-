# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function

import array
import datetime
from random import randint

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import snortlib
from ryu.lib.packet import in_proto
from ryu.lib import hub


class SimpleSwitchSnort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.mirror_bridge_dpid = 8796747973215 # id of switch that is used to mirror traffic to Snort
        self.snort_port = 2 # port id on switch that is connected to Snort
        self.mac_to_port = {}
        self.datapaths = {}
        self.query_interval = 0.01 # the time interval with which requests for flow information are sent to change the flow being monitored
        self.current_match = None
        self.current_out_port = None
        self.current_priority = 1
        self.mirroring_status = False
        self.monitor_network = 2 # 0 - no monitoring, 1 - monitoring traffic from all flows, 2 - monitoring single flow

        socket_config = {'unixsock': False}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
        
        # in order to change flow being monitored in the time interval, a thread which will requests flow information has to be spawned
        if self.monitor_network == 2:
          self.monitor_thread = hub.spawn(self._monitor)
          
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                if dp.id == self.mirror_bridge_dpid:
                    self._request_stats(dp)
            hub.sleep(self.query_interval)

    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if eth:
            self.logger.info("%r", eth)

        # for p in pkt.protocols:
        #     if hasattr(p, 'protocol_name') is False:
        #         break
        #     print('p: %s' % p.protocol_name)
        
        
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.info('register datapath: %s', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %s', datapath.id)
                del self.datapaths[datapath.id]
                
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
        # correctly.
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # Handler for receipt of flow statistics. Statistics are used to get list of flows on specified switch and change monitored flow

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath          
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # change monitored flow only if there are flows installed other than default flow to controller
        if len(ev.msg.body) > 2:
            
           # If you want to monitor only first flow intalled on the switch and stop modifying monitored flow uncomment lines 144 and 173 and comment lines 145-156
           #flow_id = 1
           flow_id = randint(0, len(ev.msg.body)-2) #do not take default flow to controller         
           if self.mirroring_status:
               
               actions = [parser.OFPActionOutput(self.current_out_port)]
               
               inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                    actions)]                                                 
                           
               mod = parser.OFPFlowMod(datapath=datapath, priority=self.current_priority,
                                       match=self.current_match, instructions=inst)

               datapath.send_msg(mod)  
           
           try:
               self.current_match = ev.msg.body[flow_id].match
               self_current_priority = ev.msg.body[flow_id].priority
               self.current_out_port = ev.msg.body[flow_id].instructions[0].actions[0].port
               actions = [parser.OFPActionOutput(self.current_out_port),
                         parser.OFPActionOutput(self.snort_port)] #modify flow entry by adding second port used to send packets to Snort
               
               inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                    actions)]                                                 
                           
               mod = parser.OFPFlowMod(datapath=datapath, priority=self.current_priority,
                                       match=self.current_match, instructions=inst)

               datapath.send_msg(mod)
               self.mirroring_status = True
               #hub.kill(self.monitor_thread)
               
           except:
               self.mirroring_status = False

    # Print Snort alert along with packet info
    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        print('alertmsg: %s' % ''.join(msg.alertmsg[0].decode('utf-8')[0:-1]))
        self.packet_print(msg.pkt)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
              
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]                                                 
        if datapath.id == self.mirror_bridge_dpid:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
    
        #pkt = packet.Packet(array.array('B', ev.msg.data))
        #print(pkt.protocols)
        #for p in pkt.protocols:
        #    print(p)
        
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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        if self.monitor_network == 0 or self.monitor_network == 2:
            actions = [parser.OFPActionOutput(out_port)]
        elif self.monitor_network == 1:
            actions = [parser.OFPActionOutput(out_port),
                       parser.OFPActionOutput(self.snort_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=srcip,
                                        ipv4_dst=dstip
                                        )
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
