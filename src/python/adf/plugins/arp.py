#!/usr/bin/env python
import binascii
from adf import *


class ARP(Plugin):
    '''generate ARP replies where filter matches 
            (e.g.: filter="info['proto']=='arp' and str(info['dip'])=='x.x.x.x'")
       ip=<ip to generate filter from>
       mac=<mac address to reply with>'''

    def config(self, *args, **kwargs):
        r = Plugin.config(self, *args, **kwargs)
        if self.mac:
            self.__bin_mac = binascii.unhexlify(self.mac.replace(':', ''))
        if self.ip:
            self.filter = "info['proto']=='arp' and str(info['dip'])=='%s'" % self.ip
        return r

    def effect(self, pktinfo, pkt):
        '''if we get here, we saw an ARP request for an IP we handle
           so craft an ARP reply saying we're here'''
        self.debug(' in '+repr(pkt))
        pkt.arp.op = 2  # ARP reply
        pkt.arp.tha = pkt.arp.sha  # reply to sender
        pkt.dst = pkt.src  # reply to sender
        # MAC to answer with
        pkt.src = pkt.arp.sha = self.__bin_mac
        pkt.arp.spa, pkt.arp.tpa = pkt.arp.tpa, pkt.arp.spa  # swap source/target IPs
        self.debug(' out '+repr(pkt))
        pktinfo['dest'], pktinfo['source'] = pktinfo['source'], self.name
        return pktinfo, pkt
