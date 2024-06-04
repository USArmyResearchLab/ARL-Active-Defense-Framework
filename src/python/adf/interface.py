from adf import *

'''Interface requires dpkt+IPy to decode
Tap requires pytun
Pcap requires pypcap
NFQueue requires netfilterqueue'''
try:
    import dpkt
    from IPy import IP
except:
    dpkt = IP = None


class Interface(Plugin):
    '''Raw socket capture/inject class
        if non-*nix, use Pcap(device=...) instead'''
    decode = True  # if 0, disable packet decoding
    if not dpkt or not IP:
        decode = False  # can't decode without dpkt and IPy

    '''we use raw sockets to eliminate the dependency on libpcap (and its read timeouts)
            anything that can be read as a socket (CANbus, etc...) would use similar code'''
    try:
        ETHER_TYPE = 0x0003  # ETH_P_ALL to capture all packets
        SET_SRC_MAC = False  # if true, set emitted packet source MAC to interface MAC
        # linux/if.h
        IFF_PROMISC = 0x0100
        # linux/sockios.h
        SIOCGIFFLAGS = 0x8913  # get the active flags
        SIOCSIFFLAGS = 0x8914  # set the active flags
        SIOCGIFHWADDR = 0x8927  # get hardware address

        def ifctl(self, ctl, fmt, *args):
            import fcntl
            dev = self.device.encode()
            # add ifname to param struct
            param = struct.pack('16s'+fmt, dev, *args)
            # strip ifname and unpack return struct
            return struct.unpack(fmt, fcntl.ioctl(self.__socket, ctl, param)[16:])

        def get_hwaddr(self, dev):
            # return struct will be family, addr[0:14] but we only want addr[:6]
            return self.ifctl(self.SIOCGIFHWADDR, 'H14s', 0, b'')[1][:6]
            
        def set_promisc(self, promisc):
            flags = self.ifctl(self.SIOCGIFFLAGS, 'H', 0)[0]
            if promisc:
                flags |= self.IFF_PROMISC  # turn promisc on
            elif (flags & self.IFF_PROMISC):
                flags ^= self.IFF_PROMISC  # turn promisc off if on
            flags = self.ifctl(self.SIOCSIFFLAGS, 'H', flags)[0]
            return flags

        def main(self):
            '''capture thread, decodes packets and sends them to the next plugin'''
            try:
                self.__socket = socket.socket(
                    socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETHER_TYPE))
                self.__socket.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # set sniff interface, do this before setting promisc
                self.__socket.bind((self.device, 0))
                self.hwaddr = self.get_hwaddr(self.device)
                self.set_promisc(True)  # interface promisc on

                while not self.is_shutdown():  # capture loop
                    try:
                        # this must be set before every read
                        self.__socket.settimeout(1)
                        try:
                            packetdata, sll = self.__socket.recvfrom(65536)
                        except socket.timeout:
                            continue  # no packet, no problem
                        if sll[2] == socket.PACKET_OUTGOING:
                            continue  # we don't want to capture injected packets
                        if sll[0] != self.device:
                            continue  # between socket creation and bind we may get a few packets from the wrong interface so discard them
                    # fatal capture error (interface went down?)
                    except Exception as e:
                        self.error(e)
                        break  # stop capture loop
                    try:
                        # get back packet info and dpkt obj
                        info, packet = self._decode(time.time(), packetdata)
                        self.dispatch(info, packet)  # send the decoded packet
                    except Exception as e:  # decode/dispatch errors are not fatal, do not stop capturing
                        self.warning(e)

                self.set_promisc(False)  # interface promisc off
                self.__socket.close()

            except Exception as e:  # startup failed
                self.error(e)

        def handle_packet(self, info, packet, **kwargs):
            '''if we are handed a packet, inject it on the wire'''
            if self.__socket and packet and self.filter_packet(info, packet):
                if self.metrics:
                    self._metrics(info)
                try:
                    if self.SET_SRC_MAC:
                        packet.src = self.hwaddr
                    return self.__socket.send(bytes(packet))
                except Exception as e:
                    self.warning(e)

    except:
        pass  # a dep is not available, can't raw capture/inject but try to provide decoding

    def _decode(self, ts, packet, info=None):
        '''decode packets headers down to TCP/UDP ports, return info and dpkt object'''
        # init info if not passed in
        if info is None:
            info = {'source': self.name,
                    'ts': ts,
                    'len': len(packet)}   # init to capture info
        if int(self.decode):  # if not decoding, return capture info and raw packet
            try:
                # decode packet as ether
                packet = dpkt.ethernet.Ethernet(packet)
                info.update(smac=packet.src, dmac=packet.dst,
                            etype=packet.type)
                try:
                    info.update(vlan=packet.tag)  # get vlan tag
                except:
                    pass  # no VLAN tag
                l3 = packet.data  # drill down to layer 3
                if packet.type == dpkt.ethernet.ETH_TYPE_ARP:  # parse IP addrs out of ARP
                    info.update(proto='arp',
                                sip=IP(socket.inet_ntop(
                                    socket.AF_INET, l3.spa)),
                                dip=IP(socket.inet_ntop(socket.AF_INET, l3.tpa)))
                elif packet.type == dpkt.ethernet.ETH_TYPE_IP:  # parse IPv4 header
                    info.update(proto=l3.p,
                                sip=IP(socket.inet_ntop(
                                    socket.AF_INET, l3.src)),
                                dip=IP(socket.inet_ntop(socket.AF_INET, l3.dst)))
                elif packet.type == dpkt.ethernet.ETH_TYPE_IP6:  # parse IPv6 header
                    info.update(proto=l3.nxt,
                                sip=IP(socket.inet_ntop(
                                    socket.AF_INET6, l3.src)),
                                dip=IP(socket.inet_ntop(socket.AF_INET6, l3.dst)))
                else:  # not IP or ARP, stop here and return layer 3 as data
                    info.update(data=l3)
                    return info, packet
                # add protocol data to info
                info.update(data=self._decode_l4(l3, info))
            except Exception as e:
                self.debug(e, exc_info=True)  # ether decoding error
        return info, packet  # return info and packet

    def _decode_l4(self, l3, info):
        # decode TCP/UDP
        try:
            # clear checksums
            l3.sum = 0  # IP hdr checksum
            l4 = l3.data  # get TCP
            l4.sum = 0  # TCP/UDP checksum
            # parse layer 4 header as TCP or UDP
            info.update(sport=l4.sport, dport=l4.dport)
            data = l4.data  # data = protocol data
            # get TCP info
            try:
                info.update(flags=l4.flags, seq=l4.seq,
                            ack=l4.ack, win=l4.win)
            except:
                pass
        except:
            data = l3.data  # IP but not TCP/UDP
        return data


try:
    import pytun
    import select
    from binascii import unhexlify

    class Tap(Interface):
        '''create virtual interface'''

        def main(self):
            '''capture thread, decodes packets and sends them to the next plugin'''
            if self.device:
                self.__tap = pytun.TunTapDevice(
                    flags=pytun.IFF_TAP | pytun.IFF_NO_PI, name=self.device)
            else:
                self.__tap = pytun.TunTapDevice(

                    flags=pytun.IFF_TAP | pytun.IFF_NO_PI)
            self.device = bytes(self.__tap.name, 'ascii')
            if self.hwaddr:
                self.__tap.hwaddr = unhexlify(self.hwaddr.replace(':', ''))
            if self.addr:
                self.__tap.addr = self.addr
            if self.netmask:
                self.__tap.netmask = self.netmask
            if not self.mtu:
                self.mtu = 1514
            self.__tap.mtu = int(self.mtu)
            self.__tap.up()
            while not self.is_shutdown():
                try:
                    ready = select.select([self.__tap], [], [], 1)
                    if not ready[0]:
                        continue
                    packetdata = self.__tap.read(self.__tap.mtu)
                    ts = time.time()
                    # get back packet info and dpkt obj
                    info, packet = self._decode(ts, packetdata)
                    self.dispatch(info, packet)  # send the decoded packet
                except Exception as e:  # capture error (interface went down?)
                    self.error(e, exc_info=True)
                    break  # stop capture loop
            # interface promisc off
            self.__tap.down()
            self.__tap.close()

        def handle_packet(self, info, packet, **kwargs):
            '''if we are handed a packet, inject it on the wire'''
            if self.__tap and packet and self.filter_packet(info, packet):
                if self.metrics:
                    self._metrics(info)
                try:
                    if self.SET_SRC_MAC:
                        packet.src = self.__tap.addr
                    self.__tap.write(bytes(packet))
                except Exception as e:
                    self.warning(e)

except:
    pass  # no pytun, can't use Tap interfaces

try:
    import pcap

    class Pcap(Interface):
        '''pypcap-basesd capture/read/write class
            config: pcap_in = filename to read
                    pcap_out = filename to write
                     - or -
                    device = interface to capture/inject on
                        supports non-linux if you have pypcap, but...
                        may get stuck in timeout on a quiet interface, 
                        recommend using the raw sockets with the Interface plugin'''
        decode = 1  # if 0, disable packet decoding
        pcap = None
        device = None
        pcap_fh = None
        pcap_in = None
        pcap_out = None
        timeout_ms = 1
        delta = False

        def open_pcap(self):
            self.pcap = pcap.pcap(self.pcap_in)
            self.info('reading from %s', self.pcap_in)

        def open_interface(self):
            self.pcap = pcap.pcap(
                self.device, timeout_ms=self.timeout_ms, immediate=True)

        def main(self):
            '''capture thread, decodes packets and sends them to the next plugin'''
            try:
                while not self.pcap and not self.is_shutdown():
                    if self.device:
                        self.open_interface()
                    elif self.pcap_in:
                        self.open_pcap()
                    else:
                        time.sleep(1)
            except Exception as e:
                self.error(e)
            if self.pcap:
                last_ts = None
                while not self.is_shutdown():
                    for ts, packetdata in self.pcap.readpkts():
                        if self.is_shutdown():
                            break
                        try:
                            # get back packet info and dpkt obj
                            info, packet = self._decode(ts, packetdata)
                            if self.pcap_in and self.delta and ts:
                                if last_ts is not None:
                                    time.sleep(max(0, ts-last_ts))
                                last_ts = ts
                            # send the decoded packet
                            self.dispatch(info, packet)
                        except Exception as e:  # read error
                            self.error(repr(e), exc_info=True)
                            break
                    if self.pcap_in:
                        self.info('finished reading %s', self.pcap_in)
                        break
                del self.pcap
            self.stop()

        def handle_packet(self, info, packet, **kwargs):
            '''if we are handed a packet, inject it on the wire'''
            if packet and self.filter_packet(info):
                if self.metrics:
                    self._metrics(info)
                try:
                    if self.device:
                        if self.pcap:
                            self.pcap.sendpacket(bytes(packet))
                    else:
                        if not self.pcap_fh:
                            if self.pcap_out:
                                self.pcap_fh = open(self.pcap_out, 'wb')
                                # generic pcap header
                                self.pcap_fh.write(struct.pack(
                                    'IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                                self.info('writing to '+self.pcap_out)
                        if self.pcap_fh:
                            ts = int(info['ts'])
                            uts = int(info['ts']-float(ts))*1000000
                            data = bytes(packet)
                            self.pcap_fh.write(struct.pack(
                                'IIII', ts, uts, len(data), len(data))+data)
                except Exception as e:
                    self.warning(repr(e), exc_info=True)

        def stop(self):
            if self.pcap_fh:
                del self.pcap_fh
            Interface.stop(self)

except:
    pass  # no pypcap support


try:
    from netfilterqueue import NetfilterQueue

    class NFQueue(Interface):
        '''Netfilter Queue interface
        for use with iptables rules like 

iptables -I INPUT -i eth0 -j NFQUEUE --queue-num 1

        or nftables rules like 

table inet filter {
        chain input {
                type filter hook input priority filter; policy accept;
                iif "eth0" queue to 1
        }

        chain forward {
                type filter hook forward priority filter; policy accept;
        }

        chain output {
                type filter hook output priority filter; policy accept;
        }
}
table arp filter {
        chain input {
                type filter hook input priority filter; policy accept;
                iif "eth0" queue to 1
        }
}

        config: device=queue-num
        info will have nfq_packet object + decode and packet will be dpkt object with plugin-generated layer 2 header
         (source MAC and protocol will be valid but dest MAC will be zeros.)
        on dispatch back to this interface, payload will be set to packet object (minus the layer 2 header) and accepted
          (unless packet is None or drop=True in info)
        '''

        def accept(self, packet):
            # called by nfq when we get a packet
            try:
                # decode the packet, putting the nfq packet object in info
                info, packet = self._decode(time.time(), packet)
                self.dispatch(info, packet)  # send the decoded packet
            except Exception as e:  # decode/dispatch errors are not fatal, do not stop capturing
                self.warning(e)

        def handle_packet(self, info, payload, **kwargs):
            '''if we are handed a packet, return it to NFQ'''
            if self.__nfq and payload and self.filter_packet(info, payload):
                if self.metrics:
                    self._metrics(info)
                try:
                    packet = info.get('nfq_packet')
                    # drop packets set to drop or with no payload
                    if info.get('drop') or not payload:
                        packet.drop()
                    # strip the layer 2 header we generated, update the nfq payload and accept it.
                    packet.set_payload(bytes(payload.data))
                    return packet.accept()
                except Exception as e:
                    self.warning(e)

        def main(self):
            self.__nfq = NetfilterQueue()
            self.__nfq.bind(int(self.device), self.accept)
            nfq_sock = socket.fromfd(
                self.__nfq.get_fd(), socket.AF_NETLINK, socket.SOCK_RAW)
            # run until shutdown
            while not self.is_shutdown():
                nfq_sock.settimeout(1)
                try:
                    self.__nfq.run_socket(nfq_sock)
                except socket.timeout:
                    continue
            # unbind
            self.__nfq.unbind()

        def _decode(self, ts, packet):
            '''decode packets headers down to TCP/UDP ports, return info and dpkt object'''
            # save the nfq packet object in the info
            info = {'nfq_packet': packet,
                    'source': self.name,
                    'ts': ts,
                    'len': packet.get_payload_len()}  # init to capture info, add 14 bytes for the layer 2 header
            if int(self.decode):  # if not decoding, return capture info and raw packet
                try:
                    # packets from nfq start at layer 3 so we need to prepend a layer 2 header
                    # we do not know the dest mac so leave it zeroed
                    info['len'] += 14
                    packet = dpkt.ethernet.Ethernet(
                        src=packet.get_hw(), etype=packet.hw_protocol, data=packet.get_payload())
                    # decode packet using Interface _decode
                    info, packet = super()._decode(ts, bytes(packet), info)
                except Exception as e:
                    self.debug(e, exc_info=True)  # decoding error
            return info, packet  # return info and packet as dpkt object
except:
    pass  # no NFQUEUE support


def test(infile=None, outfile=None):
    '''Interface test harness
    If no args, creates Pcap<>Tun<--kernel-->Tun<>Raw chain and juggles some packets to test 
        (must test with root privs to pass this)
    If args, reads PCAP from first arg, writes PCAP to second args (if given)'''
    import os
    import logging
    PACKET = bytes([0x55]*6+[0xaa]*6+[0x55, 0xaa])  # fake ethernet header

    class Dump(Plugin):
        def effect(self, info, pkt, **kwargs):
            if info.get('etype') == 21930:
                self.event(packet=info)
            print(info)
            return info, pkt
    f = Framework()
    if not infile:  # test raw interface, Tap, and Pcap modules
        # create taps
        t1 = f.start_plugin(Tap, name='tap1', device='tap1')
        t2 = f.start_plugin(Tap, name='tap2', device='tap2')
        time.sleep(1)
        # create PCAP and raw interfaces
        i1 = f.start_plugin(Interface, name='raw1', device='tap1')
        i2 = f.start_plugin(Interface, name='raw2', device='tap2')
        td = f.start_plugin(Dump, name='tapdump')
        pd = f.start_plugin(Dump, name='pcapdump')
        # dump and forward between taps
        f.link_plugin('tapdump', 'tap1', 'tap2')
        # dump traffic at interfaces but do not forward
        f.link_plugin('raw1', 'pcapdump:0')
        f.link_plugin('raw2', 'pcapdump:0')
        # create traffic, and wait for event saying we got it
        f.lock()
        # we should see each packet twice, as each end of the tap will get it and send it to the other interface
        # this tests send/receive on all interface types
        for i in (i1, i2):
            i.inject({}, PACKET)
            f.handle_event(True)
            f.handle_event(True)
        f.unlock()
        # verify all stops properly at framework shutdown
    else:  # test PCAP file read/write
        pcap1 = f.start_plugin(Pcap, name='pcap1', delta=1)
        pd = f.start_plugin(Dump, name='pcapdump')
        f.link_plugin('pcap1', 'pcapdump')
        if outfile:
            pcap2 = f.start_plugin(Pcap, name='pcap2', pcap_out=outfile)
            f.link_plugin('pcapdump', 'pcap2')
        pcap1.config(pcap_in=infile)
        pcap1.join()
    f.stop()


if __name__ == '__main__':

    import sys
    import logging
    logging.basicConfig(level=logging.DEBUG)
    test(*sys.argv[1:])
