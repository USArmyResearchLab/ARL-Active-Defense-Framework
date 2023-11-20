from adf import *

'''Interface requires ctypes to capture/inject and dpkt+IPy to decode
Tap requires pytun
Pcap requires pypcap'''
try:
    import ctypes
except:
    pass
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
        ETHER_TYPE = 0x0003  # ETH_P_ALL

        class ifctl(ctypes.Structure):
            '''shim class to handle setting interfaces to promisc mode'''
            # linux/if.h
            IFF_PROMISC = 0x100
            # linux/sockios.h
            SIOCGIFFLAGS = 0x8913  # get the active flags
            SIOCSIFFLAGS = 0x8914  # set the active flags
            _fields_ = [
                ("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)
            ]

            def __init__(self, socket, dev):
                self.__socket = socket
                self.__dev = dev.encode()
                ctypes.Structure.__init__(self)

            def set_promisc(self, promisc):
                import fcntl
                self.ifr_ifrn = self.__dev
                fcntl.ioctl(self.__socket, self.SIOCGIFFLAGS,
                            self)  # get interface flags
                if promisc:
                    self.ifr_flags |= self.IFF_PROMISC  # turn promisc on
                elif (self.ifr_flags & self.IFF_PROMISC):
                    self.ifr_flags ^= self.IFF_PROMISC  # turn promisc off if on
                fcntl.ioctl(self.__socket, self.SIOCSIFFLAGS,
                            self)  # set interface flags
                return self.ifr_flags

        def main(self):
            '''capture thread, decodes packets and sends them to the next plugin'''
            try:
                self.__socket = socket.socket(
                    socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETHER_TYPE))
                self.__socket.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # set sniff interface, do this before setting promisc
                self.__socket.bind((self.device, 0))
                ifctl = self.ifctl(self.__socket, self.device)
                ifctl.set_promisc(True)  # interface promisc on

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

                ifctl.set_promisc(False)  # interface promisc off
                self.__socket.close()

            except Exception as e:  # startup failed
                self.error(e)

        def handle_packet(self, info, packet, **kwargs):
            '''if we are handed a packet, inject it on the wire'''
            if self.__socket and packet and self.filter_packet(info, packet):
                if self.metrics:
                    self._metrics(info)
                try:
                    return self.__socket.send(bytes(packet))
                except Exception as e:
                    self.warning(e)

    except:
        pass  # ctypes not available, can't raw capture/inject but try to provide decoding

    def _decode(self, ts, packet):
        '''decode packets headers down to TCP/UDP ports, return info and dpkt object'''
        info = {'source': self.name, 'ts': ts,
                'len': len(packet)}  # init to capture info
        if int(self.decode):  # if not decoding, return capture info and raw packet
            try:
                packet = dpkt.ethernet.Ethernet(
                    packet)  # decode packet as ether
                info.update(smac=packet.src, dmac=packet.dst,
                            etype=packet.type)
                try:
                    info.update(vlan=packet.tag)  # get vlan tag
                except:
                    pass  # no VLAN tag
                d = packet.data  # drill down to layer 3
                if packet.type == dpkt.ethernet.ETH_TYPE_ARP:  # parse IP addrs out of ARP
                    info.update(proto='arp', sip=IP(socket.inet_ntop(socket.AF_INET, d.spa)), dip=IP(
                        socket.inet_ntop(socket.AF_INET, d.tpa)))
                elif packet.type == dpkt.ethernet.ETH_TYPE_IP:  # parse IPv4 header
                    info.update(proto=d.p, sip=IP(socket.inet_ntop(socket.AF_INET, d.src)), dip=IP(
                        socket.inet_ntop(socket.AF_INET, d.dst)))
                elif packet.type == dpkt.ethernet.ETH_TYPE_IP6:  # parse IPv6 header
                    info.update(proto=d.nxt, sip=IP(socket.inet_ntop(socket.AF_INET6, d.src)), dip=IP(
                        socket.inet_ntop(socket.AF_INET6, d.dst)))
                else:  # not IP or ARP, stop here and return layer 3 as data
                    info.update(data=d)
                    return info, packet
                try:
                    # clear checksums
                    d.sum = 0  # IP hdr checksum
                    d.data.sum = 0  # TCP/UDP checksum
                    # parse layer 4 header as TCP or UDP
                    info.update(sport=d.data.sport, dport=d.data.dport)
                    data = d.data.data  # data = protocol data
                    # get TCP info
                    try:
                        info.update(flags=d.data.flags, seq=d.data.seq,
                                    ack=d.data.ack, win=d.data.win)
                    except:
                        pass
                except:
                    data = d.data  # IP but not TCP/UDP
                info.update(data=data)  # add protocol data to info
            except Exception as e:
                self.debug(e, exc_info=True)  # ether decoding error
            return info, packet  # return info and packet


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
