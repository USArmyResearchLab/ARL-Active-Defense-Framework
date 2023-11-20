#!/usr/bin/env python

from adf import *
from adf.canbus import *
from adf.canbus.j1939 import J1939EncodeId, J1939DecodeId
import binascii
import struct
import time
import pickle


class Packet(Plugin):
    '''In-band pub/sub protocol for sending <=2040 bytes per packet via J1939
    set priority from 0-7, default 7, is J1939 priority
    set domain from 240-255, default 240
    set channel and addr from 0-15. defaults to 0
        addr is normally source address, but is dest address if request 
    set channels to list of channels to listen to. defaults to channel.
    set send count per frame for redundancy and rate in frames per second. defaults are 1 send and no rate limit
    The Publisher expects string/bytearray in event:data and will use the following keys:
        channel: override channel
        addr: override address
        control: up to 3 bytes of channel control data, will be zero padded

    protocol format:
        J1939 PGN=0x10000|Domain<<8|sequence, SA=channel<<4|addr
        if sequence=0, frame is header (1 byte length in frames,3 bytes control, CRC32)
        if 0<sequence<=length, frame is data
        if sequence==length, flush buffer 

    handles Event:  {channel:0-15, addr:0-15, control:<3 bytes> data:<bytearray, max 2040>}
    generates Event {channel, addr, control, data}

    If subclassing to send/recv raw data:
        send_raw(data,control,channel,addr) to send
        recv_raw(self,data,control,channel,addr,**info) will be called on receive
'''
    priority = 7
    domain = 240  # J1939 PF
    channel = 0  # channel to send on
    addr = 0  # source ID
    channels = []
    count = 1  # times to send each frame
    rate = 0  # send rate in FPS. 0=as fast as possible

    def init(self):
        self.frames = {}
        self.channel = int(self.channel)
        self.addr = int(self.addr)
        self.rate = int(self.rate)
        self.count = int(self.count)
        self.domain = int(self.domain)
        if self.channels:
            self.channels = [int(c) for c in self.channels]
        else:
            self.channels = [self.channel]

    def handle_event(self, e):
        self.send_raw(
            e.get('data', bytearray()),
            e.get('control', bytearray(b"\x00\x00\x00")),
            e.get('channel', self.channel),
            e.get('addr', int(self.addr))
        )
        return True

    # send is used in Plugin for dispatch!
    def send_raw(self, data, ctl=bytearray(b"\x00\x00\x00"), channel=None, addr=None):
        '''we get data to send and have to split it into CAN frames'''
        if channel is None:
            channel = self.channel
        if addr is None:
            addr = self.addr
        SA = (channel << 4) | addr
        l = int(len(data)/8)
        if len(data) % 8:
            l += 1  # one more frame for remaining bytes
        hdr = bytes([l])+bytes(ctl)
        crc = binascii.crc32(hdr+bytes(data)) & 0xffffffff  # to unsigned CRC32
        # send the header
        for c in range(self.count):
            self.dispatch({}, Message(timestamp=time.time(),
                                      arbitration_id=J1939EncodeId(
                priority=self.priority,
                DP=1, PF=self.domain, SA=SA),
                data=hdr+struct.pack('!I', crc)))
            if self.rate:
                time.sleep(1.0/float(self.rate))
        seq = 0
        # send the data
        for i in range(0, 8*l, 8):
            for c in range(self.count):
                seq += 1
                self.dispatch({}, Message(timestamp=time.time(),
                                          arbitration_id=J1939EncodeId(
                    priority=self.priority,
                    DP=1, PF=self.domain, SA=SA,
                    GE=seq),
                    data=data[i:i+8]))
                if self.rate:
                    time.sleep(1.0/float(self.rate))

    def handle_packet(self, info, msg, **kwargs):
        '''buffer CAN frames until we have a packet'''
        j = J1939DecodeId(
            msg)  # call static decoder so we don't have to be linked through a J1939Decoder plugin
        if j and j.get('DP') and j.get('PF') == self.domain and (j.get('SA') >> 4) in self.channels:
            ch, addr, seq = j.get('SA') >> 4, j.get('SA') & 15, j.get('GE')
            if not seq:
                self.frames[(ch, addr)] = [int(msg.data[0]),  # length
                                           msg.data[1:4],  # control
                                           struct.unpack('!I', msg.data[4:8])[
                    0],  # crc
                    {}]  # frames
            elif (ch, addr) in self.frames:
                if seq <= self.frames[(ch, addr)][0]:
                    self.frames[(ch, addr)][3][seq-1] = msg.data
            # try reassembly if seq=count
            if (ch, addr) in self.frames and seq == self.frames[(ch, addr)][0]:
                l, ctl, crc, frames = self.frames[(ch, addr)]
                try:
                    data = bytearray()
                    for f in range(l):
                        data.extend(frames[f])
                    if crc != binascii.crc32(bytes([l])+bytes(ctl)+bytes(data)) & 0xffffffff:
                        raise Exception('bad crc %s != %s' % (crc,
                                                              binascii.crc32(bytes([l])+bytes(ctl)+bytes(data)) & 0xffffffff))
                    self.recv_raw(data=data, ctl=ctl,
                                  channel=ch, addr=addr, **info)
                    try:
                        del self.frames[(ch, addr)]
                    except:
                        pass
                except KeyError:
                    pass  # we dropped a frame, ignore it
                except Exception as e:
                    self.error(e, exc_info=True)

    def recv_raw(self, data, ctl, channel, addr, **info):
        '''called when we receive a full packet'''
        self.event(self.name, ts=info.get('ts', time.time()),
                   channel=channel, addr=addr,
                   control=ctl, data=data)


class Transport(Packet):
    '''Transport handler for arbitrary data via J1939 IBP. 
    Sends/recEIves events on channel
    event must be pickleable

    If subclassing to send/recv data:
        send_data(data) to send
        flush_data(self,data,addr) will be called on receive

    Transport control bytes are:
        0: Flags: F......A
            F (128) : Final packet of data
            A (1)    :ACK and request packet (addr is dest)
        1-2: Sequence number of packet sent or requested

    Request/Ack mechanism:
        (sending 3 packets)
        [seq 0]--->
        (if good)
                <---[ack, seq 1]
        [seq 1]--->
                <---[ack, seq 2]
        [fin, seq 2]--->
                <---[fin, ack, seq 3]


    Config:
        domain=[domain ID to use, default 240]
        channel=[channel to use, default 0]
        addr=[source ID to use, default 0]
        ack=[if set, request/ack mechanism will be used]
        timeout=[seconds before ack/req will be resent, default 1]
        size=[maximum packet size, default 2040]
    '''

    ack = False
    timeout = 1
    size = 2040

    def init(self):
        self.__ch_recv = {}  # receive buffer [addr][seq]
        self.__ch_req = {}  # requested packet tracking [addr]=(seq,timestamp)
        self.__ch_send = []  # send buffer [seq]
        self.ack = bool(self.ack)
        self.timeout = int(self.timeout)
        self.size = int(self.size)
        Packet.init(self)

    def __send(self, seq, data=bytearray(), ack=False, fin=False, **kwargs):
        '''send packet on channel'''
        Packet.send_raw(self,
                        data=data,
                        # F......A flags and sequence
                        ctl=bytearray(struct.pack(
                            '!BH', (int(fin) << 7) & 0xff | int(ack), seq)),
                        **kwargs)  # pass kwargs to allow channel/addr override

    def __flush(self, addr):
        '''assemble and dump receive buffer'''
        data = bytearray()
        for seq, pkt in sorted(self.__ch_recv.setdefault(addr, {}).items()):
            data.extend(pkt)
        self.flush_data(data, addr)  # call upper flush
        # done with buffer and state
        del self.__ch_recv[addr], self.__ch_req[addr]

    def flush_data(self, data, addr):
        '''handle received data'''
        # generate event from data
        try:
            # unpickle
            e = pickle.loads(data)
            # set source
            e.path.append(self.name)
            # send event
            self.event(event=e)
        except Exception as e:
            self.warning(e, exc_info=True)

    def recv_raw(self, *req, **pkt):  # override recv_raw from Packet to handle Transport protocol
        '''receive or request incoming packet from the wire. arguments are a bit weird. 
        If we are called to handle a packet, pkt will get a dict with data, ctl, channel, addr, and other info
        If we are called to request a packet, req will get an addr,seq tuple'''
        if pkt:  # we might be getting a packet
            flags, seq = struct.unpack('!BH', pkt.get('ctl'))
            fin, ack = flags >> 7, flags & 1  # F......A flags
            addr = pkt.get('addr')
        else:
            # we're being called to request a packet
            fin, ack, addr, seq = False, False, req[0], req[1]
        if ack and addr == self.addr:  # if ack rcvd and we are using acks
            if self.ack:
                if fin:
                    self.__ch_send = []  # FIN+ACK means we are done
                elif seq < len(self.__ch_send):  # don't send a packet we don't have
                    self.__send(
                        seq,  # send requested
                        data=self.__ch_send[seq],
                        fin=(seq == len(self.__ch_send)-1))  # FIN on last
        else:  # not ack, contains data
            if pkt:
                data = pkt.get('data')
                if data:
                    # store data if we have a packet
                    self.__ch_recv.setdefault(addr, {})[seq] = data
                else:
                    seq = -1  # initial handshake is seq 0 but no data, we have to request seq 0
            self.__ch_req[addr] = (seq, time.time())  # save seq and timestamp
            if fin:
                self.__flush(addr)  # __flush buffer if done
            # request next. set addr to request destination
            if self.ack:
                self.__send(seq+1, addr=addr, ack=True, fin=bool(fin))

    def handle_event(self, e):
        '''send event on channel'''
        data = pickle.dumps(e)  # ensure data is pickle-shaped
        self.send_data(data)
        return True

    def send_data(self, data, **kwargs):
        '''send data on channel'''
        for i in range(0, len(data), self.size):  # up to 2040 bytes per packet
            self.__ch_send.append(bytearray(data[i:i+self.size]))  # packetize
        if self.ack:
            # if ack enabled, we handshake with seq=0, no data
            self.__send(0, **kwargs)
        else:  # send all packets
            for seq in range(len(self.__ch_send)):
                self.__send(seq,
                            data=self.__ch_send[seq],
                            fin=(seq == (len(self.__ch_send)-1)), **kwargs)  # FIN on last
            self.__ch_send = []  # discard after sending

    def idle(self, count):
        '''while idle, see if we have any requests to resend'''
        if self.ack:  # only if we have ack on
            for addr, (seq, ts) in self.__ch_req.items():
                if time.time()-ts > self.timeout:  # if last request timed out
                    self.warning('%s recv timeout: addr %s seq %s' %
                                 (self.name, addr, seq+1))
                    self.recv_raw(addr, seq)


def test(*args):
    TESTARGS = dict(
        size=2040,
        ack=False,
        rate=10,
        channel=0,
    )

    import sys
    import time
    import logging
    try:
        TESTARGS['channel'] = int(args[0])
        data = bytes(args[1], 'ascii')
    except:
        sys.exit(
            '''test harness
    packet/channel1->J1939_1->test1->packet/channel2->J1939_2->test2-->packet/channel1
    args are <channel> <'data'> [size] [enable_ack] [rate]
    ''')
    if len(args) > 2:
        TESTARGS['size'] = int(args[2])
    if len(args) > 3:
        TESTARGS['ack'] = int(args[3])
    if len(args) > 4:
        TESTARGS['rate'] = int(args[5])
    logging.basicConfig(level=logging.DEBUG)
    f = Framework()

    # Test plugins
    from adf.plugin import Test
    t = f.start_plugin(Test)

    # test packet data
    f.start_plugin(Packet, addr=1, name='p1', **TESTARGS)
    f.start_plugin(Packet, addr=2, name='p2', **TESTARGS)
    f.link_plugin('p1', 'Test')
    f.link_plugin('p2', 'Test')
    # send event and wait for p2 response
    f.subscribe('Test', 'p2')  # p2 will resend the event
    print('IBP PACKET: Test sent event to p1, Test received event:',
          t.sr('p1', data=data))

    # stop packet plugins
    f.stop_plugin('p1')
    f.stop_plugin('p2')

    # test channel data
    f.start_plugin(Transport, addr=1, name='c1', **TESTARGS)
    f.start_plugin(Transport, addr=2, name='c2', **TESTARGS)
    f.link_plugin('c1', 'Test')
    f.link_plugin('c2', 'Test')
    f.event('c1', data=data)  # start sending the data first
    time.sleep(0.1)
    # subscribe it now so sr() only gets the response
    f.subscribe('Test', 'c1')
    print('IBP TRANSPORT: Test sent event to c1, Test received event:', t.sr())

    # stop framework
    f.stop()


if __name__ == '__main__':
    import sys
    test(sys.argv[1:])
