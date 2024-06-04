'''ADF CAN/J1939/J1708/J1587 package'''
import logging
log = logging.getLogger(__name__)

__all__ = []
try:
    from can import Bus, Message
    __all__.append('Message')
except ImportError:
    log.error('could not import can, please install python-can')

CANOPTS = {'bustype': 'socketcan'}


# ADF classes
try:
    from adf import *

    class CANInterface(Plugin):
        '''CANBUS/socketCAN ADF interface
        Functions like the Interface Plugin, but for CAN/VCAN interfaces
        Config:
        Required:    device=<can interface to attach to>
        Optional:
            can_filters=[{"can_id": ..., "can_mask": ..., "extended": True|False},...] list of filters for received messages
                pass if rx_id & can_mask == can_id & can_mask
                and if extended is True|False, rx_is_extended==extended 
            receive_own_messages=False|True to see own sent messages
            local_loopback=True|False to prevent other socketCAN on this machine from seeing sent messages
            ignore_rx_error_frames=False|True to ignore error frames
            fd=True|False to enable FD frames

        pass-through methods to underlying can.Bus:
            set_filters(can_filters)    change interface filters
            send_periodic(msgs,period,duration=None)
            stop_all_periodic_tasks()

        event handling controls periodic send tasks
            id=           arbitration ID of message to send, if not set will stop all tasks.
            data=         data of message to send for id, will also modify existing send, if not set will stop send of id
            extended=     is extended ID frame, default False unless id > 0x7ff
            period=       interval for periodic send, must set if starting new send
            duration=     duration to send for, default is None (forever)
        '''

        can_filters = {}
        receive_own_messages = False
        local_loopback = True
        ignore_rx_error_frames = False
        fd = True
        __tasks = {}  # periodic tasks

        def main(self):
            self.__error = None
            try:
                self.__bus = Bus(self.device,
                                 can_filters=self.can_filters,
                                 receive_own_messages=self.receive_own_messages,
                                 local_loopback=self.local_loopback,
                                 ignore_rx_error_frames=self.ignore_rx_error_frames,
                                 fd=self.fd, **CANOPTS)
            except Exception as e:
                self.error(e, exc_info=True)
                self.stop()

            '''capture thread, decodes packets and sends them to the next plugin'''
            while not self.is_shutdown():
                try:
                    msg = self.__bus.recv(timeout=1)
                    if msg is None:
                        continue  # no packet, no problem
                    info = {'ts': msg.timestamp, 'source': self.name,
                            'id': msg.arbitration_id}
                    self.dispatch(info, msg)  # send the decoded packet
                except Exception as e:  # capture error (interface went down?)
                    self.error(e, exc_info=True)
                    break  # stop capture loop
            # interface off
            if self.__bus:
                self.__bus.shutdown()  # stop any periodic
                del self.__bus

        def handle_packet(self, info, pkt, **kwargs):
            '''if we are handed a packet, inject it on the wire'''
            if self.__bus and pkt and self.filter_packet(info, pkt):
                if self.metrics:
                    self._metrics(info)  # do metrics if enabled
                try:
                    self.__bus.send(pkt)
                    self.__error = None
                except Exception as e:
                    # if we get a send error, log it once and then shut up
                    # 'no buffer space available' is common on CAN interfaces if the bus is down
                    if not self.__error:
                        self.__error = e
                        self.warning(e)

        def set_filters(self, filters):
            if self.__bus:
                return self.__bus.set_filters(filters)

        def send_periodic(self, msgs, period, duration=None):
            if self.__bus:
                return self.__bus.send_periodic(msgs, period, duration)

        def stop_all_periodic_tasks(self):
            if self.__bus:
                self.__bus.stop_all_periodic_tasks()
            self.__tasks = {}

        def handle_event(self, e):
            '''event with id data period keys will start sending id,data every period
                duration will set periodic send duration
                extended sets extended frame if id < 00800 
            event with id of existing send task will change data
            event with id key and no data will stop send of that id
            if no id will stop all'''
            try:
                if e.id is not None:  # start a task
                    data = e.get('data')
                    if data:
                        msg = Message(arbitration_id=int(e.id), dlc=len(
                            data), data=data, is_extended_id=bool(e.extended) or int(e.id) > 0x7ff)
                        if e.id in self.__tasks:
                            self.__tasks[e.id].modify_data(msg)
                        else:
                            self.__tasks[e.id] = self.send_periodic(
                                msg, float(e.period), duration=e.duration)
                        return True
                    else:
                        self.__tasks[e.id].stop()
                        del self.__tasks[e.id]
                        return True
                else:  # stop all
                    self.stop_all_periodic_tasks()
                    return True
            except Exception as e:
                self.warning(e)

    import socket
    import struct
    import time

    class CANoverIP(Plugin):

        '''sends/receives CAN over UDP
        each datagram may contain multiple CAN frames.
        each frame is an 8-byte header, followed by frame data,
        followed by next frame header, and so on.
        header format is: 
            0        1        2        3        4        5        6        7       
            NNNNNNNN NNNNNNNN XREiiiii iiiiiiii iiiiiiii iiiiiiii F.....eb DDDDDDDD

            N=node ID
            X=extended ID format flag
            R=remote frame flag
            E=error frame flag
            i=arbitration ID, left-padded with 0 if 11-bit
            F=FD frame flag
            e=FD error state indicator
            b=FD bitrate switch flag
            D=DLC (data length)

        config (must be set at plugin load)
            port=<UDP port>. Default is 1939.

            addr=<IP> default is 127.0.0.1.
                send messages to this IP.
                can be broadcast (example: 192.168.0.255 for 192.168.0.0/24)

            listen=<IP>
                use an assigned unicast ip, broadcast IP, or 0.0.0.0 for all addresses.

            node=<0-65535> default is 0
                identifies the sending node. ignore messages from self.
        '''
        listen = None
        addr = '127.0.0.1'
        port = 1939
        node = 0

        def init(self):
            self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if self.listen:
                self.__socket.bind((self.listen, int(self.port)))
            self.__socket.settimeout(1)
            self.info('node %s listening on %s, sending to %s', self.node,
                      (self.listen, self.port), (self.addr, self.port))

        def handle_packet(self, info, msg, **kwargs):
            '''if we are handed a packet, send it over UDP'''
            if msg and self.filter_packet(info, msg):
                if self.metrics:
                    self._metrics(info)
                hdr = struct.pack('!HIBB', self.node,
                                  int(msg.is_extended_id) << 31 |
                                  int(msg.is_remote_frame) << 30 |
                                  int(msg.is_error_frame) << 28 |
                                  msg.arbitration_id,
                                  int(msg.is_fd) << 7 |
                                  int(msg.error_state_indicator) << 1 |
                                  int(msg.bitrate_switch),
                                  msg.dlc)
                self.__socket.sendto(hdr+bytes(msg.data),
                                     (self.addr, int(self.port)))

        def main(self):
            while not self.is_shutdown():
                try:
                    addr = None
                    # get packet
                    pkt, addr = self.__socket.recvfrom(65535)
                    i = 0
                    # get frame header and then dlc bytes of data
                    while i < len(pkt):
                        hdr = pkt[i:i+8]
                        i += 8
                        node, canid, flags, dlc = struct.unpack('!HIBB', hdr)
                        if node == self.node:
                            # if node id of rcvd packet is us, ignore it.
                            break
                        data = pkt[i:i+dlc]
                        i += dlc
                        msg = Message(
                            channel=str(self.client_address),
                            timestamp=time.time(),
                            is_remote_frame=bool(canid & 0x40000000),
                            extended_id=bool(canid & 0x80000000),
                            is_error_frame=bool(canid & 0x20000000),
                            arbitration_id=canid & 0x1fffffff,
                            is_fd=bool(flags & 0x8),
                            bitrate_switch=bool(flags & 0x1),
                            error_state_indicator=bool(flags & 0x2),
                            dlc=dlc, data=data)

                        info = {'ts': msg.timestamp,
                                'source': self.name,
                                'id': msg.arbitration_id}

                        self.dispatch(info, msg)

                except socket.timeout:
                    continue
                except Exception as e:
                    self.warning(addr, exc_info=True)

            self.__socket.close()

    __all__.append('CANInterface')
    __all__.append('CANoverIP')

    # CANInterface/CANoverIP unit test
    def test(can_if):
        import logging
        from pprint import pformat
        from os import system
        f = Framework()
        f.start_plugin(CANInterface, device=can_if)
        f.start_plugin(CANoverIP)
        f.link_plugin('CANInterface', 'CANoverIP')
        logging.info(pformat(f.config('show')))
        for v in range(16):
            system('cansend '+can_if+' %03x' % v+'#%04x' % v)
        f.stop()
    __all__.append('test')

except ImportError as e:
    log.error(e)

# load support for the canbus protocols
try:
    from . import j1939
    __all__.append('j1939')
    from .j1939 import J1939Decoder
    __all__.append('J1939Decoder')
    from .dbc import DBCDecoder, DBCEncoder
    __all__.append('DBCEncoder')
    __all__.append('DBCDecoder')
except ImportError as e:
    log.error(e)

# capture/replay support
try:
    from . import logger
    __all__.append('logger')
    from .logger import Log, Replay
    __all__.append('Log')
    __all__.append('Replay')
except ImportError as e:
    log.error(e)

# load support for J1708
try:
    from .j1708 import J1708Interface, J1708overIP
    from .j1587 import J1587Decoder
    __all__.append('J1708Interface')
    __all__.append('J1708overIP')
    __all__.append('J1587Decoder')
except ImportError as e:
    # do not log an error here, release will not have these due to hardware and licensing issues.
    pass

# load additional modules
try:
    from . import IBP
    __all__.append('IBP')
except ImportError as e:
    log.error(e)
try:
    from . import UDS
    __all__.append('UDS')
except ImportError as e:
    log.error(e)
