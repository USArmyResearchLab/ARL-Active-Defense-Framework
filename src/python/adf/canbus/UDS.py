#!/usr/bin/env python3
'''ISO15765/14229/UDS plugins'''

import sys
import struct
import logging
import secrets
from adf import *
from adf.canbus import *
from adf.canbus.j1939 import J1939EncodeId, J1939DecodeId

ISO_PGN = 0xDA00

SIDNR = 0x7F

service_identifier = {0x7F: "NegativeResponse",
                      0x10: "DiagnosticSessionControl",
                      0x11: "ECUReset",
                      0x19: "ReadDTCInformation",
                      0x14: "ClearDiagnosticInformation",
                      0x2F: "InputOutputControlByIdentifier",
                      0x24: "ReadScalingDataByIdentifier",
                      0x27: "SecurityAccess",
                      0x22: "ReadDataByIdentifier",
                      0x2A: "ReadDataByPeriodicIdentifier",
                      0x2C: "DynamicallyDefineDataIdentifier",
                      0x2E: "WriteDataByIdentifier",
                      0x3D: "WriteMemoryByAddress",
                      0x23: "ReadMemoryByAddress",
                      0x28: "CommunicationControl",
                      0x3E: "TesterPresent",
                      0x83: "AccessTimingParameter",
                      0x84: "SecuredDataTransmission",
                      0x85: "ControlDTCSetting",
                      0x86: "ResponseOnEvent",
                      0x87: "LinkControl",
                      0x2F: "InputOutputControlByIdentifier",
                      0x31: "RoutineControl",
                      0x34: "RequestDownload",
                      0x35: "RequestUpload",
                      0x36: "TransferData",
                      0x37: "RequestTransferExit",
                      0x38: "RequestFileTransfer",

                      }

negative_response_codes = {0x10: "General Reject",
                           0x11: "Service Not Supported",
                           0x12: "Subfunction Not Supported",
                           0x31: "Request Out of Range",
                           0x33: "Security Access Denied"
                           }


def get_first_nibble(data_byte):
    return (data_byte & 0xF0) >> 4


def get_second_nibble(data_byte):
    return data_byte & 0x0F

# data: data portion of ISO15765 message
# make sure pgn is da00 or the other one


def is_transport(data):
    return get_first_nibble(data[0]) != 0


def is_first_frame(data):
    return get_first_nibble(data[0]) == 1


def is_consecutive_frame(data):
    return get_first_nibble(data[0]) == 2


def is_fc_frame(data):
    return get_first_nibble(data[0]) == 3


def dissect_first_frame(data):
    data_length = (get_second_nibble(data[0]) << 8) | data[1]
    first_data = data[2:]
    return (data_length, first_data)


def dissect_consecutive_frame(data):
    seq_num = get_second_nibble(data[0])
    data_portion = data[1:]
    return (seq_num, data_portion)


def dissect_fc_frame(data):
    flow_status = get_second_nibble(data[0])
    block_size = data[1]
    separation_time = data[2]  # in milliseconds, minimum
    return (flow_status, block_size, separation_time)


def dissect_other_frame(data):
    data_length = data[0]
    message_data = data[1:]
    return data_length, message_data

# separate block of data into chunks appropriate for ISO15765 comms
# first block is 6 bytes, consecutive is 7 bytes


def transport_separate_data(data):
    data_ptr = 0
    length = len(data)
    data_ptr += 6
    yield data[:6]
    while data_ptr < length:
        yield data[data_ptr:data_ptr + 7]
        data_ptr += 7

# create list of single or first/consecutive frames


def construct_frames(data):
    frames = []
    if len(data) < 8:
        # single             code 0, len           7 bytes data             padding
        frames.append(bytes([len(data)]) + bytes(data) +
                      bytes([0] * (7-len(data))))
    else:
        i = 1
        block = transport_separate_data(data)  # get block generator
        # first                      code 1|lenh,                  len               6 bytes data
        frames.append(
            bytes([0x10 | (len(data) >> 8), len(data) & 0xff]) + next(block))
        for b in block:  # consecutive frames
            # consec                      code 2|index   up to 7 bytes     padding
            frames.append(bytes([0x20 | (i & 0x0f)]) +
                          b + bytes([0] * (7-len(b))))
            i += 1
    return frames


def bytes_to_hex_string(data): return ''.join('%02x' % b for b in data)


class ISOTransportQueue:
    def __init__(self, source_address, dest_address, first_frame_message):
        self.dest_address = dest_address
        self.source_address = source_address
        (self.data_length, first_data) = dissect_first_frame(first_frame_message)
        remaining_data = self.data_length - 6
        num_data_messages = remaining_data // 7 if remaining_data % 7 == 0 else remaining_data // 7 + 1
        self.message_queue = [None] * (num_data_messages + 1)
        self.message_queue[0] = bytes(first_data)

    def add_message(self, consecutive_frame):
        (seq_num, data_portion) = dissect_consecutive_frame(consecutive_frame)
        i = seq_num
        while i < len(self.message_queue):
            if self.message_queue[i] is None:
                self.message_queue[i] = bytes(data_portion)
                return
            else:
                i += 16

        raise Exception("ISO15765 message_queue full")

    def is_full(self):
        return None not in self.message_queue

    def get_data(self):
        if self.is_full():
            return bytearray(b''.join(self.message_queue)[:self.data_length])
        else:
            raise Exception("Called get_data on ISOTransportQueue before full")


class ISO(Plugin):
    '''sends/receives ISO 15765 messages, decodes ISO 14229 messages'''

    address = None  # default J1939 address for this node. None captures all traffic

    def init(self):
        self.rx_queues = {}  # incoming message queues
        self.tx_queues = {}  # sa->frames for sending messages
        if self.address is not None:
            self.address = int(self.address)

    def send_frame(self, data, dst=0x00, src=0xf9, pri=6, **info):
        '''send a J1939 frame'''
        self.dispatch(info, Message(arbitration_id=J1939EncodeId(
            priority=pri, PGN=ISO_PGN, DA=dst, SA=src), data=data))

    def send_message(self, data, src=None, dst=0x00, **info):
        '''send a 15765 message as frames'''
        if src is None:
            src = self.address
        frames = [(f, src) for f in construct_frames(data)]
        if len(frames) > 1:
            # save consecutive frames for response to FC
            self.tx_queues[dst] = frames
        self.send_frame(frames[0][0], dst=dst, src=src,
                        **info)  # single or first frame

    def process_frame(self, info, msg):
        '''handle incoming ISO frames. If we get an FC frame, respond with remaining frames to send
        else return data up'''
        (pgn, priority, sa, da, data) = self.read_frame(info, msg)
        if pgn:  # frame is valid and addressed to us
            if data:
                # send received messages up
                return (pgn, priority, sa, da, data)
            else:  # fc-frame, request for consecutive frames
                frames = self.tx_queues.get(sa)  # get queued frames
                if frames:  # send them
                    for (f, fa) in frames[1:]:
                        self.send_frame(f, dst=sa, src=fa,
                                        dispatch=info.get('prev'))
                    del self.tx_queues[sa]  # discard queue
        # no data to return (not our frame or we were completing a send)
        return (None, None, None, None, None)

    def handle_packet(self, info, msg, **kwargs):
        '''generate events if full message received'''
        pgn, priority, sa, da, data = self.process_frame(info, msg)
        if data:
            self.event(sa=sa, da=da, data=data)

    def handle_event(self, e):
        '''if we get an event by our name, send it as a ISO frame'''
        if e.name == self.name:
            # send the request
            self.send_message(e.get('data', bytearray()), e.get('da', 0))
            return True
        return False

    def read_frame(self, info, msg):
        # we get j1939 decode and message data
        try:
            j = J1939DecodeId(msg)
            (pgn, priority, src_addr, dst_addr,
             message_data) = j['PGN'], j['priority'], j['SA'], j['DA'], msg.data
        except:
            return (None, None, None, None, None)  # no data to return
        # filter to ISO frames addressed to us
        if ((pgn == ISO_PGN) and (self.address is None or dst_addr == self.address)):
            if is_first_frame(message_data):
                # don't do anything if we already see a session from this source
                #logging.debug("This was the First Frame of an ISO message.")
                if not self.rx_queues.get(src_addr):
                    self.rx_queues[src_addr] = ISOTransportQueue(
                        src_addr, dst_addr, message_data)
                    self.send_frame(bytearray(
                        [0x30, 0, 0, 0, 0, 0, 0, 0]), src=dst_addr, dst=src_addr, dispatch=info.get('prev'))
            elif is_consecutive_frame(message_data):
                #logging.debug("This was a consecutive frame of an ISO message.")
                this_queue = self.rx_queues.get(src_addr)
                if this_queue:
                    this_queue.add_message(message_data)
                    if this_queue.is_full():
                        completed_data = this_queue.get_data()
                        del (self.rx_queues[src_addr])
                        return (pgn, priority, this_queue.source_address,
                                this_queue.dest_address, completed_data)
            elif is_fc_frame(message_data):
                return (pgn, priority, src_addr, dst_addr, None)
            else:
                data_length, message_data = dissect_other_frame(message_data)
                return (pgn, priority, src_addr, dst_addr, message_data[:data_length])
        return (None, None, None, None, None)  # no data to return


class UDS(ISO):
    '''sends ISO14229/UDS messages and gather responses'''
    SESSION_DEFAULT = 0x01
    SESSION_PROGRAM = 0x02
    SESSION_EXTENDED = 0x03
    SESSION_SAFETY = 0x04

    RESET_HARD = 0x01
    RESET_KEY = 0x02
    RESET_SOFT = 0x03

    IDENTIFIERS = {
        'VIN': [0xf1, 0x90],
        'SW': [0xf1, 0x95],
        'HW': [0xf1, 0x93]

    }

    def diagnostic_session_control(self, session=SESSION_DEFAULT):
        return dict(sid=0x10, param=[session])

    def ecu_reset(self, reset=RESET_HARD):
        return dict(sid=0x11, param=[reset])

    def read_data_by_identifier(self, *ids):
        '''args are list of identifiers to request'''
        p = []
        # if id in identifiers dict, use it else use input in high/low bytes
        for i in ids:
            v = self.IDENTIFIERS.get(i)
            if v is None:
                v = [i >> 8, i & 0xff]
            p.extend(v)
        return dict(sid=0x22, param=p)

    def write_data_by_identifier(self, **id_data):
        '''args are id=data, id=data'''
        p = []
        for i in id_data.keys():
            v = self.IDENTIFIERS.get(i)
            if v is None:
                v = [i >> 8, i & 0xff]
            p.extend(v)  # add identifier
            p.extend(id_data[i])  # add data bytes
        return dict(sid=0x2e, param=p)

    def read_memory_by_address(self, addr, l):  # read l@address
        return dict(sid=0x23, param=bytes([0x44])+struct.pack('!II', addr, l))

    def write_memory_by_address(self, addr, d):  # write d@address
        return dict(sid=0x3d, param=bytes([0x44])+struct.pack('!II', addr, len(d))+bytes(d))

    def request_transfer(self, addr, l, upload=False):
        if upload:
            sid = 0x35
        else:
            sid = 0x34
        return dict(sid=sid, param=bytes([0x00, 0x44])+struct.pack('!II', addr, l))

    def transfer_block(self, seq=0, data=[]):
        if seq:
            sid = 0x36
        else:
            sid = 0x37
        return dict(sid=sid, param=bytes([seq])+bytes(data))

    def handle_event(self, e):
        '''if we get an event, send it as a UDS request'''
        self.uds_request(e.get('sid', 0x10), e.get(
            'param', []), e.get('da', 0))
        return True

    def handle_packet(self, info, msg, **kwargs):
        '''handle incoming as iso params, generate event when full message received'''
        data = self.parse_uds(info, msg)
        if data:
            self.event(ts=info.get('ts'), **data)

    def uds_request(self, sid=0x22, param_bytes=[], da=0, sa=None, **info):
        '''UDS request message. param_bytes is everything following sid. 
        The message is filled with zeros at the end.'''
        if sa is None:
            sa = self.address
        self.send_message(
            bytearray([sid] + list(param_bytes)), dst=da, src=sa, **info)

    def parse_uds(self, info, msg):
        '''parse incoming data as ISO param, generate data if we get params'''
        data_package = {}
        (pgn, priority, src_addr, dst_addr, data) = self.process_frame(info, msg)
        # data will be None if we don't have the full message yet
        if data is not None:
            data = bytearray(data)
            d = dict(data=data, sa=src_addr, da=dst_addr,
                     sid=data[0], param=data[1:])
            if data[0] == 0x7f:  # negative response, byte 2 will be bad SID, byte 3 will be error code
                d.update(nr_sid=data[1], nr_code=data[2], resp=False)
                try:
                    dp = data_package.setdefault('Negative Response', {})
                    dp.update({service_identifier.get(
                        data[1], data[1]): negative_response_codes.get(data[2], data[2])})
                except KeyError:
                    pass
            else:
                # sid mask is 10111111, positive response bit is 01000000
                sid, param, resp = data[0] & 0xbf, data[1:], bool(
                    data[0] & 0x40)
                s = service_identifier.get(sid, 'SID%02x' % sid)
                if resp:  # if positive response
                    d.update(resp=True)  # if not true, is request, not NR
                    if sid == 0x10:  # Control
                        data_package.setdefault(s, param)
                    if sid == 0x22:  # Read Data By Identifier
                        dp = data_package.setdefault(s, {})
                        # loop until params exhausted
                        while param:
                            param = self.parse_data_by_identifier(dp, param)
                    if sid == 0x2e:  # Write Data By Identifier
                        dp = data_package.setdefault(s, [])
                        # loop until params exhausted
                        while param:
                            dp.append(param[0] << 8 | param[1])
                            param = param[2:]
                    if sid == 0x23 or sid == 0x3d:  # R/W Memory By Address
                        data_package.setdefault(s, param)
                    if sid == 0x36:  # Data Transfer
                        data_package.setdefault(s, {})[param[0]] = param[1:]
                    if sid == 0x2c:
                        data_package.setdefault(
                            s, {param[0]: param[1:]})  # define identifier
                    if sid == 0x31:  # routine control
                        dp = data_package.setdefault(s, {})
                        t, param = param[0], param[1:]
                        sf = dp.setdefault(
                            {1: 'start', 2: 'stop', 3: 'result'}.get(t, t), {})
                        sf[param[0] << 8 | param[1]] = (param[2], param[3:])
                else:  # is request
                    d.update(req=True)
                    if sid == 0x10:  # Control
                        dp = data_package.setdefault(s, param)
                    if sid == 0x22:  # Read Data By Identifier
                        dp = data_package.setdefault(s, [])
                        # loop until params exhausted
                        while param:
                            dp.append(param[0] << 8 | param[1])
                            param = param[2:]
                    if sid == 0x2e:  # Write Data By Identifier
                        dp = data_package.setdefault(s, {})
                        # loop until params exhausted
                        while param:
                            param = self.parse_data_by_identifier(dp, param)
                    if sid == 0x2c:  # define identifier
                        dp = data_package.setdefault(s, {})
                        t, param = param[0], param[1:]
                        if t == 0x1:  # if defining data by identifiers
                            while param:
                                # DID[position]=(SID,len)
                                dp.setdefault(param[0] << 8 | param[1], {})[
                                    param[4]] = (param[2] << 8 | param[3], param[5])
                                param = param[6:]
                            else:
                                dp[t] = param  # memory or clear
                    if sid == 0x23 or sid == 0x3d:  # R/W Memory By Address
                        data_package.setdefault(s, param)
                    if sid == 0x36:  # Data Transfer
                        data_package.setdefault(s, {})[param[0]] = param[1:]
                    if sid == 0x31:  # routine control
                        dp = data_package.setdefault(s, {})
                        t, param = param[0], param[1:]
                        sf = dp.setdefault(
                            {1: 'start', 2: 'stop', 3: 'req'}.get(t, t), {})
                        sf[param[0] << 8 | param[1]] = param[2:]
            # return decoded params
            if data_package:
                d.update(data_package)
            return d

    def parse_data_by_identifier(self, dp, param):
        try:
            p, pd = param[0:2], param[2:]
            dp[p[0] << 8 | p[1]] = pd  # catch all, set numeric identifier key
            if p == bytearray([0xF1, 0x90]):
                dp["VIN"] = str(pd)
            elif p == bytearray([0xF1, 0x8C]):
                dp["ECU Serial Number"] = str(pd)
            elif p == bytearray([0xF1, 0x95]):
                dp["ECU Software Version"] = ' '.join(['%d' % b for b in pd])
            elif p == bytearray([0xF1, 0x93]):
                dp["ECU Hardware Version"] = ' '.join(['%d' % b for b in pd])
        except KeyError:
            pass


class UDSProxy(UDS):
    '''stores and forwards UDS messages based on results of effect
       effect method should return False to drop the message, True to forward it
        dispatch, dest, etc.. in info can be set to route the message
        data will have full UDS decode (sa,da,sid, param, and any decoded params)
         forwarded message will be encoded from sa,da,sid,and bytes of param, 
         so any changed params should be re-encoded'''

    def init(self):
        self.__redir = {}
        UDS.init(self)  # ADF plugin init

    def handle_packet(self, info, msg, **kwargs):
        '''handle incoming as iso params, generate event when full message received'''
        data = self.parse_uds(info, msg)
        # if we have a full message, run it through the effect. if we get True, forward the data we get back
        if data and self.effect(info, data):
            sid = data.get('sid', 0)
            if data.get('resp'):
                sid |= 0x40  # set response bit in sid if resp is True
            self.uds_request(
                sid=sid,
                param_bytes=bytearray(data['param']),
                sa=data.get('sa', self.address),
                da=data.get('da', 0),
                **info)

    def effect(self, info, data):
        '''default effect to forward all'''
        return True

    '''these can be called as a return from effect'''

    def respond(self, info, data, **kwargs):
        '''updates data from kwargs, flips sa/da and dispatches to the previous'''
        data.update(**kwargs)
        data.update(sa=data.get('da'), da=data.get('sa'))
        info.update(dispatch=info.get('prev'))
        return True

    def redirect(self, info, data, dest=None, **kwargs):
        '''redirect message, redirect responses back to source'''
        data.update(**kwargs)
        prev = info.get('prev')  # where this message came from
        if prev in self.__redir:  # came from redirection
            info.update(dispatch=self.__redir[prev])  # return back to source
        elif dest:  # we are redirecting this message
            info.update(dispatch=dest)
            self.__redir[dest] = prev  # save prev hop for return from redirect
        return True


class UDSResponder(ISO):
    '''responds to UDS/ISO14229 messages'''
    address = 0
    DATA_BY_IDENTIFIER = {
        b'\xf1\x90': b'OU81BADDEADBEEF2',  # just respond with a fake VIN for now
        b'\xf1\x93': b'1',
        b'\xf1\x95': b'1'
    }
    MEMORY = {}  # fake memory for R/W by address
    DT_MEM_ADDR = None  # for pending data transfer, memory address to r/w next block
    DT_UPLOAD = 0  # set to 1+ if we are sending blocks, 0 if we are receiving
    DT_BLOCK_SIZE = 253  # transfer message size of 255 (SID+seq+block)
    SESSION = 0
    UNLOCKED = False
    SEC_METHOD = 1
    SECRET = b'\xca\xfe'

    def respond_read_data_by_identifier(self, params, r):
        # allow anything to be read as long as it has a default or has been previously written
        k = bytes(params[0:2])
        if k in self.DATA_BY_IDENTIFIER:
            # append PR-SID, PID and response data
            r += b'\x62'+k+self.DATA_BY_IDENTIFIER[k]
            return True
        return False

    def respond_write_data_by_identifier(self, params, r):
        # allow anything to be written
        k = bytes(params[0:2])
        self.DATA_BY_IDENTIFIER[k] = bytes(params[2:])
        r += b'\x6e'+k
        return True

    def parse_address_size(self, params):
        # parses [SL<<4|AL][A.....][S.....] as AL bytes address and SL bytes size
        # returns (address length, size length), (address, size), remaining data
        sl, al = params[0] >> 4, params[0] & 0xf
        return (al, sl), struct.unpack('!II', params[1:1+al].rjust(4, b'\x00')+params[1+al:1+al+sl].rjust(4, b'\x00')), params[1+al+sl:]

    def encode_address_size(self, al, sl, address, size):
        return bytes([sl << 4 | al])+struct.pack('!I', address)[-al:]+struct.pack('!I', size)[-sl:]

    def respond_read_memory_by_address(self, params, r):
        (al, sl), (address, size), data = self.parse_address_size(params)
        r += b'\x63'
        for loc in range(address, address+size):
            r += bytes([self.MEMORY.get(loc, 0)])
        return True

    def respond_write_memory_by_address(self, params, r):
        (al, sl), (address, size), data = self.parse_address_size(params)
        r += b'\x7d'+self.encode_address_size(al, sl, address, size)
        for i in range(len(data)):
            self.MEMORY[address+i] = data[i]
        return True

    def respond_request_download(self, params, r):
        # download here means requesting the responder download, client->server
        # we only support DFI  0 (no compress or encrypt)
        if params[0] == 0x00:
            (al, sl), (address, size), data = self.parse_address_size(
                params[1:])
            self.DT_MEM_ADDR = address
            self.DT_UPLOAD = False
            r += b'\x74\x10'+bytes([self.DT_BLOCK_SIZE+2])  # send block len
            return True
        return False

    def respond_request_upload(self, params, r):
        # upload is server->client
        # we only support DFI  0 (no compress or encrypt)
        if params[0] == 0x00:
            (al, sl), (address, size), data = self.parse_address_size(
                params[1:])
            self.DT_MEM_ADDR = address
            self.DT_UPLOAD = True
            r += b'\x75\x10'+bytes([self.DT_BLOCK_SIZE+2])  # send block len
            return True
        return False

    def respond_request_transfer(self, params, r):
        if self.DT_MEM_ADDR is None:
            return False  # transfer not set up
        if self.DT_UPLOAD:  # we are sending data to the client
            s = params[0]
            r += b'\x76'+bytes([s])
            # read block of memory based on seq #
            for loc in range(self.DT_MEM_ADDR+(self.DT_BLOCK_SIZE*(s-1)), self.DT_MEM_ADDR+(self.DT_BLOCK_SIZE*(s))):
                r += bytes([self.MEMORY.get(loc, 0)])
        else:  # client is sending data to us
            s = params[0]
            # set offset based on seq number
            loc = self.DT_MEM_ADDR+(self.DT_BLOCK_SIZE*(s-1))
            for v in params[1:]:  # write block to memory
                self.MEMORY[loc] = v
                loc += 1
            r += b'\x76'+bytes([s])
        return True

    def respond_request_transfer_exit(self, params, r):
        if self.DT_MEM_ADDR is not None:
            self.DT_MEM_ADDR = None
            r += b'\x77'
            return True
        return False

    def respond_diagnostic_session_control(self, params, r):
        if params[0] and params[0] < 4:  # allow anything reasonable
            # P2/P2 extended defaults of 16ms/and 16*256 ms
            r += b'\x50'+bytes([params[0]])+b'\x00\x10\x01\x00'
            self.SESSION = params[0]
            self.event(session_started=True, session_type=params[0])
            return True
        return False

    def respond_ecu_reset(self, params, r):
        # do nothing but say we did
        self.SESSION = None
        self.UNLOCKED = None
        self.SEED = None
        self.event(ecu_reset=params[0])
        r += b'\x51'+bytes([params[0]])
        return True

    def respond_security_access_add1(self, params, r):
        if params[0] == 0x01:  # sendSeed
            if self.UNLOCKED:
                r += b'\x67\x01\x00\x00'
            else:
                self.SEED = secrets.token_bytes(2)
                r += b'\x67\x01'+self.SEED
                self.event(securityaccess='add1', seed=self.SEED)
            return True
        if params[0] == 0x02:  # sendKey
            if not self.UNLOCKED:
                if not self.SEED:
                    r += b'\x7f\x27\x24'
                    return True
                key = params[1:3]
                if len(key) == 2:
                    k = key[0]*256+key[1]
                    c = (self.SEED[0]*256+self.SEED[1])+1
                    self.event(securityaccess='add1', key=k, check=c)
                    if k == c:
                        self.UNLOCKED = True
                        self.SEED = None
                        r += b'\x67\x02'  # good key
                        return True
                r += b'\x7f\x27\x35'  # bad key
                return True
        return False

    def respond_security_access_xor(self, params, r):
        if params[0] == 0x01:  # sendSeed
            if self.UNLOCKED:
                r += b'\x67\x01\x00\x00'
            else:
                self.SEED = secrets.token_bytes(2)
                r += b'\x67\x01'+self.SEED
                self.event(securityaccess='xor', seed=self.SEED)
            return True
        if params[0] == 0x02:  # sendKey
            if not self.UNLOCKED:
                if not self.SEED:
                    r += b'\x7f\x27\x24'
                    return True
                key = params[1:3]
                if len(key) == 2 and key[0] == self.SECRET[0] ^ self.SEED[0] and key[1] == self.SECRET[1] ^ self.SEED[1]:
                    self.event(securityaccess='xor', key=key)
                    self.UNLOCKED = True
                    self.SEED = None
                    r += b'\x67\x02'  # good key
                    return True
                else:
                    r += b'\x7f\x27\x35'  # bad key
                    return True
        return False

    def respond_security_access_m42swap(self, params, r):
        if params[0] == 0x01:  # sendSeed
            if self.UNLOCKED:
                r += b'\x67\x01\x00\x00'
            else:
                self.SEED = secrets.token_bytes(2)
                r += b'\x67\x01'+self.SEED
                self.event(securityaccess='m42swap', seed=self.SEED)
            return True
        if params[0] == 0x02:  # sendKey
            if not self.UNLOCKED:
                if not self.SEED:
                    r += b'\x7f\x27\x24'
                    return True
                key = params[1:3]
                if len(key) == 2:
                    k = key[0]*256+key[1]
                    c = ((self.SEED[0]*256+self.SEED[1]) *
                         42) & 0xffff  # (uint16) seed * 42
                    c = (c & 0xff) << 8 | c >> 8  # swap bytes
                    self.event(securityaccess='m42swap', key=k, check=c)
                    if k == c:
                        self.UNLOCKED = True
                        self.SEED = None
                        r += b'\x67\x02'  # good key
                        return True
                r += b'\x7f\x27\x35'  # bad key
                return True
        return False

    def handle_packet(self, info, msg, **kwargs):
        (pgn, priority, sa, da, data) = self.process_frame(info, msg)
        if data:
            r = bytearray()
            code, params = data[0], data[1:]
            resp = None
            # handle services. r will get data to return, resp will be False if error and True if data good.
            if code == 0x27:
                if self.SESSION:
                    if self.SEC_METHOD == 1:
                        resp = self.respond_security_access_add1(params, r)
                    if self.SEC_METHOD == 2:
                        resp = self.respond_security_access_xor(params, r)
                    if self.SEC_METHOD == 3:
                        resp = self.respond_security_access_m42swap(params, r)
                else:
                    resp = True
                    r += b'\x7f\x27\x22'  # conditionsNotMet
            if code == 0x10:
                resp = self.respond_diagnostic_session_control(params, r)
            if self.SESSION:  # session must be started before anything else works
                if code == 0x11:
                    resp = self.respond_ecu_reset(params, r)
                if code == 0x22:
                    resp = self.respond_read_data_by_identifier(params, r)
                if code == 0x2e:
                    resp = self.respond_write_data_by_identifier(params, r)
                # programming session must be started
                if self.SESSION == 2 and (self.SEC_METHOD == 0 or self.UNLOCKED):
                    if code == 0x23:
                        resp = self.respond_read_memory_by_address(params, r)
                    if code == 0x34:
                        resp = self.respond_request_download(params, r)
                    if code == 0x35:
                        resp = self.respond_request_upload(params, r)
                    if code == 0x36:
                        resp = self.respond_request_transfer(params, r)
                    if code == 0x37:
                        resp = self.respond_request_transfer_exit(params, r)
                    if code == 0x3d:
                        resp = self.respond_write_memory_by_address(params, r)
            # catch all, respond with NR, SID, and service not supported
            if resp is None:
                r += bytes([0x7f, code, 0x11])
            # negative response from code handler
            elif not resp:
                # NR, SID, subfunction not supported
                r += bytes([0x7f, code, 0x12])
            # now send it
            if r:
                self.send_message(r, dst=sa)  # send response

    def stop(self, *args, **kwargs):
        # dump the fake ECU's memory
        print(self.name, '**** MEMORY DUMP ****')
        for addr, data in sorted(self.MEMORY.items()):
            print(hex(addr), hex(data))
            self.event(addr=hex(addr), val=hex(data))
        ISO.stop(self, *args, **kwargs)


class BlockVINChange(UDSProxy):
    '''don't allow VIN change'''

    def effect(self, info, data):
        if data.get('sid') == 0x2e:
            if str(data.get('param', [])[0:2]) == '\xf1\x90':  # if VIN update
                # NR of subsystem not supported
                return self.respond(info, data, sid=0x7f, param=bytearray([0x2e, 0x12]))
        return True  # pass other traffic


class BlockTransfer(UDSProxy):
    def effect(self, info, data):
        if data.get('sid') == 0x34 or data.get('sid') == 0x35:
            # NR of subsystem not supported
            return self.respond(info, data, sid=0x7f, param=bytearray([data.get('sid'), 0x12]))
        return True  # pass other traffic


def test(*args):

    TESTARGS = dict()

    from adf.plugin import Test
    import sys
    logging.basicConfig(level=logging.DEBUG)

    f = Framework()

    logging.info('ISO/UDS test %s' % TESTARGS)

    cmd = f.start_plugin(UDS, name='uds', address=1, **TESTARGS)
    f.start_plugin(UDSResponder, name='udsr', address=0, **TESTARGS)
    t = f.start_plugin(Test, name='DPA')
    f.start_plugin(Test, name='ECU')

    # UDS source <-> Test <-> Proxy <-> Test2 <-> responder
    f.link_plugin('uds', 'DPA')
    if len(args) > 1:
        f.start_plugin(UDSProxy, name='udsp', **TESTARGS)
        f.link_plugin('DPA', 'uds', 'udsp')
        f.link_plugin('udsp', 'DPA', 'ECU')
        f.link_plugin('ECU', 'udsr', 'udsp')
    else:
        f.link_plugin('DPA', 'uds', 'ECU')
        f.link_plugin('ECU', 'udsr', 'DPA')
    f.link_plugin('udsr', 'ECU')

    # get responses to DPA
    f.subscribe('DPA', 'uds')

    # test  data
    print(t.sr('uds', **cmd.diagnostic_session_control(cmd.SESSION_DEFAULT)))
    print(t.sr('uds', **cmd.read_data_by_identifier('VIN')))

    print(t.sr('uds', **cmd.write_data_by_identifier(VIN=b'1234567890ABCDEF')))
    print(t.sr('uds', **cmd.read_data_by_identifier('VIN')))

    print(t.sr('uds', **cmd.ecu_reset()))

    print(t.sr('uds', **cmd.diagnostic_session_control(cmd.SESSION_PROGRAM)))
    print(t.sr('uds', **cmd.read_memory_by_address(0, 64)))
    print(
        t.sr('uds', **cmd.write_memory_by_address(32, bytearray([0x55, 0xaa]))))
    print(t.sr('uds', **cmd.read_memory_by_address(0, 64)))

    print(t.sr('uds', **cmd.request_transfer(0x8000, 0x100)))
    print(t.sr('uds', **cmd.transfer_block(1, range(0, 253))))
    print(t.sr('uds', **cmd.transfer_block(2, range(253, 256))))
    print(t.sr('uds', **cmd.transfer_block()))

    print(t.sr('uds', **cmd.request_transfer(0x8080, 0)))
    print(t.sr('uds', **cmd.transfer_block(1)))
    print(t.sr('uds', **cmd.transfer_block()))

    f.stop()


if __name__ == '__main__':
    test(sys.argv[1:])
