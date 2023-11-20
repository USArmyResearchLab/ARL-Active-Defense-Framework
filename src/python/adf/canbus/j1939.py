#!/usr/bin/env python
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from adf.canbus.logger import Log
import cmath
import sys
from adf import *
from adf.canbus import Message


def is_param_valid(params, param):
    # returns SPN if parameter is valid, and the value range
    if param.startswith('spn'):
        spn = param.split()[0]
        if params.get(spn.replace('spn', 'valid')):
            return spn, params.get(spn.replace('spn', 'range'))
    return None, (None, None)


def J1939EncodeId(**info):
    '''arbitration ids are ppprdPPPPPPPPDDDDDDDDSSSSSSSS
        p=priority, r=reserved, d=datapage, P=protocol-family, D=destination/group, S=source
        PGN is composed of r+d+P+D bits
        args are shifted and ored as priority << PGN | (R << DP << PF << PS|GE|DA) << SA'''
    pgn = info.get('PGN', 0) | info.get('R', 0) << 17 | info.get('DP', 0) << 16 | info.get('PF', 0) << 8 | \
        (info.get('PS', 0) | info.get('DA', 0) | info.get('GE', 0))
    return info.get('priority', 0) << 26 | pgn << 8 | info.get('SA', 0)


def J1939DecodeId(msg):
    '''decode arbitration ID to J1939 header fields'''
    info = {}
    # 29 bit arb id fields
    # 10987654 32109876 54321098 76543210
    # ...pppRD PFPFPFPF PSPSPSPS SASASASA
    info['priority'] = msg.arbitration_id >> 26
    info['SA'] = msg.arbitration_id & 0x000000ff
    # PGN mask
    # 00000011 111111111 11111111 00000000
    # 03       FF        FF       00
    info['PGN'] = (msg.arbitration_id & 0x03ffff00) >> 8
    # PGN format
    # 000000RD PFPFPFPF PSPSPSPS
    info['R'] = info['PGN'] >> 17
    info['DP'] = (info['PGN'] & 0x010000) >> 16
    info['PF'] = (info['PGN'] & 0x00ff00) >> 8
    info['PS'] = (info['PGN'] & 0x0000ff)
    # PF 0xf0-0xff is Broadcast and PS is group extension (GE)
    # PF 0xEC is TP_CM, PF 0xEB is TP_DT,
    # lower is Unicast and PS is dest (DA)
    if info['PF'] >= 0xf0:
        info['type'] = 'PDU2'
        info['GE'] = info['PS']
    elif info['PF'] == 0xec:
        info['type'] = 'TP_CM'
    elif info['PF'] == 0xeb:
        info['type'] = 'TP_DT'
    else:
        info['type'] = 'PDU1'
        info['DA'] = info['PS']
        info['PGN'] &= 0x3ff00  # mask low 8 on PDU1 for decoding
    return info


def J1939DecodeCM(msg=None, cm={}, data=None):
    '''decode PF=0xEC CM_TP.* messages
        return CM object'''
    if not data:
        data = msg.data
    if data[0] == 32:  # BAM Code|BBytes|Packets|reserved|PGN
        cm['BAM'] = True
        if 'CTS' in cm:
            del cm['CTS']
        if 'RTS' in cm:
            del cm['RTS']
        cm['bytes'] = data[2] << 8 | data[1]
        cm['packets'] = data[3]
        cm['PGN'] = data[7] << 16 | data[6] << 8 | data[5]
        cm['DT'] = {}
    elif data[0] == 16:  # RTS C|BB|P|r|PGN
        cm['RTS'] = True
        if 'BAM' in cm:
            del cm['BAM']
        cm['bytes'] = data[2] << 8 | data[1]
        cm['packets'] = data[3]
        cm['PGN'] = data[7] << 16 | data[6] << 8 | data[5]
        cm['DT'] = {}
    elif data[0] == 17:  # CTS C|P|N|r|r|PGN
        cm['CTS'] = True
        if 'BAM' in cm:
            del cm['BAM']
        cm['packets'] = data[1]
        cm['next_seq'] = data[2]
        cm['PGN'] = data[7] << 16 | data[6] << 8 | data[5]
    elif data[0] == 19:  # ACK C|BB|P|r|PGN
        cm['ACK'] = True
        cm['bytes'] = data[2] << 8 | data[1]
        cm['packets'] = data[3]
        cm['PGN'] = data[7] << 16 | data[6] << 8 | data[5]
    elif data[0] == 255:  # abort
        cm['ERR'] = data[1]
    return cm


def J1939EncodeCM(cm):
    '''Encodes TP_CM message and converts data (if present) into DT frames, setting bytes/packets fields
    CM should have BAM|RTS|CTS|ACK=True to set mode, the embedded DT PGN set, and SA|DA|priority for the arb ID
    also bytes/packets fields set or data set
    returns CAN Message and modifies cm in place, setting bytes/packets, del data key and setting DT key'''
    data = bytearray([0xff]*8)
    if 'data' in cm:  # consume data into DT chunks
        d = bytearray(cm['data'])
        cm['bytes'] = cm.get('bytes', len(d))
        cm['DT'] = {}
        i = 1
        while d:
            cm['DT'][i], d = d[0:7], d[7:]
            i += 1
        del cm['data']
        cm['packets'] = cm.get('packets', len(cm['DT']))
    if cm.get('BAM'):  # C|BB|P|r|PGN
        data[0] = 0x20
        data[2] = cm['bytes'] >> 8
        data[1] = cm['bytes'] & 0xff
        data[3] = cm['packets']
        data[7] = cm['PGN'] >> 16
        data[6] = cm['PGN'] >> 8 & 0xff
        data[5] = cm['PGN'] & 0xff
    elif cm.get('RTS'):  # C|BB|P|r|PGN
        data[0] = 0x10
        data[2] = cm['bytes'] >> 8
        data[1] = cm['bytes'] & 0xff
        data[3] = cm['packets']
        data[7] = cm['PGN'] >> 16
        data[6] = cm['PGN'] >> 8 & 0xff
        data[5] = cm['PGN'] & 0xff
    elif cm.get('CTS'):  # C|P|1|rr|PGN
        data[0] = 0x11
        data[1] = cm['packets']
        data[2] = 0x01  # we'll start at first packet
        data[7] = cm['PGN'] >> 16
        data[6] = cm['PGN'] >> 8 & 0xff
        data[5] = cm['PGN'] & 0xff
    elif cm.get('ACK'):  # C|BB|P|r|PGN
        data[0] = 0x13
        data[2] = cm['bytes'] >> 8
        data[1] = cm['bytes'] & 0xff
        data[3] = cm['packets']
        data[7] = cm['PGN'] >> 16
        data[6] = cm['PGN'] >> 8 & 0xff
        data[5] = cm['PGN'] & 0xff
    elif cm.get('ERR'):
        data[0] = 0xff
        data[1] = cm.get('ERR')
    return Message(arbitration_id=J1939EncodeId(
        PGN=0xEC00,
        priority=cm.get('prioriy', 7),
        SA=cm.get('SA', 0),
        DA=cm.get('DA', 0)
    ), dlc=8, data=data)


def J1939DecodeDT(msg, cm):
    '''decode PF=0xEB CM_TP.DT message, add to DT of existing cm object'''
    data = msg.data
    # first byte is seq no, rest is data
    seq = data[0]
    if 'DT' in cm:
        cm['DT'][seq] = data[1:]  # strip off seq No
    return (seq == (cm['packets']))  # return True if last packet (DT complete)


def J1939JoinDT(cm):
    '''Join all DT messages in a cm object'''
    if not 'DT' in cm:
        return None
    data = bytearray()
    for s in range(1, cm['packets']+1):
        data.extend(cm['DT'][s])
    del cm['DT']  # clear unassembled data
    return data[0:cm['bytes']]


def J1939EncodeDT(cm):
    '''generate CM_TP.DT messages from cm with DT key set (call J1939EncodeCM with cm['data'] set first)'''
    for seq, d in sorted(cm['DT'].items()):
        yield Message(arbitration_id=J1939EncodeId(
            PGN=0xEB00,
            priority=cm.get('prioriy', 7),
            SA=cm.get('SA', 0),
            DA=cm.get('DA', 0)
        ), dlc=8, data=bytearray([seq])+d)


class J1939Decoder(Plugin):
    TP_TRACK = {}  # transport protocol state tracking
    pgn = {}  # PGN decoding expressions

    def __decode_id(self, info, msg):
        try:
            info.update(J1939DecodeId(msg))
        except Exception as e:
            self.warning(e)

    def __decode_cm(self, msg, cm={}):
        try:
            return J1939DecodeCM(msg, cm)
        except Exception as e:
            self.warning(e)

    def __decode_dt(self, msg, cm):
        try:
            return J1939DecodeDT(msg, cm)
        except Exception as e:
            self.warning(e)

    def __join_dt(self, cm):
        try:
            return J1939JoinDT(cm)
        except Exception as e:
            self.warning(e)

    def effect(self, info, msg):
        # create the J1939 key and decode the 29-bit arb id
        j = info.setdefault('J1939', {})
        self.__decode_id(j, msg)
        # decode more stuff here
        try:
            # PF will change but PS/SA should not for a given CM and following DT
            tid = j['PS'] << 8 | j['SA']  # tracking id is PS and SA fields,
            if j['type'] == 'TP_CM':  # CM message
                cm = self.__decode_cm(msg, self.TP_TRACK.setdefault(
                    tid, {}))  # init/get state and decode
                if cm:
                    if 'data' in cm:
                        del cm['data']  # clear old assembled data
                    j['TP'] = cm  # add to info
                    # end of message or error, remove state
                    if ('ACK' in cm) or ('ERR' in cm):
                        del self.TP_TRACK[tid]
            elif j['type'] == 'TP_DT':  # DT message
                cm = self.TP_TRACK.get(tid)  # get state if tracked
                if cm:  # DT message for established TP, else ignore
                    if 'data' in cm:
                        del cm['data']  # clear old assembled data
                    j['TP'] = cm
                    # if complete, join data
                    if self.__decode_dt(msg, cm):
                        cm['data'] = self.__join_dt(cm)
                        # decode PGN if configured
                        self.__decode_pgn(cm, cm['data'])
            else:
                self.__decode_pgn(j, msg.data)  # decode PGN if configured
        except Exception as e:
            self.warning(e)
        # return the decoded info
        return info, msg

    def __decode_pgn(self, info, data):
        # if PGN=nnnnn and pgn.nnnnn=<expr> in config, decode using expr
        x = self.pgn.get(str(info['PGN']))
        if x:
            p = info.setdefault('params', {'PGN': info['PGN']})
            p.update(eval(x, globals(), {'data': data}))
            return p


class J1939ParamEncoder(Plugin):
    # re-encodes params to the data, we currently only support type PDU2
    def effect(self, info, msg):
        # there should be a PGN key in the J1939 data if there are decoded params
        p = info.get('J1939', {}).get('params')
        try:
            if p and 'PGN' in p:
                self.__encode_pgn(p, msg.data)
        except Exception as e:
            self.warning(e)
        return info, msg

    def __encode_pgn(self, p, data):
        # if PGN=nnnnn and pgn.nnnnn=<expr> in config, encode using expr
        x = self['pgn.%d' % p['PGN']]
        # modify data[] using p{}
        if x:
            exec(x, globals(), {'params': p, 'data': data})
            return True
        return False


class J1939Log(Log):
    def effect(self, pktinfo, msg):
        if not self.fh:
            self.start_log()
        j = pktinfo.get('J1939')
        if j:
            self.fh.write('%s %s J1939 p%d %6d %02x->' % (self.name,
                          pktinfo['source'], j['priority'], j['PGN'], j['SA']))
            if j['type'] == 'PDU1':
                self.fh.write('%02x' % j['DA'])
            else:
                self.fh.write('**')
            self.fh.write(' %5s' % j['type'])
            if 'params' in j:
                p = j['params']
                self.fh.write(' pgn%s %s %s' % (p['PGN'], p['name'], ' '.join(('%s:%s' % (
                    k, v) for (k, v) in sorted(p.items()) if (k != 'name' and k != 'PGN')))))
            elif 'TP' in j and 'data' in j['TP']:
                self.fh.write(' %s' % repr(j['TP']))
            else:
                self.fh.write(' '+' '.join('%02x' % b for b in msg.data))
        self.fh.write('\n')
        self.fh.flush()
        return pktinfo, msg  # forward packet if we are inline

# unit tests


def test(*args):
    f = Framework()
    p = f.start_plugin(J1939Decoder)
    # test encode decode of IDs
    di, msg = p.effect({}, Message(arbitration_id=J1939EncodeId(
        priority=0, PGN=0x1ff00, DA=1, SA=0xff)))
    j = di['J1939']
    print(msg, j)
    assert (j == {'priority': 0, 'SA': 255, 'PGN': 130817, 'R': 0,
            'DP': 1, 'PF': 255, 'PS': 1, 'type': 'PDU2', 'GE': 1})
    di, msg = p.effect({}, Message(
        arbitration_id=J1939EncodeId(priority=7, DA=3, SA=1, PF=239)))
    j = di['J1939']
    print(msg, j)
    assert (j == {'priority': 7, 'SA': 1, 'PGN': 61184, 'R': 0,
            'DP': 0, 'PF': 239, 'PS': 3, 'type': 'PDU1', 'DA': 3})

    # test encode/decode of CMs
    # arbitration_id=0x00ec0001,data=[0x10,0x07,0x00,0x01,0xff,0x00,0xef,0x00])
    di, msg = p.effect({}, J1939EncodeCM(
        dict(RTS=True, SA=1, PGN=61184, data=[0]*7)))
    tp = di['J1939']['TP']
    print(msg, tp)
    assert (tp == {'RTS': True, 'bytes': 7,
            'packets': 1, 'PGN': 61184, 'DT': {}})
    # di,msg=p.effect({},Message(arbitration_id=0x00ec0100,data=[0x11,0x01,0x01,0xff,0xff,0x00,0xef,0x00]))
    di, msg = p.effect({}, J1939EncodeCM(
        dict(CTS=True, DA=1, PGN=61184, data=[0]*7)))
    tp = di['J1939']['TP']
    print(msg, tp)
    assert (tp == {'CTS': True, 'next_seq': 1, 'packets': 1, 'PGN': 61184})

    # test encode decode of single frame DT
    cm = dict(BAM=True, SA=1, PGN=61184, data=[
              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    di, msg = p.effect({}, J1939EncodeCM(cm))
    tp = di['J1939']['TP']
    print(msg, tp, cm)
    assert (tp == {'BAM': True, 'bytes': 7,
            'packets': 1, 'PGN': 61184, 'DT': {}})
    for msg in J1939EncodeDT(cm):
        di, msg = p.effect({}, msg)
        tp = di['J1939']['TP']
        print(msg, tp)

    # test multi frame DT
    cm = dict(BAM=True, SA=1, PGN=61184, data=list(a for a in range(16)))
    di, msg = p.effect({}, J1939EncodeCM(cm))
    tp = di['J1939']['TP']
    print(msg, tp, cm)
    assert (tp == {'BAM': True, 'bytes': 16,
            'packets': 3, 'PGN': 61184, 'DT': {}})
    di, msg = p.effect({}, Message(arbitration_id=0x00ec0001, data=[
                       0x20, 0x10, 0x00, 0x03, 0xff, 0x00, 0xef, 0x00]))
    tp = di['J1939']['TP']
    print(msg, tp)
    for msg in J1939EncodeDT(cm):
        di, msg = p.effect({}, msg)
        tp = di['J1939']['TP']
        print(msg, tp)
    assert (tp == {'bytes': 16, 'packets': 3, 'PGN': 61184,
            'BAM': True, 'data': bytearray(a for a in range(16))})
    f.stop()
