#!/usr/bin/env python3

import sys
from csv import DictReader

global slot, pgn, spn
slots = {None: None}
params = {}

slot_csv, param_csv = DictReader(open(sys.argv[1], errors='ignore')), DictReader(
    open(sys.argv[2], errors='ignore'))

# config text, %s gets PGN
if len(sys.argv) > 3:
    config_text = sys.argv[3]
else:
    config_text =\
        '''config-plugin decode "pgn.%s=%s"'''

# expression variable text, %s gets byte position
if len(sys.argv) > 4:
    data_var = sys.argv[4]
else:
    data_var = 'data[%s]'

for slot in slot_csv:
    i, n, t = int(slot['SLOT Identifier']
                  ), slot['SLOT Name'], slot['SLOT Type']
    s, l, o = slot['Scaling'], slot['Length'], slot['Offset']
    if s and l and o:
        try:
            if 'byte' in l:
                l = int(l.split()[0])*8
            else:
                l = int(l.split()[0])
        except:
            l = None

        try:
            if n.startswith('SAEb'):
                s = None  # Bitmapped or bitfield, no scaling
            else:
                # split on spaces to get numeric value,
                s = s.split()[0].replace(',', '')
                if '/' in s:
                    s = 1.0/float(s.split('/')[1])  # fractional value per bit
                elif '^' in s:
                    s = 10**float(s.split('^')[1])  # exponential scaling
                else:
                    s = float(s)  # direct scaling
        except:
            s = None  # no scaling information

        try:
            o = float(o.split()[0].replace(',', ''))
        except:
            o = None
        if o == 0.0:
            o = None

    slots[i] = {'type': t, 'scaling': s, 'length': l, 'offset': o}


for param in param_csv:
    try:
        pgn, label, spn, name, src = int(param['PGN']), param['Parameter Group Label'], int(
            param['SPN']), param['Name'], param['Acronym']
    except Exception as e:
        continue  # print pgn,e
    try:
        slot = int(param['SLOT Identifier'])
        # position in frame will be something like START_BYTE.start_bis-END_BYTE.end_bit
        # bytes are 12345678 leftmost to rightmost, and bits are ALSO 12345678 with 1=MSb and 8=LSb
        # only take start byte pos, length tells us the rest
        p = param['pos'].split('-')[0]
        if '.' in p:
            p, b = (int(v, 16) for v in p.split('.'))  # byte.bit position
        else:
            p, b = int(p, 16), 1
        # convert byte from 12345678... to 01234567..., bit from 12345678 to 87654321
        params.setdefault(pgn, {'label': label, 'source': src, 'params': {}})[
            'params'].setdefault(spn, {'byte': p-1, 'bit': 9-b, 'name': name}).update(slots[slot])
    except Exception as e:
        continue  # print e,param

for pgn, p in sorted(params.items()):
    exps = []
    for spn, s in sorted(p['params'].items()):
        name, byte_pos, bit_pos, length, scaling, offset = s['name'], s[
            'byte'], s['bit'], s['length'], s['scaling'], s['offset']
        print('# pgn%s %s spn%s %s pos:%s.%s len:%s *%s +%s' %
              (pgn, p['source'], spn, s['name'], s['byte'], s['bit'], s['length'], s['scaling'], s['offset']))
        if 'PropA' in name or 'PropB' in name:
            continue  # skip proprietary PGNs
        if length:
            pmin = 0
            pmax = (2**length)-1
            exp = ''
            # J1939 values are little endian, so it will go LSB,...,MSB,MSbs
            while length:  # while we have bits left to decode
                if exp:
                    exp += '|'  # or positions together
                # bytes and bits remaining in length
                byte, bits = divmod(length, 8)
                if bits:
                    byte += 1  # if extra significant leftmost bits, carry to next byte
                byte -= 1
                exp += data_var % (byte_pos+byte)  # get the byte pos
                if bits:  # if processing most significant bits
                    if bit_pos < 8:
                        # if not left-aligned mask off high bits
                        exp = '(%s&%s)' % (exp, 2**(bit_pos)-1)
                    if bits and (bits < bit_pos):
                        # if not right-aligned shift right
                        exp = '%s>>%s' % (exp, (bit_pos-bits))
                    length -= bits
                    bits = 0
                else:
                    length -= 8  # consume whole byte
                if byte:
                    # if not LSB, shift into position
                    exp = '%s<<%s' % (exp, 8*byte)
            exp_raw = exp
            if scaling:  # if scaling, max raw value == INVALID
                exp_valid = '(%s!=%s)' % (exp, pmax)
                if scaling != 1.0:
                    exp = 'float(%s)*%s' % (exp, scaling)
                    pmax *= scaling
            else:
                exp_valid = 'True'  # unscaled, is a bit field or map
            if offset:
                if offset < 0:
                    exp = '(%s)-%s' % (exp, -offset)
                else:
                    exp = '(%s)+%s' % (exp, offset)
                pmin += offset
                pmax += offset
            else:
                offset = 0.0
            n = name.replace('#', '').replace('"', '').replace("'", '')
            exps.append("'spn%s %s':%s, 'range%s':%s, 'valid%s':%s, 'raw%s':%s" % (spn, n, exp,
                                                                                   spn, '(%s,%s)' % (
                                                                                       pmin, pmax),
                                                                                   spn, exp_valid,
                                                                                   spn, exp_raw))
    if exps:
        print(config_text %
              (pgn, "{'name':'%s',%s}" % (p['source'].replace('/', ''), ','.join(exps))))
