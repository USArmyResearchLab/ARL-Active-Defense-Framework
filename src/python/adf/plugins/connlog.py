#!/usr/bin/env python
from adf import *


class ConnLog(Plugin):
    '''really simply plugin to log TCP connections'''

    track = {}
    logfile = None
    fh = None
    mode = 'w'

    def __start_log(self):
        if self.loglife:
            self.fh = open(self.logfile, self.mode)
        else:
            self.fh = sys.stdout
        self.info('logging to %s' % self.fh)

    def __tcp_flags(self, f):
        s = ''
        if f & 32:
            s = 'U'
        else:
            s = ' '
        if f & 16:
            s += 'A'
        else:
            s += ' '
        if f & 8:
            s += 'P'
        else:
            s += ' '
        if f & 4:
            s += 'R'
        else:
            s += ' '
        if f & 2:
            s += 'S'
        else:
            s += ' '
        if f & 1:
            s += 'F'
        else:
            s += ' '
        return s

    def effect(self, pktinfo, pkt):
        if pkt and pktinfo.get('proto') == 6:  # if TCP
            tup = (pktinfo['sip'], pktinfo['sport'],
                   pktinfo['dip'], pktinfo['dport'])
            if tup in self.track:  # C->S already tracked
                # client packet,bytes
                cp, cb, sp, sb = 1, len(pktinfo['data']), 0, 0
            elif (tup[2], tup[3], tup[0], tup[1]) in self.track:  # S->C packet and C->S
                # flip addrs to C->S tuple
                tup = (tup[2], tup[3], tup[0], tup[1])
                cp, cb, sp, sb = 0, 0, 1, len(
                    pktinfo['data'])  # server packet,bytes
            elif pkt.ip.tcp.flags & 31 == 2:  # TCP flags are SYN only
                # start tracking: init start ts, end ts, cp, cb, sp, sb
                self.track[tup] = [pktinfo['ts'], pktinfo['ts'], 0, 0, 0, 0]
                # client packet,bytes
                cp, cb, sp, sb = 1, len(pktinfo['data']), 0, 0
            if tup in self.track:
                self.track[tup] = [self.track[tup][0],
                                   pktinfo['ts'],
                                   self.track[tup][2]+cp,
                                   self.track[tup][3]+cb,
                                   self.track[tup][4]+sp,
                                   self.track[tup][5]+sb]
                extra_info = []
                for k, v in sorted(self.config().items()):
                    if k.startswith('extra'):
                        extra_info.append(self.eval_packet(v, pktinfo, pkt))
                if not self.fh:
                    self.__start_log()
                self.fh.write('%s %s %15s:%5s %5s %15s:%5s %6s (%5ds, %d/%d <> %d/%d) %s\n' % (
                    self.name, time.ctime(self.track[tup][1]),
                    tup[0], tup[1],
                    ('%4d>' % cb) if cp else ('<%-4d' % sb),
                    tup[2], tup[3],
                    self.__tcp_flags(pkt.ip.tcp.flags),
                    self.track[tup][1]-self.track[tup][0],
                    self.track[tup][2],
                    self.track[tup][3],
                    self.track[tup][4],
                    self.track[tup][5],
                    ' '.join(extra_info)))
        return pktinfo, pkt  # forward the packet
