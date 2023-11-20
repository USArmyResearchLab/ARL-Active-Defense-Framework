import sys
import logging
import time
from adf import *
from adf.canbus import *
import struct


class Log(Plugin):
    '''really simple plugin to log CAN/J1708 traffic and Events'''
    file = None
    fh = None
    mode = 'w'

    def start_log(self):
        if self.file:
            self.fh = open(self.file, self.mode)
        else:
            self.fh = sys.stdout
        self.log('logging to %s' % self.fh)

    def effect(self, pktinfo, msg):
        if not self.fh:
            self.start_log()
        if type(msg) is Event:
            _write_csv_event(self.fh, msg)
            return pktinfo, None  # don't dispatch events
        elif type(msg) is Message:
            _write_csv_can(self.fh, msg)
        else:
            _write_csv_j1708(
                self.fh, pktinfo['ts'], pktinfo['source'], pktinfo['MID'], msg, pktinfo['checksum'])
        return pktinfo, msg  # forward if we are inline

    # this is a bit oddish, we inject an event into the packet q to maintain order
    def handle_event(self, event): self.inject({}, event)

    # flush log on idle
    def idle(self, count):
        if self.fh:
            self.fh.flush()


class Capture(Plugin):
    file = None
    fh = None
    '''write CAN packets to a pcap file of DLT LINKTYPE_CAN_SOCKETCAN (227)'''

    def start_log(self):
        if self.file:
            self.fh = open(self.file, 'wb')
        # magic, version 2.4, no tzoffset, no sigfigs,snaplen,DLT
        self.fh.write(struct.pack(
            '!IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 227))
        self.log('wrote PCAP header to %s' % self.fh)

    def effect(self, info, msg):
        if not self.fh:
            self.start_log()
        if self.fh and type(msg) is Message:  # we can only write CAN
            ts = int(msg.timestamp)
            uts = int((msg.timestamp-ts)*1000000)
            msg_id = msg.is_error_frame << 29 | msg.is_remote_frame << 30 | msg.is_extended_id << 31 | msg.arbitration_id
            #ts_sec,ts_usec,incl_len,orig_len,arb_id,DLC,0,0,0 + data
            self.fh.write(struct.pack('!IIIIIBBBB', ts, uts, 8+len(msg.data),
                          8+len(msg.data), msg_id, len(msg.data), 0, 0, 0)+msg.data)
        return info, msg


class Replay(Plugin):
    '''replays CAN/J1708 from CSV log
        file is opened when log config value is set
        first packet will be emitted immediately after file is opened
        remaining packets will follow timestamp deltas
        if channel is set, channel field must start with filter string
        dest in pktinfo will be set to channel
        config: log/fh = file/filename to read
        can_channel = string channel field must contain to be considered can traffic. Default is 'can'
        j1708_channel = string channel field must contain to be considered j1708 traffic. Default is 'j'
        use_ts = if True use timestamp values from file, else use current timestamp 
        delta = delay between messages, if True, use ts delta, if False replay as fast as possible '''
    file = None
    fh = None
    can_channel = 'can'
    use_ts = False
    delta = True
    j1708_channel = None
    count = None

    def read_csv(self, infh, can_channel, j1708_channel):
        return _read_csv(infh, can_channel, j1708_channel)

    def open_file(self):
        if self.file:
            if self.file.endswith('.gz'):
                import gzip
                self.fh = gzip.open(self.file, 'rt')
            else:
                self.fh = open(self.file)
        self.log('reading from %s', self.fh)

    def main(self):
        '''reader thread'''
        last_ts = None
        c = 0
        while not self.is_shutdown():
            try:
                if not self.fh:  # wait to get the filename in the config.
                    time.sleep(1)
                    if self.file:
                        self.open_file()
                    continue
                d = self.read_csv(self.fh, self.can_channel,
                                  self.j1708_channel)  # get from csv
                if not d:
                    continue
                c += 1
                # replaying can and channel name match?
                if type(d) is Message and self.can_channel and self.can_channel in d.channel:
                    msg = d
                    ts = msg.timestamp
                    if not self.use_ts:
                        msg.timestamp = time.time()
                    pktinfo = {'ts': msg.timestamp, 'source': self.name,
                               'dest': msg.channel, 'id': msg.arbitration_id}
                # replaying j1708 and latch
                elif self.j1708_channel and self.j1708_channel in d[1]:
                    ts, channel, mid, msg, checksum = d
                    if self.use_ts:
                        pktinfo = {'ts': ts, 'source': self.name,
                                   'MID': mid, 'dest': channel, 'checksum': checksum}
                    else:
                        pktinfo = {'ts': time.time(), 'source': self.name,
                                   'MID': mid, 'dest': channel, 'checksum': checksum}
                else:
                    continue
                if self.delta:
                    if self.delta is True:
                        if last_ts and ts > last_ts:
                            time.sleep(ts-last_ts)  # maintain timestamp delta
                    else:
                        time.sleep(float(self.delta))
                last_ts = ts
                self.handle_packet(pktinfo, msg)  # send the decoded message
                if self.count and c == self.count:
                    raise StopIteration
            except StopIteration:
                self.log('finished reading %s (%s)', self.file, last_ts)
                self.fh.close()
                self.stop()
                break  # EOF
            except Exception as e:  # read error
                self.error(e, exc_info=True)
                self.stop()
                break


def _read_csv(infh, can_channel='can', j1708_channel='j'):
    while True:
        line = infh.readline()
        if not line:
            raise StopIteration
        try:
            line = line.strip().split(',')
            timestamp = float(line[0])
            channel = line[1]
            if can_channel and can_channel in channel:
                return _read_csv_can(line)
            if j1708_channel and j1708_channel in channel:
                return _read_csv_j1708(line)
        except:
            pass


def _read_csv_can(line):
    try:
        timestamp = float(line[0])
        channel = line[1]
        arbitration_id = int(line[2], 16)
        l = int(line[3])
        data = bytearray()
        for i in range(4, 4+l):
            data.append(int(line[i], 16))
        try:
            return Message(timestamp=timestamp, channel=channel, arbitration_id=arbitration_id, data=data,
                           is_fd=(len(data) > 8))
        except Exception as e:
            print(e)
    except:
        pass


def _read_csv_j1708(line):
    try:
        timestamp = float(line[0])
        channel = line[1]
        mid = int(line[2], 16)
        l = int(line[3])
        data = bytearray()
        for i in range(4, 4+l):
            data.append(int(line[i], 16))
        checksum = int(line[4+l], 16)
        try:
            return timestamp, channel, mid, data, checksum
        except Exception as e:
            print(e)
    except Exception as e:
        print(e)


def _write_csv_can(outfh, msg):
    line = []
    line.append(str(msg.timestamp))
    line.append(str(msg.channel))
    line.append('%08x' % msg.arbitration_id)
    line.append(str(msg.dlc))
    line.extend(['%02x' % d for d in msg.data])
    outfh.write(','.join(line)+'\n')


def _write_csv_j1708(outfh, timestamp, channel, mid, data, checksum):
    line = []
    line.append(str(timestamp))
    line.append(str(channel))
    line.append('%02x' % mid)
    line.append(str(len(data)))
    line.extend(['%02x' % d for d in data])
    line.append('%02x' % checksum)
    outfh.write(','.join(line)+'\n')


def _write_csv_event(outfh, event):
    line = []
    line.append(str(event.get('ts', time.time())))
    line.append(str(event.name))
    for k, v in event.data().items():
        line.append("%s:%s" % (k, v))
    outfh.write(','.join(line)+'\n')
