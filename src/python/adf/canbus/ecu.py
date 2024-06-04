#!/usr/bin/env python3
from adf import Plugin, time, threading
from adf.canbus import Message


class ECU(Plugin):
    '''base ECU class.
    receive(id,data) is called when we get a message we listen for
    update() is called every RATE seconds
    transmit() is called every RATE seconds after update()
        should return [ (id,[data]),... ] list of tuples to send'''

    RATE = 0.1  # base update/send cycle time in seconds (lower is faster)
    # intermessage delay, will not affect rate unless total delay exceeds cycle time
    INTER_MESSAGE = 0.01
    # if we are simulating faster/slower than realtime, multiplies rate/intermessage by 1/TDF
    TIME_DELTA_FACTOR = 1.0
    # and can be passed to the model to multiply time deltas.
    EXTENDED_IDS = False  # do we send extended (29-bit) IDs?
    LISTEN = None
    LISTEN_MASK = 0x1FFFFFFF  # by default don't mask any bits of the ID when listening

    periodic = None  # if set, enables and specifies interface for periodic send events

    def init(self):
        # ensure params are floats, if set by config they might be strings
        self.RATE = float(self.RATE)
        self.INTER_MESSAGE = float(self.INTER_MESSAGE)
        self.TIME_DELTA_FACTOR = float(self.TIME_DELTA_FACTOR)
        # change update and message rates based on TDF
        self.INTER_MESSAGE = (1.0/self.TIME_DELTA_FACTOR)*self.INTER_MESSAGE
        self.RATE = (1.0/self.TIME_DELTA_FACTOR)*self.RATE
        # ensure LISTEN is a list
        if self.LISTEN is not None and type(self.LISTEN) is not list:
            self.LISTEN = [self.LISTEN]
        # data of last periodic send, only trigger event if data changes
        self.__last_ps_data = {}

    def effect(self, info, msg):
        '''handle received CAN messages and set params if we care'''
        if self.LISTEN and msg.arbitration_id & self.LISTEN_MASK in self.LISTEN:
            self.receive(msg.arbitration_id, msg.data)
        return info, None  # we don't want to forward traffic, but we might be linked so drop all

    def main(self):
        self.tick = 0  # update ticks
        td = 0.0  # time elapsed while sending messages
        # sleep for the update interval minus the time it took to send
        while not self.is_shutdown(self.RATE-td):
            self.update()  # update internal state
            t = time.time()
            params = self.transmit()  # send params we generate
            for arbid, data in params:
                if arbid is not None:
                    # self.debug('%s: %s',arbid,data)
                    self.dispatch(
                        dict(id=arbid, ts=time.time(), source=self.name),
                        Message(is_extended_id=self.EXTENDED_IDS or arbid >
                                0x7ff, arbitration_id=arbid, data=bytes(data))
                    )
                time.sleep(self.INTER_MESSAGE)
            td = time.time()-t
            self.tick += 1

    def clear_periodic(self):
        '''send event to the self.periodic interface to stop all periodic sends'''
        if self.periodic:
            self.__last_ps_data.clear()
            return self.event(self.periodic,id=None) #send event to interface to stop all sends

    def set_periodic(self, arbitration_id, period, data, duration=None):
        '''send event to the self.periodic interface to start/stop/change periodic sends
        if data is None, will stop any running send of arbitration_id'''
        if self.periodic:  # if periodic send enabled and data has changed, send event to interface to start/change send
            if duration or self.__last_ps_data.get(arbitration_id) != data:
                self.event(self.periodic, id=arbitration_id,
                           period=period, data=data, duration=duration)
                self.__last_ps_data[arbitration_id] = data

    def receive(self, arbid, data):
        '''called when we receive an ID we care about'''
        pass

    def update(self):
        '''perform update actions every tick'''
        pass

    def transmit(self):
        '''send CAN messages based on current params'''
        return []


class Comm(Plugin):
    '''Base class for 2-way communication with an ECU
Comm.talk(arbid,data) to send data to arbid
Comm.listen(arbid,count,timeout) to listen for count frames from arbid with timeout
    listen will return list of frame data'''

    INTER_MESSAGE = 0.0  # rate we send at
    EXTENDED_IDS = False  # do we send extended (29-bit) IDs?
    LISTEN_MASK = 0x1FFFFFFF  # by default don't mask any bits of the ID when listening

    PROP_PGN = 0xEF00  # J1939 proprietary comms PGN
    TP_CM_PGN = 0xEC00  # J1939 TP Control Message BAM|CTS|RTS|ACK handshakes
    TP_DT_PGN = 0xEB00  # J1939 TP Data Transfer  frames

    def init(self):
        self.__buf = []
        self.__listen = None
        self.__rcvd = threading.Event()

    def talk(self, arbid=None, data=None, msg=None, **kwargs):
        if msg:
            self.dispatch(dict(id=msg.arbitration_id,
                          ts=time.time(), source=self.name, **kwargs), msg)
        else:
            self.dispatch(
                dict(id=arbid, ts=time.time(), source=self.name, **kwargs),
                Message(is_extended_id=self.EXTENDED_IDS or arbid >
                        0x7ff, arbitration_id=arbid, data=bytes(data))
            )
        if self.INTER_MESSAGE:
            time.sleep(self.INTER_MESSAGE)

    def listen(self, arbid, count=1, timeout=None):
        # clear buffer
        self.__buf = []
        # start listening for arbid
        self.__listen = arbid
        # listen until we have count frames buffered
        while len(self.__buf) < count:
            # wait for a frame to arrive, stop if timeout happens
            self.__rcvd.clear()
            if not self.__rcvd.wait(timeout):
                break
        self.__listen = None  # stop listening
        return self.__buf  # return what we got

    def effect(self, info, msg):
        # if we are listening and id & mask == the id we are listening for
        if self.__listen and (msg.arbitration_id & self.LISTEN_MASK) == self.__listen:
            # buffer frame data and set received flag
            self.__buf.append(msg)
            self.__rcvd.set()
        return info, None  # we don't forward


class TestECU(ECU):
    LISTEN = 1
    SEND = 2

    def init(self):
        ECU.init(self)
        # define the params the ECU is responsible for here
        self.param_in = None
        self.param_out = 0
        self.tick_count = 0

    def receive(self, arbid, data):
        self.param_in = data[0]//2

    def update(self):
        # if we got a value, set the output to it, else drop off
        if self.param_in is not None:
            self.param_out = self.param_in
            self.param_in = None
        elif not self.tick % 10:  # decay by 1 every 10 ticks (1 second)
            self.param_out = max(0, self.param_out-1)

    def transmit(self):
        return [
            (self.SEND, [self.param_out]),  # we send ID 2
        ]


def test(iface):
    from adf import Framework
    import canbus
    f = Framework()
    ecu = f.start_plugin(TestECU)
    comm = f.start_plugin(Comm)
    comm.link(ecu)
    ecu.link(comm)
    comm.talk(0x1, [0xff])
    time.sleep(1)
    print(comm.listen(2, 16))
    f.stop()
