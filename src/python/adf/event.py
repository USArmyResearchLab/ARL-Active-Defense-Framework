from adf import *


class Event(object):
    '''generic event class, just stores data passed to it
special attributes are:
    name: event name, plugins that subscribe to this name will get event
    path: list of plugins that have seen this event, plugin will not get an event if it is already in the path
    sync: if True, event handling queue will stop while this event is being handled
'''

    def __init__(self, __name='event', source=None, sync=False, *args, **kwargs):
        '''name=event name, source=event source, initializes path'''
        self.name = __name  # event name, plugins can subscribe to this
        self.path = []  # event handling path, list of plugin names
        if source:
            self.path.append(source)
        self.sync = sync
        self.__data = {}
        self.data(*args, **kwargs)

    def __str__(self): return '%s %s %s' % (
        self.name, self.path, self.__data)  # return event as string

    def __iter__(self):  # return keys in data
        for d in self.__data:
            yield d
    # access data using dotted-keys
    def get(self, k, default=None): return dk_get(self.__data, k, default)
    def set(self, k, v): return dk_update(self.__data, k, v)
    def delete(self, k): return dk_del(self.__data, k)
    # access data as dict
    def setdefault(
        self, k, default=None): return self.__data.setdefault(k, default)

    def update(self, *args, **kwargs): self.__data.update(*args, **kwargs)
    def __getitem__(self, k): return self.__data[k]
    def __delitem__(self, k): del self.__data[k]
    def __setitem__(self, k, v): self.__data[k] = v
    def keys(self): return self.__data.keys()
    def values(self): return self.__data.values()
    def items(self): return self.__data.items()
    # access data as attributes (read only)
    def __getattr__(self, k): return self.get(k)
    # bulk set/return/evaluate event data

    def data(self, *args, **kwargs):
        '''set/get event data
           we need to be able to accept data as tuples or a dict'''
        for a in args:
            kwargs.update(a)
        self.__data.update(**kwargs)
        return self.__data.copy()  # return copy of data as dict

    def eval(self, expr):
        '''eval expression with event data as locals'''
        return eval(expr, globals(), self.__data)
    # because we override __getattr__ we need these to be able to pickle
    def __getstate__(self): return self.__dict__
    def __setstate__(self, d): self.__dict__.update(d)


''' EVENT HANDLER PLUGINS '''

from .plugin import Plugin #Plugin imports Event so this import cannot come before the Event class def.


class Listener(Plugin):
    '''receives Events via TCP from Sender, queues them'''
    listen = 'localhost'
    port = 42224

    def main(self):
        import socketserver

        class EventSocket(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    l = struct.unpack('!L', self.request.recv(4))[0]
                    event = pickle.loads(self.request.recv(l))
                    event.path.append(self.server.parent.name)
                    self.server.parent.debug(
                        '%s %s %s', self.client_address, l, event)
                    # we're not a Plugin instance so we have to call event in the parent
                    self.server.parent.event(event=event)
                except Exception as e:
                    self.server.parent.debug(e)

        class EventServer (socketserver.TCPServer):
            allow_reuse_address = True

        self.__server = EventServer((self.listen, int(self.port)), EventSocket)
        self.__server.parent = self
        self.log('event socket is %s', str(self.__server.server_address))
        self.__server.serve_forever()  # start listening

    def shutdown(self):
        if self.__server:
            self.__server.shutdown()
            self.debug('%s was shut down', self.__server)
        Plugin.stop(self)

    # in case we are running in a separate context, call shutdown in that context
    def stop(self, *args): self.call_method('shutdown')


class Sender(Plugin):
    '''sends events via TCP to Listener'''
    host = 'localhost'
    port = 42224
    timeout = 60
    __socket = None

    def send(self, event):
        # turn event into a generic dict
        data = pickle.dumps(event)
        if not self.__socket:  # open socket
            self.__socket = socket.create_connection(
                (self.host, int(self.port)), 1)
        self.debug('sent %s %s %r', self.__socket, len(data), data)
        # send length followed by data
        self.__socket.sendall(struct.pack('!L', len(data)))
        self.__socket.sendall(data)

    def handle_event(self, event):
        self.send(event)  # send event if we handle it
        return True

    def idle(self, count):
        # close socket on idle
        if self.__socket and self.timeout and (not count % self.timeout):
            self.__socket.close()
            self.__socket = None

    def shutdown(self):
        if self.__socket:
            self.__socket.close()
        Plugin.stop(self)

    # in case we are running in a separate context, call shutdown in that context
    def stop(self, *args): self.call_method('shutdown')


class Channel(Plugin):
    '''sends/receives events via UDP

            packet format is:

            FSSSSSSS SSSSSSSS data...
            FS: F|15-bit Sequence number. F bit set indicates last packet.

            config (must be set at plugin load)
            port=<UDP port>. Default is 42223

            addr=<IP> 
                send messages to this IP.
                can be broadcast (example: 192.168.0.255 for 192.168.0.0/24)

            listen=<IP> 
                use an assigned unicast ip, broadcast IP, or 0.0.0.0 for all addresses.

            size=max bytes per UDP packet, not including header, default 1024
    '''
    listen = None
    addr = None
    port = 42223
    size = 1024

    def handle_event(self, e):
        '''send event on channel'''
        if self.addr:
            self.send(pickle.dumps(e))  # ensure data is pickle-shaped

    def send(self, data):
        i = s = 0
        if self.__socket:
            while i < len(data):  # send all packets with proper headers
                self.__socket.sendto(
                    # pack header: FSSSSSSS SSSSSSSS
                    struct.pack('!H', int(i+self.size >= len(data))
                                << 15 | s) + bytes(data[i:i+self.size]),
                    (self.addr, self.port)
                )
                s += 1
                i += self.size

    def flush(self, addr):
        '''handle received data'''
        # generate event from data
        try:
            # unpickle
            e = pickle.loads(
                b''.join(v for (k, v) in sorted(self.__buf[addr].items())))
            # set source
            e.path.append(self.name)
            # send event
            del self.__buf[addr]
            self.event(event=e)
        except Exception as e:
            self.warning(e, exc_info=True)

    def main(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if self.addr:
            self.log('sending to %s:%s', self.addr, self.port)
        if self.listen:
            self.__socket.bind((self.listen, int(self.port)))
            self.log('listening on %s:%s', self.listen, self.port)
        self.__socket.settimeout(1)
        self.__buf = {}  # packet buffer
        while not self.is_shutdown():
            try:
                addr = None
                # get packet
                if not self.__socket:
                    continue
                pkt, addr = self.__socket.recvfrom(65535)
                s = struct.unpack('!H', pkt[0:2])[0]  # get header
                # buffer by [source][seq]
                self.__buf.setdefault(addr, {})[s & 0x7fff] = pkt[2:]
                if s & 0x8000:
                    self.flush(addr)  # if fin, flush it
            except socket.timeout:
                continue
            except Exception as e:
                self.warning('%s from %s', e, addr, exc_info=True)
        self.__socket.close()


class Migrate(Plugin):
    '''pretty simple plugin to do state migration via event
        if we set config item trigger and we get a <trigger> event, we dump the state into a <output> event.
            this would typically get sent by EventSender to another instance's EventListener
        we are also listening for <name> event to migrate incoming state. 
        If restore is set we also migrate config'''
    trigger = None
    output = None
    flush = False
    restore = False

    def init(self):
        if not self.output:
            self.output = self.name

    def handle_event(self, event):
        '''this is fun. we have to tell the framework process to dump the state, then send it along
            when we receive state, we have to let the framework handle it'''
        if event.name == self.trigger:
            self.log("send state triggered")
            self.call('dump_state', name=self.output)
        elif event.name == self.name:
            self.log("got incoming state from event")
            # pass state to load_state in framework process
            self.call('load_state', flush=self.flush,
                      restore=self.restore, state=event['state'])


try:
    import paho.mqtt.client as mqtt
    import json

    class MQTT(Plugin):
        '''send/receive events via Paho-MQTT'''
        client = None
        host = 'localhost'
        port = 1883
        subscribe = None

        def main(self):
            self.client = mqtt.Client()
            self.client.connect(self.host, self.port)
            if self.subscribe:
                self.client.on_message = self.on_message
                self.debug('subscribing to %s', self.subscribe)
                self.client.subscribe(self.subscribe)
            self.client.loop_forever()

        def shutdown(self):
            if self.client:
                self.client.disconnect()  # stops main thread
            Plugin.stop(self)

        # in case we are running in a separate context, call shutdown in that context
        def stop(self, *args): self.call_method('shutdown')

        def on_message(self, client, userdata, message):
            self.debug('got %s', message)
            # send whatever we are subscribed to as an event
            self.event(message.topic, json.loads(message.payload))

        def handle_event(self, e):
            if self.client:
                self.debug('publishing %s', e.name)
                self.client.publish(e.name, json.dumps(e.data()))
                return True

    def test_mqtt(*args):
        try:
            sub = args[0]
        except:
            sub = None
        from adf import Framework, Event
        f = Framework()
        f.start_control(('localhost', 42222))
        f.start_plugin(MQTT, subscribe=sub)
        # wait to get an event from MQTT or elsewhere
        f.lock()
        e = f.handle_event(10)
        f.unlock()
        # generate a new event with same data and send via MQTT
        if e:
            f.event('MQTT', sync=True, **e)
        else:
            f.event('MQTT', sync=True)
        f.stop()
except:
    pass  # no MQTT support


def test(*args):
    # test Event, Listener, Sender, and Channel
    from adf import Framework
    f = Framework()
    global rcvd_event

    class TestListener(Listener):
        def event(self, event=None):
            self.info(event)
            global rcvd_event
            rcvd_event = event
    rcvd_event = None
    l = f.start_plugin(TestListener)
    s = f.start_plugin(Sender)
    time.sleep(1)
    f.event('Sender', foo='bar', sync=True)
    f.stop_plugin('Sender')
    f.stop_plugin('Listener')
    while rcvd_event == None:
        time.sleep(1)
    assert (rcvd_event.name == 'Sender' and rcvd_event.foo == 'bar')
    rcvd_event = None

    class TestChannel(Channel):
        def event(self, event=None):
            self.info(event)
            global rcvd_event
            rcvd_event = event
    c1 = f.start_plugin(Channel, name='c1', addr='localhost')
    c2 = f.start_plugin(TestChannel, name='c2', listen='localhost')
    time.sleep(1)
    f.event('c1', foo='bar', sync=True)
    while rcvd_event == None:
        time.sleep(1)
    assert (rcvd_event.name == 'c1' and rcvd_event.foo == 'bar')
    f.stop()
    f.join()
