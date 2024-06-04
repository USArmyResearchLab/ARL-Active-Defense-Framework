from adf import *
# from adf import * will not make Event available during import of Plugin
from .event import Event

'''Plugin object'''


class Plugin(mp.Process):
    '''generic packet/event handler plugin, use this as a base class.

    Plugins run as new threads or processes and communicate with the Framework via IPC mechanisms
        Traffic is routed directly between linked plugins, and must flow via the dispatch and handle_packet methods
        Events are queued by the framework and sent to all plugins that subscribe to that event.
            Events must be sent/received via the event and handle_event methods
        Plugin state is maintained in the framework context, and must be managed via the plugin's *_state methods.'''

    '''startup/shutdown'''

    def __init__(self, framework=None, **config):
        if framework:
            self.__framework = framework  # ref to hosting framework
            self.__state = framework.manager.dict()  # proxy to shared state manager
        else:
            self.__state = {}  # no persist state, events won't work
        # if MP mode, we have to pipe between plugins. non-MP mode with queue=1 will use mp.dummy "pipe" for queueing
        if ADF_MP or config.get('queue'):
            self.__pipe_rx, self._pipe_tx = mp.Pipe(False)
        else:
            self._pipe_tx = self  # dispatch will direct call self.send, which calls handle packet
        # packet count, last report timestamp, and deltas for metrics
        self.__i_count = 0
        self.__i_lts = None
        self.__i_delta = 0.0
        self._dispatch = self.__dispatch  # set default dispatch mode
        self._event_q = mp.Queue()  # event queue
        self._ipc_req = mp.Queue() # IPC request queue, expects (method,args,kwargs) tuples
        self._ipc_ret = mp.Queue() # IPC return queue, return from method called via _ipc_req
        self._ipc_lock = mp.Lock() #IPC req lock, should be acquired until response has been read from _ipc_ret 
        self.__idle_count = 0  # count of consecutive calls to idle
        self.__packet_idle = mp.Event()  # set if packet loop has been idle for >1 sec
        self.__shutdown = mp.Event()  # set when shutdown has been initiated
        self.__stopped = mp.Event()  # set after packet/event handlers stop
        self.__handled = mp.Event()  # set after we have handled an event.
        self.__config(**config)  # set initial config
        name = self.get('name', self.__class__.__name__)
        if framework:
            self.__logger = framework.getLogger(name)
        else:
            self.__logger = logging.getLogger(name)  # get pre-init logger
        self.init()  # perform custom init
        self.__config()  # update config after init
        mp.Process.__init__(self, target=self.__main, name=name)

    # pythfor things like self.<configitem> in eval/expr
    def __getattr__(self, k): return self.__dict__.get(k)

    def __getitem__(self, k): return self.__getattr__(
        k)  # same thing for self[configitem]

    def get(self, k, default=None): return dk_get(self.__dict__,
                                                  k, default)  # dotted-key method for getting attributes

    def init(self):
        '''implement this to perform actions before plugin thread/process is spawned'''
        pass

    def __main(self):
        '''plugin main loop. Handles events from the IPC'''
        if ADF_MP:  # if forked ignore signals, we need to let the framework stop us
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            self.__logger = self.__framework.getLogger('%s[%s]' % (
                self.name, self.pid))  # replace logger with name[pid]
        else:
            self.pid = os.getpid()  # forking sets this, we have to set it if thread
        # start the packet thread if we queue packets
        if self.__pipe_rx:
            packet_loop = threading.Thread(
                target=self.__packet, name=self.name+'_packet')
            packet_loop.start()
            self.debug(packet_loop)
        else:  # if we don't queue, set the packet_idle event so we can exit
            packet_loop = None
            self.__packet_idle.set()
        #start the event thread
        __event = threading.Thread(target=self.__event, name=self.name+'_event')
        __event.start()
        self.debug(__event)
        # if this plugin has a main thread, start it.
        main = threading.Thread(target=self.main, name=self.name+'_main')
        main.start()
        self.debug(main)

        #handle IPC 
        while True:
            try:
                method,args,kwargs = self._ipc_req.get(timeout=1)
                self.debug('IPC req %s(%s %s)',method,args,kwargs)
                try: 
                    if method == 'config':
                        f = self.__config  # private function so needs special handling
                    # turn _name info self.name and call with event data
                    else:
                        f = eval('self.'+method)
                        # util function to extract function/args from event data and call it
                    r = f(*args,**kwargs)
                except Exception as e:
                    r = e
                self.debug('IPC ret %s %s',method,r)
                self._ipc_ret.put(r)
            except queue.Empty:
                if self.is_shutdown():
                    break
            except Exception as e:
                self.warning(e)

        # wait for packet and event handlers to stop
        if packet_loop:
            packet_loop.join()
            self.debug(packet_loop)
        __event.join()
        self.debug(__event)

        # event and packet stopped, wait for main to stop, it might be waiting on is_shutdown
        self.__stopped.set()
        main.join()
        self.debug(main)
        

    def __event(self):
        # event handler thread
        # run until shutdown and queue is empty
        while True:
            try:
                # get incoming events
                event = self._event_q.get(timeout=1)
                # _method events are triggered from framework but run in plugin process
                self.__idle_count = 0
                # do we have a function for handling this event?
                f = None
                # first look for method handle_NAME_SOURCE
                if event.path:
                    f = getattr(self, 'handle_'+event.name +
                                '_'+event.path[0], None)
                # now look for method handle_NAME
                if f is None:
                    f = getattr(self, 'handle_'+event.name, None)
                if f is None:
                    f = self.handle_event  # generic handle event
                try:
                    if f(event):
                        self.__handled.set()  # if we handle an event, set the flag
                except Exception as e:
                    self.warning("%s: %s" % (f, e), exc_info=True)
                # mark event as handled
                self._event_q.task_done()
            except queue.Empty:  # run idle on Q empty, then exit if shutting down
                self.__idle_count += 1
                try:
                    self.idle(self.__idle_count)
                except Exception as e:
                    self.warning("idle: %s" % (e), exc_info=True)
                if self.is_shutdown():
                    break
            except Exception as e:
                self.warning(e, exc_info=True)

    def __packet(self):
        # process packets until shutdown
        while True:
            try:
                if self.__pipe_rx.poll(1):
                    self.__packet_idle.clear()
                    self.handle_packet(*self.__pipe_rx.recv())
                    # only exit if no packets in queue
                elif self.is_shutdown():
                    break
                else:
                    if not self.__packet_idle.is_set():
                        self.debug('packet loop idle')
                    self.__packet_idle.set()
            except Exception as e:
                self.warning(e, exc_info=True)

    def is_idle(self, wait=False):
        '''returns True if packet loop is idle
        if wait=timeout, will wait (forever if True) for packet loop to go idle'''
        if wait:
            if wait is True:
                self.__packet_idle.wait()
            else:
                self.__packet_idle.wait(wait)
        return self.__packet_idle.is_set()

    def main(self):
        '''your main thread goes here'''
        pass

    def stop(self, *args):
        self.__shutdown.set()
        # called by signal, log it
        if args:
            self.warning('signal%s' % str(args))

    def is_shutdown(self, wait=False):
        '''returns True when shutdown has been initiated
        if wait=timeout, will wait (forever if True) for packet/event loops to stop
            main will still be running so main can safely wait on is_shutdown()'''
        if wait:
            if wait is True:
                self.__stopped.wait()
            else:
                self.__stopped.wait(wait)
        return self.__shutdown.is_set()

    '''logging'''

    def log(self, msg, *args, **kwargs):
        '''logging helper'''
        level = kwargs.get('level', logging.INFO)
        if 'level' in kwargs:
            del kwargs['level']
        return self.__logger.log(level, msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs): return self.log(msg,
                                                           level=logging.DEBUG, *args, **kwargs)

    def info(self, msg, *args, **kwargs): return self.log(msg,
                                                          level=logging.INFO, *args, **kwargs)

    def warning(self, msg, *args, **kwargs): return self.log(msg,
                                                             level=logging.WARNING, *args, **kwargs)

    def error(self, msg, *args, **kwargs): return self.log(msg,
                                                           level=logging.ERROR, *args, **kwargs)
    '''plugin config'''

    def config(self, *args, **kwargs):
        '''get plugin config (all or single key) or push key=value configs to plugin context
        config() will return dict of config, syncing to shared state
        config(key) will return value of key or None if not set
        config(key=value,...) will set key to value and sync/return config
        config(!key=value) or config (!key) will delete key from config (value is ignored)
        keys are dotted-key syntax, in that a.b.c will set/return/delete [a][b][c]'''
        if kwargs:
            # generates an internal __config event which is handled by __main
            self.call_method('config', **kwargs)
            # return reflection of only updated keys
            return dict((k, dk_get(self.get_state('__config'), k)) for k in kwargs.keys())
        elif args:
            for arg in args:
                if arg.startswith('!'):
                    # delete key from config
                    self.call_method('config', **{arg: None})
                else:
                    # get value from reflection in state
                    return dk_get(self.get_state('__config'), arg)
        else:
            return self.get_state('__config')  # return reflection from state

    def __config(self, **kwargs):
        '''plugin context method to update or get attributes'''
        for k, v in kwargs.items():
            if k.startswith('!'):
                dk_del(self.__dict__, k[1:])  # delete key if !key
            else:
                dk_update(self.__dict__, k, v)  # update config if set
        # get a pickle-shaped reflection
        # exclude private members and _members that may be instances or instancemethods
        # update reflection in shared state
        return self.set_state(__config=dict((k, v)
                       for (k, v) in self.__dict__.items() if not k.startswith('_')))

    def call_method(self, method, *args, **kwargs):
        '''helper method to put an IPC event in this plugin's queue
        used to call a method from outside context in MP Mode'''
        with self._ipc_lock: #lock IPC so we know the response will be to us
            self._ipc_req.put((method, args, kwargs))  # send request
            return self._ipc_ret.get() #dequeue and return the result

    '''packet handling'''

    def handle_packet(self, info, packet, prev=None):
        '''checks packet against filter_packet method, passes it through effect method, then dispatches.
    filter_packet and effect are typically implemented in subclasses, or handle_packet can be replaced'''
        if self.filter_packet(info, packet, prev=prev):  # if packet passes filters
            # perform our effect. Pass prev only if set, effect might not accept that arg
            if prev:
                try:
                    info, packet = self.effect(info, packet, prev=prev)
                except TypeError:
                    info, packet = self.effect(info, packet)
            else:
                info, packet = self.effect(info, packet)
            # forward packet if not dropped.
            if packet:
                self.dispatch(info, packet)

    def filter_packet(self, info, packet=None, **kwargs):
        '''filter based on config filter=<expression>
        uses eval_packet if filter is set, so locals for eval are:
            self
            info (keys are sip,dip,sport,dport,proto, etc...)
            packet
        '''
        if not self.filter:
            return True  # filter is disabled
        else:
            return self.eval_packet(self.filter, info, packet)

    def eval_packet(self, x, info, packet):
        '''evaluate x as expression based on a packet
        all globals and refs to plugin, packet, and info are available'''
        try:
            return eval(x, globals(), {'self': self, 'packet': packet, 'info': info})
        except Exception as e:
            self.debug("eval_packet(%s): %r", x, e, exc_info=True)

    def exec_packet(self, x, info, packet):
        '''like eval_packet, but executes statement x
        can be used to call plugin methods or modify state, packet or info'''
        try:
            exec(x, globals(), {'self': self, 'packet': packet, 'info': info})
        except Exception as e:
            self.debug("exec_packet(%s): %r", x, e, exc_info=True)

    '''packet dispatch'''

    def link(self, p=None, pri=0, direct=False):
        '''link to plugin p with priority pri
    direct: create a single low-latency link by setting our dispatch method to p.handle_packet
        this bypasses dispatch logic and the destination's packet queue
        packet handling chain will run in the thread of the last interface or normal dispatch
        not compatible with multiprocessing mode
        packet order is undefined if normal links are also in use
        '''
        if p:
            if direct:
                self.unlink()  # remove existing links if any
                self._dispatch = p.handle_packet  # direct call to remote plugin's handle_packet
                return True
            self._dispatch = self.__dispatch  # clear any direct link
            l = self.__state.get('__links', {})
            if p.name not in l:
                # link (connection,priority) by plugin name
                l[p.name] = (p._pipe_tx, pri)
                self.__state['__links'] = l  # sync to share state
                return True
        return False

    def unlink(self, p=None):
        '''unlink one or all plugins'''
        self._dispatch = self.__dispatch  # clear any direct link
        if p:
            l = self.__state.get('__links', {})
            if p.name in l:
                del l[p.name]
                self.__state['__links'] = l
                return True
            return False
        else:
            self.__state['__links'] = {}

    def get_links(self):
        '''return list of (name,priority) tuples for each link'''
        return [(p, pri) for (p, (c, pri)) in self.__state.get('__links', {}).items()]

    def dispatch(self, info, packet):
        '''send packets to:
        if info['dest'] set:
            link in dest if link exists (overrides all, but only if we are linked)
        else if info['dispatch'] set:
            links with priority > 0 and links in dispatch
        else:
            links with (priority >= 0 and not info['source'] or info['prev'])
        info['prev'] will be set to name of this plugin
        '''
        # if we are gathering throughput metrics
        if self.metrics:
            self._metrics(info)
        # __dispatch if normal link, p.handle_packet if direct link to p
        # set prev kwarg to self to enable packet routing in direct mode
        return self._dispatch(info, packet, prev=self)

    def __dispatch(self, info, packet, **kwargs):
        '''real dispatch code, bypassed if direct linking'''
        l, links, dispatch, dest = None, self.__state.get(
            '__links', {}), info.get('dispatch'), info.get('dest')
        if dest:  # follow configured hard destination
            if type(dest) is not list:
                dest = [dest]  # if string, make into list
            # if dest set, see if we are linked
            l = [(p, c) for (p, (c, pri)) in links.items() if p in dest]
        if not l:  # if we can't reach the dest
            if dispatch:  # follow configured dispatch
                # unset so we don't affect next plugin dispatch
                del info['dispatch']
                if type(dispatch) is not list:
                    dispatch = [dispatch]  # if string, make into list
                l = [(p, c) for (p, (c, pri)) in links.items()
                     if pri > 0 or p in dispatch]
            else:  # select links with pri > 0, or pri = 0 and not prev hops
                l = [(p, c) for (p, (c, pri)) in links.items() if pri > 0 or
                     (pri == 0 and p not in info.get('prev', []))]
        # add to set of previous hops to prevent loops
        info.setdefault('prev', set()).add(self.name)
        n = []  # plugin names we dispatched to
        for (p, c) in l:
            try:
                c.send((info, packet))  # connection to selected links
                n.append(p)
            except Exception as e:
                self.warning("dispatch to %s: %s", p, e, exc_info=True)
        return n

    def send(self, t):
        '''called externally to send to us if not using a pipe/queue'''
        return self.handle_packet(t[0], t[1])

    def inject(self, info, packet):
        '''injects a packet to this plugin's packet queue'''
        try:
            return self._pipe_tx.send((info, packet))
        except Exception as e:
            self.warning("inject: %s", e, exc_info=True)

    def _metrics(self, info):
        '''set metrics=interval to log throughput and latency every interval'''
        its = info.get('_i_ts')
        # if we have an internal timestamp set by another plugin, we can compute metrics
        if its:
            self.__i_count += 1
            # compute running average latency
            self.__i_delta = (self.__i_delta*(self.__i_count-1) +
                              (time.time()-its))/float(self.__i_count)
            if self.__i_lts and its-self.__i_lts > int(self.metrics):
                # compute and log throughput and latency
                self.info('throughput: %s packets/sec, latency: %s sec',
                          self.__i_count/self.metrics,
                          self.__i_delta)
                # reset last ts and counter
                self.__i_lts = None
                self.__i_count = 0
            # start of interval
            if not self.__i_lts:
                self.__i_lts = its
        # set internal timestamp for use by other plugins
        info['_i_ts'] = time.time()

    '''state handling'''

    def set_state(self, *args, **kwargs):
        '''set keys in persistent state using set_state(key,value | dict | key=value,...)'''
        if len(args) == 2:
            kwargs = {args[0]: args[1]}
        elif len(args) == 1:
            kwargs = args[0]
        for k, v in kwargs.items():
            dk_update(self.__state, str(k), v)
        return dict((str(k), dk_get(self.__state, str(k))) for k in kwargs.keys())

    def get_state(self, k=None, default=None, dump=None):
        '''get single key from or copy of plugin state'''
        if k is not None:
            return dk_get(self.__state, str(k), default)
        else:
            return dict((k, v) for (k, v) in self.__state.items() if not k.startswith('__'))

    def del_state(self, k=None):
        '''delete all or key from persistent state'''
        if k is not None and not k.startswith('__'):
            return dk_del(self.__state, str(k))
        else:
            for k in list(self.__state.keys()):
                if not k.startswith('__'):
                    del self.__state[str(k)]
            return True

    def flow_state(self, info, add=False, remove=False, key='flows', flow=None, **kwargs):
        '''check and update state of flow based on packet info
           returns flow data if flow in state and None if not.
           if add=True, adds flow to state if not present and returns flow data'''
        flows = self.get_state(key, {})  # get flows dict from state
        if flow:
            f = r = flow  # override IP info flow key generation
        else:
            f = (info.get('sip'), info.get('sport'), info.get('dip'),
                 info.get('dport'), info.get('proto'))  # flow key
            r = (f[2], f[3], f[0], f[1], f[4])  # reverse dir key
        if f in flows:
            pass  # flow key is in state
        elif r in flows:
            f = r  # if reverse key in state, use it as flow key
        elif not add:
            return None  # flow not in state, and we're not adding it so return None
        if remove:  # remove flow if requested
            if f in flows:
                del flows[f]
                # propagate changes to shared state
                self.set_state({key: flows})
                return True
            return False  # not found
        # get or init flow, set initial packet info
        flow = flows.setdefault(
            f, {'key': f, 'packets': 0, 'bytes': 0, 'start': info['ts']})
        flow.update(kwargs)  # update flow with any args passed in
        flow['packets'] += 1  # increment packet count
        if 'len' in info:
            flow['bytes'] += info['len']  # update byte count
        flow['end'] = info['ts']
        if 'flags' in info:
            flow['flags'] = flow.get(
                'flags', 0) | info['flags']  # sum TCP flags
        self.set_state({key: flows})  # propagate changes to shared state
        return flow  # return flow data

    '''framework call methods'''

    def event(self, *args, **kwargs):
        '''generate and queue event
    If event name is not provided, set it to the plugin name
    Passes all arguments through to Framework.event()'''
        # event name priority is:
        # 1) from arg (NAME,key=val,key=val), if None will force to plugin name
        # 2) from kwarg (name=NAME,key=val) (will be removed from kwargs)
        # 3) defaults to plugin name
        name = False
        # if positional args were passed
        for arg in args:
            # are they are tuples/dicts, merge with kwargs
            try:
                kwargs.update(arg)
            # or set name
            except:
                name = arg
        # name not set but in kwargs, set and remove from kwargs
        if name is False:
            if 'name' in kwargs:
                name = kwargs['name']
                del kwargs['name']
        # default to plugin name
        if not name:
            name = self.name
        # send event
        if self.__framework:
            return self.__framework.event(name, source=self.name, **kwargs)

    def respond(self, event, *args, **kwargs):
        '''respond to event from S by sending event with name=S
        this is assuming S is listening to events named S. Path will start with our name.
        so if we are R, the method handle_S_R would get the response'''
        self.event(*args, name=event.path[0], **kwargs)

    def wait(self, timeout=None):
        '''waits (for timeout, else blocks) until any event handler method returns True
        returning None/False from the handler will continue to wait'''
        self.__handled.clear()
        return self.__handled.wait(timeout)

    def call(self, method, *args, **kwargs):  # call method in framework
        '''Execute method in framework context via event call
    Arguments:
        method: method of plugin to call
        additional args and key=value arguments are passed to method'''
        if self.__framework:
            # lock our own IPC as the framework will place the result there 
            with self._ipc_lock:
                #place the request in the framework's IPC queue and wait for the response in ours 
                self.__framework._ipc_req.put((self._ipc_ret, method, args, kwargs))
                return self._ipc_ret.get() #return the result
    
    '''METHODS TO BE REDEFINED IN SUBCLASSES'''

    def effect(self, info, packet, **kwargs):
        '''modify packet if exec* config items are defined, else pass it on'''
        for k, v in ((k, v) for (k, v) in sorted(self.config().items()) if k.startswith('exec')):
            # modify packet by executing config value as code
            self.exec_packet(v, info, packet)
        return info, packet  # pass packets on

    def handle_event(self, event):
        '''events in queue will call the handle_<event name>_<event source> 
            or handle_<event name> method if the method is defined.
            otherwise the handle_event method will be called'''
        # update plugin config or state from event if config*={dict}/set*={dict}/del*=key in data
        for k, v in sorted(event.data().items()):
            if k.startswith('config'):
                self.config(**v)
            elif k.startswith('set'):
                self.set_state(**v)
            elif k.startswith('del'):
                self.del_state(v)
        return True  # optional, sets the proceed flag if waiting on event

    def idle(self, count=0):
        '''idle tasks go here: called when no events have occurred for one second
        count will be number of times idle has been called since last event'''
        pass  # by default do nothing


class Test(Plugin):
    '''Test plugin will:
    echo and dispatch all packets
    sr() method will send event and return next event that arrives'''

    def init(self): self.__q = mp.Queue()

    def main(self):
        self.info('started')
        while not self.is_shutdown():
            self.info('main')
            time.sleep(1)
        self.info('stopped')

    def idle(self, count): self.info('idle %d', count)

    def effect(self, i, d):
        self.info('packet %s %s' % (i, d))
        return i, d

    def handle_event(self, e):
        self.info('event %s', e)
        self.__q.put(e)

    def sr(self, *args, **kwargs):  # send/receive event
        if args or kwargs:
            self.event(*args, sync=True, **kwargs)
        while not self.is_shutdown():
            try:
                # wait until we get the response
                return self.__q.get(timeout=1, block=True)
            except queue.Empty:
                logging.debug('waiting')


def test(*args):
    from adf import Framework
    f = Framework(logger=logging.getLogger('plugin_test'))
    # test starting
    p1 = f.start_plugin(Test, name='p1')
    p2 = f.start_plugin(Test, name='p2')
    # test config
    print(p1.config(k='v'))  # test k=v
    print(p1.config(**{'a.b.c': 'd'}))  # test dk=v
    # test set via framework
    print(f.config('config p1 intval=1 list=1,2,3 string=test dotted.keys=value'))
    print(p1.config('notset'))
    assert (p1.config('notset') is None)  # test not set behavior
    c = p1.config()  # test all values are set
    assert (c['k'] == 'v' and c['a']['b']['c'] == 'd' and c['intval'] == 1 and c['list'] == [
            1, 2, 3] and c['string'] == 'test' and c['dotted']['keys'] == 'value')
    p1.config('!a.b.c')  # test dk delete
    assert ('c' not in p1.config()['a']['b'])  # check dk delete
    print(p1.config())
    # test framework value get
    print(f.config('config p1 k'))
    print(f.config('config p1 intval'))
    print(f.config('config p1 a.b'))
    print(f.config('config p1 notset'))
    print(f.config('config p1'))
    f.config('config p1 !dotted !list')  # test !key delete with multiple keys
    print(p1.config())
    assert (p1.config('dotted') is None and p1.config(
        'list') is None)  # check deletion
    # test link
    f.link_plugin('p1', 'p2')
    # test packet path
    p1.inject({'test': 'test'}, b'test')
    p2.inject({'test': 'test'}, b'test')
    time.sleep(1)
    print(p1.dispatch({}, b'test'))
    # test events
    p1.event('p2', test='test', sync=True)
    # test call of plugin method from framework
    print(f.call_plugin('p2', 'event', 'p1', test='test', sync=True))
    # test one plugin loading another by calling framework
    print(p1.call('load_plugin', 'Plugin', name='test'))
    assert(f.get_plugin('test') is not None)
    # test plugin setting state remotely via IPC with call -> call_plugin -> set_state
    print(p2.call('call_plugin','test','set_state',from_p2='hi'))
    t=f.get_plugin('test')
    print(t.get_state())
    assert(t.get_state('from_p2') == 'hi')
    f.stop()
    p2.join()
    p1.join()
