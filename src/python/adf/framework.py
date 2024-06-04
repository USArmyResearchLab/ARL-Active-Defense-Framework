from adf import *

from pprint import pformat

#
# FRAMEWORK
#


class Framework(threading.Thread):
    def __init__(self, *startup_config, **kwargs):
        '''initialize the framework.
    Arguments:
        name: Default 'framework', for logging purposes.
        start: Default True. If start=False, framework will not be started immediately.
        on_error: Callback if plugin dies. Return True to stop framework.
        superglobals: pass in globals() from instantiating namespace to make any imported modules available there
        additional arguments will be treated as startup configuration commands. 
        These will be executed whenever framework restarts'''
        self.__startup_config = []
        if ADF_MP:
            self.__logger = kwargs.get('logger', logging.getLogger(
                '%s[%d]' % (kwargs.get('name', 'framework'), os.getpid())))
        else:
            self.__logger = kwargs.get(
                'logger', logging.getLogger(kwargs.get('name', 'framework')))
        self.__event_q = mp.Queue()  # global event queue
        self._ipc_req = mp.Queue() # IPC from plugin to framework, expects (ipc_ret,method,args,kwargs), result will be placed in ipc_ret queue
        self.__lock = mp.Lock()  # acquire the lock to stop event and idle processing
        self.__locked = False  # flag indicating we manually locked the event loop with lock()
        self.__plugins = {}  # plugin objects
        self.__subs = {}  # event subscriptions
        self.__control = None  # control server
        self.__state_file = None  # state save file
        self.__save_interval = None  # state save interval
        self.__on_error = kwargs.get('on_error')
        # setup shared state IPC server
        # state will be lost if the manager process dies so ignore signals until we fork it
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        self.manager = mp.Manager()
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGHUP, signal.SIG_DFL)
        # setup main thread
        self.__shutdown = threading.Event()
        self.__restart = False
        threading.Thread.__init__(self)
        if 'superglobals' in kwargs:
            # globals of main namespace
            self.__superglobals = kwargs['superglobals']
        else:
            self.__superglobals = {}
        if kwargs.get('start', True):
            # by default we start on init, but start=False can be set
            self.start(*startup_config)

    def start(self, *startup_config):
        '''start or restart the main thread.
    Must be called if framework is initialized with start=False
        additional arguments will be treated as startup configuration commands. 
        These will be executed whenever framework restarts'''
        if startup_config:
            self.__logger.info('startup config: %s', startup_config)
            self.__startup_config = startup_config  # set startup config
        startup = self.__shutdown.is_set()  # if restart, will be set
        if not self.is_alive():  # we are starting the framework
            startup = True
            threading.Thread.start(self)  # start main thread
        if startup:  # we are in startup or restart
            r = self.config(*self.__startup_config)  # apply initial config
            if r:
                self.__logger.info(pformat(r))
            self.__logger.info('started')
            return r
        else:
            self.restart()  # we are being called to trigger a restart
            return self.__startup_config

    def restart(self, *args):
        '''signals main thread to restart. Called by SIGHUP'''
        self.__restart = True
        self.stop(*args)

    def stop(self, *args):
        '''signal main thread to stop. Called by SIGINT.'''
        if args:
            self.__logger.warning('signal %s', str(args))
        self.unlock()  # manually unlock if locked
        self.__shutdown.set()

    def run(self):
        '''main thread. Handles startup/shutdown'''
        while True:
            self.__shutdown.clear()  # will be set if restarted
            # run event loop until stop flag set
            self.__stop_event_loop = False
            event_loop = threading.Thread(
                name='event_loop', target=self.__event_loop)
            event_loop.start()
            ipc_loop = threading.Thread(
                    name='ipc_loop', target=self.__ipc_loop)
            ipc_loop.start()
            self.__shutdown.wait()  # wait until shutdown
            self.idle(True)  # force cleanup/save state
            # concurrently unlink/stop plugins to speed up shutdown
            self.__logger.info('stopping all plugins')
            for p in self.__plugins.copy().keys():
                self.stop_plugin(p, timeout=None)
            # plugin stop may fire events so wait until queue is empty
            self.__stop_event_loop = True
            event_loop.join()
            ipc_loop.join()
            # join and unload plugins
            for p in self.__plugins.copy().keys():
                self.stop_plugin(p)
            if self.__restart:  # if restart flag set
                self.__restart = False  # clear flag
                self.start()  # do restart
            else:
                break
        # only if shutdown: stop control socket and state manager
        self.__logger.debug(self.stop_control())
        self.__logger.debug(self.manager.shutdown())
        self.__logger.info('shutdown')

    def __event_loop(self):
        '''event loop thread
        Will be paused while lock is held, allowing external code to take over event handling.'''
        self.__idle_count = 0  # count idle cycles for save interval
        # run until stop flag set and q is empty
        while not self.__stop_event_loop or not self.__event_q.empty():
            # allow lock to be acquired by other threads.
            self.__shutdown.wait(.001)
            with self.__lock:  # acquire lock, then run until queue is empty
                try:
                    while self.handle_event(1):
                        self.__idle_count = 0  # process queue until empty for 1 second
                    self.__idle_count += 1
                    # do idle tasks when event handler times out
                    self.idle(self.__idle_count)
                except Exception as e:
                    # on exception, stop processing queue
                    self.__logger.exception(e)

    def __ipc_loop(self):
        while True:
            try:
                ipc_ret,method,args,kwargs = self._ipc_req.get(timeout=1)
                self.__logger.debug('IPC %s(%s %s) -> %s',method,args,kwargs,ipc_ret)
                try:
                    f = eval('self.'+method)
                    r = f(*args,**kwargs)
                except Exception as e:
                    r = e
                self.__logger.debug('IPC ret %s %s -> %s',method,r,ipc_ret)
                ipc_ret.put(r)
            except queue.Empty:
                if self.__stop_event_loop:
                    break
            except Exception as e:
                self.__logger.exception(e)

    def idle(self, count=0):
        '''perform idle tasks. must be manually called if lock is held'''
        # detect dead plugins and cleanup
        for p, plugin in self.__plugins.copy().items():
            if not plugin.is_alive():
                if not plugin.is_shutdown():
                    self.__logger.error('%s died', p)
                    if self.__on_error and self.__on_error(p):
                        self.stop()
                self.stop_plugin(p, True)
        # save state if interval set
        if (count is True) or (self.__save_interval and (not count % self.__save_interval)):
            s = self.save_state()
            if s:
                self.__logger.info('save state to %s', s)

    def getLogger(self, name):
        '''get a child of the framework's logger'''
        return self.__logger.getChild(name)

    '''config'''

    def read_config(self, cfg):
        '''read config file given as argument and parses each line'''
        self.__logger.info('parsing %s', cfg)
        s = []
        with open(cfg, encoding='ascii', errors='replace') as cfg_fh:
            for cmd in cfg_fh.readlines():
                if cmd:
                    r = self.config(cmd)
                    if r:
                        s.append(r)
        return s

    def config(self, *args):
        '''configure framework, arguments are parsed as commands. returns any output from commands.'''
        if args:
            args = ' '.join(args)
            # detect JSON-encoded line
            if args.startswith('['):
                return self.json_config(args)
        else:
            args = ''
        cmd = [parse_env(c) for c in parse_line(args)
               ]  # parse line and env vars
        if not cmd:
            return None
        self.__logger.debug(cmd)
        c, r = cmd[0], None

        try:
            # these commands have 1 required arg
            if len(cmd) > 1:
                # include <configfiles>
                if c.startswith('inc'):
                    r = []
                    for cfg in cmd[1:]:
                        r.append({cfg: self.read_config(cfg)})

                # logging configuration
                if c == 'log':
                    # can be a basic key=vlue (level=DEBUG...)
                    if '=' in cmd[1]:
                        log_config = parse_kvs(cmd[1:])
                        import logging
                        logging.basicConfig(**log_config)
                    else:  # or a full dictionary for loading modules, etc..
                        log_config = eval(' '.join(cmd[1:]))
                        log_config.update(version=1)
                        import logging.config
                        logging.config.dictConfig(log_config)
                    r = log_config

                # import a package and make exports available
                if c.startswith('import'):
                    r = self.import_package(cmd[1])

                # control server
                # control [<address> <port>] [options]
                if c.startswith('control'):
                    if len(cmd) == 1:
                        r = self.stop_control()
                    else:
                        r = self.start_control(
                            (cmd[1], int(cmd[2])), **parse_kvs(cmd[3:]))

                if c == 'plugin':  # plugin <module> [options]
                    r = self.load_plugin(cmd[1], **parse_kvs(cmd[2:]))
                if c.startswith('stop'):  # stop <plugin-name> [options]
                    r = self.stop_plugin(cmd[1], **parse_kvs(cmd[2:]))
                if c.startswith('config'):  # config <plugin-name> [options]
                    d = parse_kvs(cmd[2:])
                    args = [k for k, v in d.items() if v is None]
                    kwargs = dict((k, v)
                                  for k, v in d.items() if v is not None)
                    r = {cmd[1]: self.config_plugin(cmd[1], *args, **kwargs)}
                # (un)link <plugin-name> [linked plugins]
                if c.startswith('link') or c.startswith('unlink'):
                    r = {cmd[1]: self.link_plugin(
                        cmd[1], *cmd[2:], unlink=c.startswith('unlink'))}
                if len(cmd) > 2:  # 2 arguments required
                    if c.startswith('direct'):  # direct link <plugin-name> <plugin-name>
                        r = {cmd[1]: self.link_plugin(
                            cmd[1], cmd[2], direct=True)}
                    # call <plugin-name> <method> [args]
                    if c.startswith('call'):
                        r = {cmd[1]: str(self.call_plugin(
                            cmd[1], cmd[2], **parse_kvs(cmd[3:])))}
                if c.startswith('exec'):  # exec <code>
                    r = self.exec_plugin(*cmd[1:])
                # subscribe <plugin name> [*|event name ... ]
                if c.startswith('sub'):
                    r = self.subscribe(*cmd[1:])

            # info
            if c.startswith('show'):  # show loaded plugins, links, and subs
                r = {n: {
                    'config': p.config(),
                    'links': p.get_links(),
                    'subs': self.get_subs(n)
                } for (n, p) in self.get_plugin().items() if not cmd[1:] or (n in cmd[1:])}
            # set env
            if c.startswith('env'):
                r = {}
                for (k, v) in parse_kvs(cmd[1:]).items():
                    if v is not None:
                        os.environ[k] = str(v)
                    r[k] = os.environ.get(k)

            # state
            if c.startswith('del'):
                r = self.del_state(*cmd[1:])
            if c.startswith('set') and len(cmd) > 1:
                r = self.set_state(cmd[1], **parse_kvs(cmd[2:]))
            if c.startswith('get'):
                r = self.get_state(*cmd[1:])
            # load state, calling with argument(s) sets the load/restore mode
            if c.startswith('load'):
                r = self.load_state(*cmd[1:])
            # save state, calling with arguments set the save interval
            if c.startswith('save'):
                r = self.save_state(*cmd[1:])

            # event handling
            # manually queue event of <type> [args]
            if c == 'event' and len(cmd) > 1:
                e = self.event(cmd[1], **parse_kvs(cmd[2:]))
                r = {e.name: e.data()}
            if c == 'lock':  # lock the main thread
                if len(cmd) > 1:
                    r = self.lock(cmd[1])
                else:
                    r = self.lock()
            if c == 'unlock':
                r = self.unlock()  # unlock the main thread
            if c == 'wait':  # handle and wait for any or named event
                r = self.wait(*cmd[1:])
                if r:
                    r = {r.name: r.data()}

            # shutdown/restart
            if c == 'shutdown':
                r = self.stop()
            if c == 'restart':
                r = self.start(*cmd[1:])  # args replace startup args

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            err = {c: {exc_type.__name__: exc_obj.args}}
            self.__logger.warning(err)
            self.__logger.debug(e, exc_info=True)
            return err

        return {c: r}

    def json_config(self, j):
        '''accepts JSON: 
            [ {"method":[args]}, {....}, ... ]
        returns:
            [ {"method":result},....]'''
        rl = []
        try:
            j = json.loads(j)
            self.__logger.debug(j)
            for cmd in j:
                rc = {}
                for k, args in cmd.items():
                    m = eval('self.'+k)
                    kwargs = {}
                    for a in args:
                        if type(a) is dict:
                            kwargs.update(a)
                            args.remove(a)
                    try:
                        r = m(*args, **kwargs)
                        if type(r) is Event:
                            r = str(r)
                        rc[k] = r
                    except:
                        exc_type, exc_obj, exc_tb = sys.exc_info()
                        err = {exc_type.__name__: exc_obj.args}
                        rc[k] = err
                        self.__logger.warning({k: err})
                rl.append(rc)
        except:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            err = {exc_type.__name__: exc_obj.args}
            rl.append(err)
            self.__logger.warning(err)
        return json.dumps(rl)

    '''plugin handling'''

    def import_package(self, pkg):
        '''calls the importomatic and puts the module contents in globals/superglobals'''
        self.__logger.info('importing %s', pkg)
        m, attrlist = import_package(pkg)
        for attr in attrlist:
            self.__superglobals[attr] = globals()[attr] = getattr(m, attr)
        return {pkg: attrlist}

    def load_plugin(self, path, **kwargs):
        '''loads a plugin given a path, then calls start_plugin
        additional key=value args are passed to plugin instant as startup config
        returns plugin name and pid as a dictionary'''
        # separate the class from the path
        try:
            p, c = path.rsplit('.', 1)
        except ValueError:
            p, c = '', path
        p_c = None
        # see if plugin was previously imported
        try:
            if p:
                p_c = getattr(globals()[p], c)
            else:
                p_c = globals()[c]
        except (KeyError, AttributeError):
            pass
        if not p_c:
            p_c = import_package(p+'.'+c, get_class=True)
        plugin = self.start_plugin(p_c, path=path, **kwargs)  # start instance
        return {plugin.name: plugin.pid}  # return name:pid mapping

    def config_plugin(self, p, *args, **kwargs):
        '''configures plugin p if given key=value arguments
        returns single value from plugin p config if given key
        else returns enture plugin p config'''
        return self.__plugins[p].config(*args, **kwargs)

    def get_plugin(self, p=None):
        '''returns loaded plugin object if given name'''
        if p is None:
            return self.__plugins.copy()
        return self.__plugins.get(p)

    def start_plugin(self, p_class, **kwargs):
        '''creates an instance of p_class in the framework and starts it, returns the instance
        extra key=value arguments are passed to plugin as configuration'''
        plugin = p_class(self, **kwargs)  # return instance
        self.__logger.info('starting %s %s %s', plugin.name, p_class, kwargs)
        if plugin.name in self.__plugins:
            raise Exception(plugin.name+' exists')
        self.__plugins[plugin.name] = plugin  # add to loaded plugins
        # subscribe to events matching name
        self.subscribe(plugin.name, plugin.name)
        plugin.start()  # start the plugin after initial config done
        return plugin

    def stop_plugin(self, p, kill=False, timeout=10):
        '''stops and unloads plugin by name. returns plugin name and pid
        a timeout of 0/None will unlink and signal plugin to stop but not join/unload it'''
        if p in self.__plugins:
            plugin = self.__plugins[p]
            # unlink this plugin to prevent pipe hangs
            for lpn, lp in self.__plugins.items():
                if lp.unlink(plugin):
                    self.__logger.info('unlinked %s from %s', p, lpn)
            # stop plugin
            if not kill:
                while plugin.is_alive():
                    plugin.stop()
                    # if no timeout, return immediately. Call again with timeout to clean up.
                    if not timeout:
                        return plugin.name
                    plugin.join(timeout)
                    if plugin.is_alive():
                        self.__logger.warning('%s did not stop', p)
                        if self.__shutdown.is_set():
                            break  # don't retry if we're shutting down
            # really stop plugin
            if ADF_MP and plugin.is_alive():
                self.__logger.warning('terminated %s', p)
                plugin.terminate()
                plugin.join(timeout)
                if plugin.is_alive():  # really really stop plugin
                    self.__logger.warning('killed %s', p)
                    os.kill(plugin.pid, signal.SIGKILL)
            # unload
            self.__logger.info('stopped %s', p)
            # prevent a race condition here, the framework idle loop may detect the plugin has stopped and call stop_plugin.
            if p in self.__plugins:
                del self.__plugins[p]
            return plugin.name  # return name of plugin stopped

    # link plugin p to send packets to link_ps list
    def link_plugin(self, p, *link_ps, unlink=False, bidir=None, direct=False):
        '''link or unlink plugin p to list of plugins. returns current links.
    Arguments are:
        p: plugin to link or unlink
        extra arguments should be plugin names or 'name:priority'
        links given are added to current links.
        if bidir=True, link_p will also be (un)linked fr=om p
        if priority and bidir is not specified, link will default to bidirectional.
        links are cleared if unlink=True and no link_ps are given.
        if direct is True, a direct link is created from p to the link_p
            a direct link is unconditional, bypassing all links, dispatch logic, and the link_p packet queue
    Priorities are:
        -1: never dispatch to this plugin unless set in info
        0: dispatch to this plugin unless source or previous
        1: always dispatch to this plugin'''
        if unlink and not link_ps:
            self.__plugins[p].unlink()  # remove all existing links
        for link_p in link_ps:
            b = bidir
            try:
                try:
                    link_p, pri = link_p.split(':', 1)
                except:
                    # also accept / in case env vars are being used
                    link_p, pri = link_p.split('/', 1)
                pri = int(pri)
            except:
                pri = 0
                if b is None:
                    b = not direct  # if priorities/bidir not specified, default to 0 and bidir link
            lp = self.__plugins.get(link_p)
            if unlink:
                self.__plugins[p].unlink(lp)  # unlink one
                if b and lp:
                    lp.unlink(self.__plugins[p])
            else:
                self.__plugins[p].link(lp, pri, direct=direct)
                if b and lp:
                    lp.link(self.__plugins[p], pri, direct=direct)
        return self.__plugins[p].get_links()

    def unlink_plugin(self, p, *link_ps, **kwargs): 
        return self.link_plugin(p, *link_ps, unlink=True, **kwargs)

    def call_plugin(self, p, method, *args, **kwargs):  # call method in plugin context
        '''Execute method in plugin p context via event call
    Arguments:
        p: name of plugin to call
        method: method of plugin to call
    additional key=value arguments are passed to method'''
        return self.__plugins[p].call_method(method,*args,**kwargs)

    def exec_plugin(self, *code):
        '''Execute code in this context
    plugin methods will be available to code by plugin name (name.method())'''
        return exec(' '.join(code), globals(), self.__plugins)

    def subscribe(self, p, *subs):
        '''Subscribe plugin to event names, returns subscribed names.
    Arguments:
        p: plugin name
        additional arguments will be treated as event names to subscribe to
        No additional arguments will return current subscriptions
        True or "*" will subscribe to all events, False or "-*" will unsubscribe from all events
        -name will remove subscription'''
        if p in self.__plugins:
            for n in subs:
                if n is True or n == '*': #sub to all
                    self.__subs[p] = True
                elif n is False or n == '-*': #unsub from all 
                        self.__subs[p] = []
                elif n[0] == '-':  # -name will remove sub
                    self.__subs[p].remove(n[1:])
                else:
                    if p not in self.__subs or self.__subs[p] is True: #init list for subs
                        self.__subs[p] = []
                    if n not in self.__subs[p]:
                        self.__subs[p].append(n)
            return {p: self.get_subs(p)}

    def get_subs(self, p):
        '''Returns event names plugin p is subscribed to. Returns False if p does not exist'''
        if p in self.__plugins:
            return self.__subs[p]
        return False

    '''event handling'''

    def event(self, __name=None, event=None, **kwargs):
        '''Publish Event, returns Event on success
    Arguments:
        event: Pass existing Event object.
        name: Name of new Event to publish
        if event.sync is True, do not return until event has been handled.
        Will block if sync=True and lock is held, unless something else calls handle_event or releases lock.
    all extra arguments populate new Event'''
        if not event:
            event = Event(__name, **kwargs)
        self.__event_q.put(event)  # queue the event
        if event.sync:
            self.__event_q.join()  # wait for handle_event to call task_done()
        return event

    def handle_event(self, block=False):
        '''Handle one queued event and return it.
    Arguments:
        block: time to wait for queued event
            False: immediately return None if queue empty (Default)
            True: block until event arrives
            <n>: wait n seconds, return none on timeout
        sync: if True (default), wait for plugins to handle event before returning'''
        try:
            if not block:
                block, timeout = False, None  # nonblocking
            elif block is True:
                block, timeout = True, None  # blocking
            else:
                block, timeout = True, float(block)  # block with timeout
            event = self.__event_q.get(block, timeout)
            handled = []  # plugins we will wait on
            for n, p in self.__plugins.items():
                try:
                    subs = self.__subs[n]
                    # plugin gets event if it subscribes to all events or if it subs to this event name
                    if ((subs is True) or (event.name in subs)):
                        # do not send source-named events to that source (subscribed by default)
                        # or to any plugin that has already handled them 
                        if event.path and n in event.path[1:] or (len(event.path) and n==event.name and n==event.path[0]):
                            continue                
                        # add plugin name if handled to event data, this prevents looping if event gets requeued
                        event.path.append(n)
                        #send event to plugin
                        p._event_q.put(event)
                        handled.append(p)
                except Exception as e:
                    self.__logger.exception(e)
            if event.sync:  # if event is synced
                for p in handled:
                    p._event_q.join()  # wait until all plugins have handled the event
            if not handled:
                # log unhandled events
                self.__logger.info('unhandled event: %s', event)
            self.__event_q.task_done()  # unblock if sync
            return event  # return event
        except queue.Empty:
            return None  # nothing happened

    def lock(self, timeout=True):
        '''lock event handling,
        returns True on success and False if optional timeout expires, else blocks)'''
        if timeout is True:
            r = self.__lock.acquire(True)  # default block forever
        else:
            r = self.__lock.acquire(True, int(timeout))  # block for timeout
        if r:
            self.__locked = True
        return r

    def unlock(self):
        '''unlock event handling
        returns True if handling was unlocked or false if not already locked'''
        if self.__locked:  # only unlock if we manually locked it, event loop will handle __lock directly
            try:
                self.__lock.release()  # release lock
                self.__locked = False
                return True
            except RuntimeError:
                self.__locked = False  # another thread may have unlocked it
        return False  # was not unlocked by us

    def wait(self, timeout=None, name=None):
        '''wait up to timeout for name or any event to be handled
        locks/unlocks queue if not already locked'''
        r = None
        try:
            t = int(timeout)
        except:
            t = True  # wait forever
        we_locked = None  # did we lock the queue?
        if not self.__locked:  # lock the queue if it's not locked
            if t is not True:
                we_locked = self.lock(t)  # with timeout
            else:
                we_locked = self.lock()  # no timeout
        if self.__locked:  # as long as someone has the lock
            while True:
                r = self.handle_event(t)  # handle the next event
                if name and r and r.name != name:
                    continue  # if waiting for specific event name, retry if no match
                break
        if we_locked:
            self.unlock()  # only unlock if we locked it
        return r

    '''state handling'''

    def del_state(self, p=None, k=None):
        '''delete named state or key, or flush all state'''
        if p:
            if p in self.__plugins:
                return self.__plugins[p].del_state(k)
            return False
        for p in self.__plugins.values():
            p.del_state()
        return True

    def get_state(self, p=None, k=None, default=None, dump=None):
        '''get state from plugins'''
        if p:
            if p in self.__plugins:
                return self.__plugins[p].get_state(k, default, dump=dump)
            return False
        return dict((p, self.get_state(p, dump=dump)) for p in self.__plugins.keys())

    def set_state(self, p, *args, **kwargs):
        '''set plugin state'''
        if p in self.__plugins:
            return self.__plugins[p].set_state(*args, **kwargs)
        return False

    def load_state(self, state_file=None, flush=False, restore=False, state=None):
        '''load state from state_file or string (provide state=<serialized>)
            if interval, set auto-save interval to state_file 
            flush=delete existing state before load
            restore=replace existing plugins with config from state'''
        if not state:
            if state_file:
                try:
                    with open(state_file, 'rb') as state_fh:
                        state = pickle.load(state_fh)
                except Exception as e:
                    self.__logger.exception(e)
                    return e
        if state:
            self.__logger.debug('state keys from %s: %s',
                                state_file, state.keys())
            if flush:
                self.__logger.info("flushed state")
                self.del_state()
            if restore:
                self.__logger.info("restoring config")
                for n in self.__plugins.copy().keys():  # stop all plugins
                    self.__logger.info(self.stop_plugin(n))
                # reload plugins from migrated state
                for c in state.get('__plugins', []):
                    self.__logger.info(self.load_plugin(**c))
                # relink plugins from migrated state
                for p, lp in state.get('__links', {}).items():
                    for (l, pri) in lp:
                        self.__plugins[p].link(self.__plugins[l], pri)
                # relink plugins from migrated state
                for p, s in state.get('__subs', {}).items():
                    try:
                        self.subscribe(p, *s)  # list of subscriptions
                    except:
                        self.subscribe(p, s)  # None or True
                    self.__logger.info('%s %s', p, self.get_subs(p))
            try:
                del state['__plugins'], state['__links'], state['__subs']
            except:
                pass
            for p, s in state.items():
                self.set_state(p, **s)  # migrate state to plugins
        return state_file

    def dump_state(self, name=None):
        '''dump state and all config, optionally send as name'''
        state = self.get_state(dump=True)
        # dump loaded plugins and their configurations
        state.update(__plugins=[p.config() for p in self.__plugins.values()])
        # dump plugin links
        state.update(__links=dict((n, p.get_links())
                     for n, p in self.__plugins.items()))
        # dump subscriptions
        state.update(__subs=dict((n, self.get_subs(n))
                     for n in self.__plugins.keys()))
        if name:
            self.event(name, sync=True, state=state)  # dump to event if set
        return state

    def save_state(self, state_file=None, interval=None):
        '''save state to state_file
        if interval, set auto-save interval to state_file'''
        if state_file:
            self.__state_file = state_file
        if interval:
            self.__save_interval = int(interval)
        if self.__state_file:
            state = self.dump_state()
            try:
                with open(self.__state_file, 'wb') as state_fh:
                    pickle.dump(state, state_fh)
            except Exception as e:
                self.__logger.exception(e)
                return e
            self.__logger.debug('state keys to %s: %s',
                                self.__state_file, state.keys())
        return self.__state_file

    '''control socket'''

    def start_control(self, laddr, **kwargs):
        '''starts a control socket thread'''
        if not self.__control:  # do not restart control server if running
            import socketserver
            import ssl

            class ControlSocket(socketserver.StreamRequestHandler):
                def handle(self):
                    self.__logger = logging.getLogger(str(self.client_address))
                    self.__logger.info('connected')
                    while True:
                        cmd = self.rfile.readline().decode()  # get line from client
                        if not cmd:
                            break  # will be None if client disconnected
                        r = self.server.framework.config(cmd)
                        if type(r) is not str:
                            r = pformat(r)
                        self.__logger.debug('%s\t%s', cmd, r)
                        self.wfile.write(r.encode() + b'\n')
                        # terminate responses with newline
                        self.wfile.write(b'\n')
                        self.wfile.flush()  # flush
                    self.__logger.info('disconnected')

            class ControlServer (socketserver.ThreadingMixIn, socketserver.TCPServer):
                allow_reuse_address = True

                def get_request(self):
                    newsocket, fromaddr = self.socket.accept()
                    if 'ssl' in self.kwargs:
                        ctx = ssl.create_default_context(
                            purpose=ssl.Purpose.CLIENT_AUTH, cafile=self.kwargs.get('cafile'))
                        ctx.load_cert_chain(certfile=self.kwargs.get(
                            'certfile'), keyfile=self.kwargs.get('keyfile'))
                        ctx.verify_mode = self.kwargs.get(
                            'verify', ssl.VerifyMode.CERT_NONE)
                        ciphers = self.kwargs.get('ciphers')
                        if ciphers:
                            ctx.set_ciphers(ciphers)
                        connstream = ctx.wrap_socket(
                            newsocket, server_side=True)
                        return connstream, fromaddr
                    return newsocket, fromaddr

            self.__control = ControlServer(tuple(laddr), ControlSocket)
            self.__control.kwargs = kwargs  # for passing ssl params and other options
            self.__control.framework = self
            self.__control.server_thread = threading.Thread(
                target=self.__control.serve_forever)
            self.__control.server_thread.daemon = True
            self.__control.server_thread.start()
        return (self.__control.server_address, self.__control.kwargs)

    def stop_control(self):
        if self.__control:
            self.__control.shutdown()
            self.__control.server_thread.join()
            self.__control = None
            return True
        return False


def test(*args):
    logger = logging.getLogger('framework_test')
    f = Framework(*args, logger=logger)
    logger.info('loaded %s', f.load_plugin('Plugin', name='test'))
    p = f.get_plugin('test')
    assert (p)

    logger.info('config %s', f.config_plugin(
        'test', test_config='test_config_value'))
    assert (f.config_plugin('test', 'test_config') == 'test_config_value')

    logger.info('link %s', f.link_plugin('test', 'test'))
    assert (p.get_links()[0][0] == 'test')

    e = f.event('test', set={'test_key': 'test_value'}, sync=True)
    logger.info('event %s', e)
    assert (e.name == 'test' and 'test' in e.path and e.get(
        'set')['test_key'] == 'test_value')

    s = f.dump_state()
    logger.info('state %s', s)
    f.del_state()
    logger.info(f.get_state())
    assert (not f.get_state('test'))
    f.load_state(state=s)
    assert (s['test'] == {'test_key': 'test_value'})
    f.set_state('test', test_key_2=2)
    f.del_state('test', 'test_key')
    s = f.get_state('test')
    logger.info(s)
    assert ('test_key' not in s and s['test_key_2'] == 2)

    # event wait/named event wait
    f.lock()
    logger.info(f.event('test'))
    r = f.wait()  # will get any event, should handle and return test
    logger.info(r)
    assert (r.name == 'test')
    logger.info(f.event('test1'))
    # looking for test2 will handle test1 and return None after timeout
    r = f.wait(1, 'test2')
    logger.info(r)
    assert (r is None)
    logger.info(f.event('test1'))
    logger.info(f.event('test2'))
    # looking for test2, will handle test1 and return test2 immediately
    r = f.wait(True, 'test2')
    logger.info(r)
    assert (r.name == 'test2')

    logger.info(f.subscribe('test','-test',False,True,'*','-*','test_event')) #unsub from test and sub to test_event
    logger.info(f.event('test'))
    logger.info(f.event('test_event')) #queue 2 events 
    r = f.wait() 
    logger.info(r) #should be []
    assert (len(r.path) == 0)
    r = f.wait()
    logger.info(r) #should be ['test']
    assert (len(r.path) == 1 and r.path[0] == 'test') 

    f.unlock()

    #interplugin state access
    logger.info('loaded %s', f.load_plugin('Plugin', name='test2'))
    p2 = f.get_plugin('test2')
    assert (p2)

    logging.info(p2.call('set_state','test',test_key_3=3))
    logging.info(p.get_state())
    assert (p.get_state('test_key_3') == 3)

    f.stop()
