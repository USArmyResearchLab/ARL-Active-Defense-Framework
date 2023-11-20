# Plugin API

All plugins should inherit Plugin or a class that inherits Plugin.

```from adf import Plugin
class MyPlugin(Plugin):
```

## Implementation methods

These methods will be called by Plugin and may be defined in your plugin class.

### Initialization

``` python
    def init(self):
        #do init here
        return None
```

   All initialization should be done from `init`. `init` is called after the plugin loads and before any threads are started. If the plugin is running in a seperate process, `init` is called before that process is forked. Do **not** define `__init__` in your class! The parent Plugin class's `__init__` will call init() at the appropriate time.  

### Main thread

``` python
    def main(self):
        #main startup code
        while not self.is_shutdown():
            #main loop
        #main shutdown code
```

If the plugin should run a main thread, define it in `main`. A main thread is not required to handle traffic or events. The `self.is_shutdown()` method returns True if the main thread should exit. The plugin will not stop until `main` returns.

### Handling Packets

``` python
    def effect(self,info,packet):
        ...
        return info,packet
```

   `effect` is the traffic handling method. It is called when traffic is dispatched to the plugin.
    Be sure to return the modified `info` and `packet` as the objects passed into the plugin may be discarded.
    To modify the actual traffic, modify `packet`. Changes to `info` will not modify `packet`.
    A dictionary must be returned for `info` . Returning None for `packet` will drop the traffic.
    Traffic returned from `effect` is dispatched to linked plugins. Setting the `dispatch` or `dest` keys in info will control dispatch. (Refer to `link` usage for dispatching rules.)

### Handling Events

``` python
    def handle_event(self,event):
        ...
        return True
```

`handle_event` is called when an event the plugin has been subscribed to occurs. `event` will be the event object. Event-specific handlers can be defined as `handle_event_`*eventname* or `handle_event_`*eventname*`_`*eventsource*
    The most specific handler will be called. Event handlers may optionally return True to allow a wait() call to continue.

``` python
    def idle(self,count):
        ...
        return None   
```

`idle` is called once per second while the event queue is empty. `count` is the number of times `idle` has been called since the last event was handled.

## API Methods

These methods are provided by the Plugin class.

* `self.config([`*key*`[=`*value*`]])`    get or set plugin configuraton.  
    `config` with no arguments will return the plugin config. A *key* argument will return the value of *key*. `!`*key* will delete *key*. *key*`=`*value* will set *key* to *value*. Returns the set values. Plugin configuration may also be accessed via `self.`*key* attributes or self[*key*] items but should not be set this way as it will not be reflected in the persistent state `config` (and `self.get(`*key*`,`*default*`)`) support dotted-keys.

* `self.event([`*eventname*`],[event=`*event*`],[sync=True],[**`kwargs`])`     generates and publishes an event to the framework.  
    If *eventname* is omitted it will be set to the plugin name. `sync=True` will block until the event is handled. The `event=` argument can be an existing Event object, it will be passed as-is. All other keyword arguments will populate the event data. Returns the generated Event object.
* `self.call(`*method*`,*`*args*`,**`*kwargs*`)`    call a method in the framework
    `call` will call a method in the framework. For example, this can be used by plugins to load/stop/configure other plugins. Returns the result.
* *plugin*.`wait(`[*timeout*]`)`   wait for plugin to handle an event  
    `wait` will block until an event handler returns True (or the optional *timeout* expires) and may be safely called from outside the plugin context. Returns True if an event was handled with result=True, else False.

* `self.dispatch(`*info*`,`*packet*`)`    dispatch traffic to linked plugins  
    `dispatch` is normally called after `effect` returns, but may be called manually (for example, from `main` or `idle`) to generate traffic. Keep in mind *info* will be modified by `dispatch`, so if calling `dispatch` from `effect` to duplicate an existing info/packet tuple you should pass `info.copy()` Refer to `effect` and the dispatching rules in the usage of `link` for more information. Returns a list of plugin names the traffic was dispatched to.
* *plugin*`.inject(`*info*`,`*packet*`)`  inject traffic to plugin  
    `inject` will inject traffic to the plugin and may be safely called from outside the plugin's context. Injected traffic will pass through any configured filter and `effect` before being dispatched.

* `self.set_state(**`kwargs`)`    Set *key*=*value* pairs in state.  
* `self.get_state([`key`])`       Get all or *key* from state.  
* `self.del_state([`key`])`       Delete all or *key* from state.  
    Sets, gets, or deletes key/value pairs from the persistent state. Dotted-keys are supported. `set_state` returns a dictionary of key/value pairs modified. For `get_state`, if no *key* is given all state will be returned.
    Returns value of *key*, else a dictionary of all state. For `del_state, if no *key* is given all state is deleted. Return True if any state was deleted.

* `self.debug(`*message*`,*`*args*`,**`*kwargs*`)`  
* `self.info(`*message*`,*`*args*`,**`*kwargs*`)`  
* `self.warning(`*message*`,*`*args*`,**`*kwargs*`)`  
* `self.error(`*message*`,*`*args*`,**`*kwargs*`)`  
    Convenience methods for logging, will call `self.log(...)` with the appropriate level set.

 `self.stop()` Signals the plugin to stop.  
    The plugin will not terminate until the event (and packet queue, if queuing packets) are empty, and the `main` method exits. Check the return value of `self.is_shutdown()` to determine if `main` should exit.

# Framework API

The framework can be used in your own code by importing and instantiating a Framework object:

``` python
from adf import Framework
f=Framework([*args],[start=True|False])
```

any *args* passed to `Framework` will be the startup config. If `start=True` (the default) the Framework will be started.

* `f.start(`[`*`*args*]`)`  start or restart the framework. Equivalent to the `restart` command.
* `f.stop()`              stop the framework. Equivalent to the `shutdown` command.  
    If the framework was not started at instantiation, `start` will start it. *args* passed to `start` will be treated as the startup config, replacing any previous startup config. Returns the current startup config.

* `f.read_config(*`*args*`)`  read config files. Equivalent to the `inc` command.  
    *args* are the filenames to read. Returns the result of parsing the config files.

* `f.config(*`*args*`)`  parse *args* as commands.  
    See usage for command reference. Returns the result of parsing commands.

* `f.import_package(`*path*`)`     import to the framework namespace. Equivalent to the `import` command.  
    Imports package at *path* and makes exported classes available.  Returns a dictionary of the package imported and the classes that were made available.

* `f.load_plugin(`*path*`,`[`name=`*name*`],**`*kwargs*`)`  load a plugin and configure it. Equivalent to the `plugin` commend.  
    Loads *path* (a path to import or the name of a class already imported) as a plugin and sets the name to *name*. If *name* omitted, uses the class name. Names must be unique within a framework instance. *kwargs* are the initial config of the plugin. Returns a `{name:PID}` dictionary if the plugin was succesfully started.

* `f.start_plugin(`*class*`,`[`name=`*name*],`**`*kwargs*`)`     instantiate *class* as a plugin and configure it.  
    Instantiates a class already in the local namespace as a plugin. Arguments are the same as `load_plugin`. (`load_plugin` loads a class from *path* and calls `start_plugin`). This is useful when you define a plugin class in the same module you are running the framework from. Returns the running plugin object.

* `f.get_plugin(`*name*`)`     return the running plugin object named *name*.

* `f.stop_plugin(`*name*`)`    stops, unlinks, and unloads plugin named *name*. Equivalent to the `stop` command.

* `f.config_plugin(`*name*`,*`*args*`,**`*kwargs*`)`  sets/gets/deletes config of*name*. Equivalent to the `config` command.
    Arguments are passed the the plugin's `config` method as-is. Returns result from plugin's `config` method. See `Plugin.config` or the `config` command.

* `f.link_plugin(`*name*`,`[*destname*[`:`*priority*] ... ]`)`    link plugin. Equivalent to the `link` command.
* `f.unlink_plugin(`*name*`,`[*destname*[`:`*bidir*] ... ]`)`     unlink plugin. Equivalent to the `unlink` command.  
    Links/unlinks *name* and all *destname* arguments provided. See the `link` and `unlink` commands for tde priority and bidir arguments. Returns a list of current links as `(`*destname*`,`*priority*`)` tuples.

* `f.call_plugin(`*name*`,`*method*`,*`*args*`,**`*kwargs*`)`   call *method* in plugin *name*, passing args/kwargs and returning the result. Equivalent to the `call` command.

* `f.subscribe(`*name*`,` [True|*eventname* ... ]`)`  subscribe plugin *name* to events. Equivalent to the `sub` command.  
    Subscribes *name* to *eventname*(s) given. If argument is True, subscribe plugin to all events.
Replaces current subscriptions. If no *eventnames* given, plugin will be unsubscribed from all.
`subscribe` returns `{name:subs}`
* `f.get_subs(`*name*`)`      Get event names plugin *name* is subscribed to.

* `f.event(`*eventname* | `event=`*event*`,`[`sync=True`]`, **`*kwargs*`)`     Publish event. Equivalent to the `event` command.  
The *eventname* or an existing Event object must be provided with event=*event*. If `sync=True` the call will return when the event has been handled by all subscribers. Returns the event published.

* `f.lock(`[*timeout*]`)`     Locks event handling. Equivalent to the `lock` command. Returns True if lockwed within *timeout*.
* `f.unlock()`                Unlocks event handling. Equivalent to the `unlock` command. Returns True if it was locked.
* `f.wait(`[`timeout=`*timeout*]`,`[`name=`*eventname*]`)`     Waits for event to be handled. Equivalent to the `wait` commamd.  
    `wait` will automatically lock and unlock event handling if it was not already locked.
If *eventname* is given, events will be handled until *eventname* is handled or *timeout* occurs.
If *timeout* is omitted, wait forever.Returns most recently handled event.

* `f.set_state(`*name*`,**`*kwargs*`)`  sets state of *name*. Calls *name*`.set_state` and returns result. Equivalent to the `set` command.
* `f.del_state(`*name*`,[`*key*`])`    get state of *name*. Calls *name*`.get_state` and returns result. Equivalent to the `get` command.
* `f.del_state(`*name*`,[`*key*`])`    deletes state of *name*. Calls *name*`.del_state` and returns result. Equivalent to the `del` command.

* `f.load_state(`[*filename*]`,`[`flush=`False|True]`,`[`restore=`False|True]`,`[`state=`*state*]`)`   loads state from *filename*. Equivalent to the `load` command.  
    If *filename* is omitted, will try to load from previously set filename. Returns the filename if set.
    See the `load` command for the meaning of the flush and restore arguments. A state dictionary can also be imported by passing it in the `state=` argument.

* `f.save_state(`[*filename*]`,`[*interval*]`)`    saves state to *filename*. Equivalent to the `save` command.  
    See the `save` command for the effect of the optional *interval* argument. If a save filename has been set, state will be automatically saved on `stop`

* `f.dump_state(`[*eventname*]`)`     dump state to dictionary or event.  
    If *eventname* is given, an event containing the framework state will be published as *eventname*
    Returns the framework state in a dictionary.
