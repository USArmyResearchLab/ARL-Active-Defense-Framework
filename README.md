# ACTIVE DEFENSE FRAMEWORK

The Active Defense Framework (ADF) is a fully modular packet processing and event-handling framework.
ADF provides a plugin-based architecture and can be implemented on traditional networks or vehicle networks such as a Controller Area Network (CAN) bus.

## Installing

ADF requires Python 3.
Building ADF requires PIP and the development packages for Python and libpcap. If these are not available, some components will not be built.  
`make apt` will try to install these on a system with APT support, as long as you have sudo privileges.

`make` will build the core framework and use PIP to install the dependencies for PCAP and CAN support.

ADF requires root or equally privileged access to the interfaces to capture and inject traffic on network interfaces. CAN interfaces do not require privileges.

## USAGE

``` text
bin/adf <startup-config | startup commands | - for config from STDIN>
commands:
    inc [filename ...] - load commands from filename
    import <package> - import package
    env [var[=value]] - get/set environment variables, can be used in commands as $var
    log <level=CRITICAL|ERROR|WARNING|INFO|DEBUG> [filename=] [filemode=] | configuration> - set log level or config
    control <listen-address> <port> [options]- start TCP control server, listens for commands
    plugin <module> [name=<name>] [key=value] ... - load <module> as <name> and set config key=value
    stop <name> - stop plugin <name>
    config <name> [key=value] ... - set <name> config key to value
    link <name> [name[:priority]]... - get or link dispatch of traffic from <name> to listed names.
    unlink <name> [name] - remove link from <name> to all or [name]
    show [name] - show config of plugin [name] or all
    call <plugin> <method> [args...] - execute plugin.method(args) in plugin process context 
    sub <plugin name> [*|eventnames]... - subscribe plugin to events. * will subscribe to all, -name will unsub from event, -* will unsub all.
    event <name> [args] - manually queue event
    lock [timeout] - lock the event queue
    unlock - unlock the event queue 
    wait [timeout [name]]  - wait [timeout] seconds for [name] or any event to be handled
    del [name [key=value]] - delete all state or named plugin's key or all state
    set <name> [key=value] - set named plugin's state key to value
    get <name> [key] - get named plugin's state key or all
    load <filename> [1=flush] [1=restore] - load state from <filename>, optionally flush existing state, optional restore config
    save <filename> [interval] - save state and config to <filename> and optionally set checkpoint interval
    restart <startup commands> - restart framework, replacing startup commands if specified
    shutdown - shut down framework
```

If a single *startup-config* argument is given, `inc` *startup-config* will be assumed.  
If the argument is `-` configuration commands will be taken from STDIN. Commands should be terminated with newlines.
Arguments that start and end with "double quotes" will include enclosed whitespace. Any text after # not enclosed in quotes is considered a comment and ignored.  

[*arg*] arguments are optional.  ... indicates multiple arguments may be given, separated by whitespace.  
All commands elicit a response of the format `{command: result}`. Invalid commands will have a result of `None`. If an exception occurs the result will be `{ExceptionType:Details}`

* `inc` *filename*  
Read and parse commands from *filename*. Multiple filenames can be provided and will be parsed in the order given.  
Response: `{'inc':[{'filename':[results]}, ... ]}`

* `import` *package*  
Import *package* to ADF namespace. package.module paths are supported.  
Response: `{'import':{package:[names]}}`

* `env` *var* [`=`*value*] ...  
Get environment variable *var*, or set *var* to *value*. Variables can be used in command args with `$`*var*  
Response: `{'env':{var:value}}`

* `log` *configuration*  
Set logging configuration. Arguments such as level=, filename=, filemode=... can be used. If *configuration* is `"{key:value,...}"` it will be evaluated as a logging dictConfig. Log level can also be set with the LOG environment variable, or by setting DEBUG=1  
Response: `{'log':config}`

* `control` *listen-address* *port* [`ssl` *options*]  
Starts a TCP control server on *listen-address:port*. Can specify an SSL configuration, set `ssl certfile=... keyfile=... cafile=... verify=0(none)|1(opt)|2(req)`
`control` with no arguments will stop any running control server  
Response: `{'control': ((listen-address, port), {options})}`

* `plugin` *module* [`name=`*name*] [*key*`=`*value* ... ]  
Loads plugin *module* as *name* and passes *key*=*value* as startup config. *module* can be a full package.module.class path or a class from a previously imported package. If *name* is not specified the class name will be used. All plugins must have unique names. Additional *key*=*value* pairs will be passed to the plugin as the startup configuration. See `config` for details of the configuration key and value format.  
Response: `{'plugin': {name:pid}}`  
pid will be the PID of the process hosting the plugin. Typically this is the same PID as the framework's process, but if ADF is running in multiprocessing mode (ADF_MP) it will be different.  

* `stop` *name*   Unlinks and stops plugin *name*.  
    Response: `{'stop':name}`

* `config` *name* [[`!`]*key*[`=`*value*] ... ]  
 Gets or sets plugin *name* configuration.  
 A *key*=*value* argument will set plugin *name* configuration *key* to *value*.  
 Response: `{'config': {name: {key:value}}}`  
 A *key* argument will return the value of *key* in plugin *name* configuration  
 Response: `{'config': {name: value}}`  
 A !*key* argument will delete *key* from *name*' configuration.  
 Response: `{'config': {name: None}}`  
 No additional arguments will return the full configuration of *name*.  
 Response: `{'config': {name: {config} }}`  

  `config` supports a dotted-key format for specifying nested keys: Key 'a.b.c' will get or set value of `{'a':{'b':{'c':value}}}`  
  if setting 'a.b.c', the 'a' and 'b' dictionaries will be created if necessary. Key `a.b` would return  `{'c':value}`

  Values are automatically parsed to integers if possible, otherwise remain strings. A comma-separated list of integers (`'1,2,3'`) will be parsed to a list (`[1,2,3]`).

* `link` *name* [*destname*[`:`*priority*] ... ]  
    Links traffic dispatch from plugin *name* to plugin *destname* with optional *priority*. If no *destname* argument is given, return current links. Links determine how traffic flows between plugins. Priority may be 1, 0, -1, or omitted. If no priority is specified, links with priority 0 will be created from *name* to *destname*, and from *destname* to *name* (bidirectional flow). If a priority is specified, only a link from *name* to *destname* will be created (unidirectional flow)  
    Response: `{'link': {name: [(destname,priority), ... ]}}`

    After traffic is processed by a plugin it is sent to linked plugins based on dispatch rules:
  * IF traffic has `dest` info AND any plugins named in `dest` are linked:
    * Traffic will ONLY be dispatched to plugins in `dest`  
  * ELSE
    * Traffic will be dispatched to any plugins linked with a priority of 1
    * IF traffic has `dispatch` info:
      * Clear `dispatch` info.  
      * Dispatch to all plugins in `dispatch` IF they are linked. Links with priority -1 will never get traffic UNLESS named in `dest` or `dispatch`.  
    * ELSE:  
      * Dispatch to all plugins linked with priority 0, UNLESS plugin name is in `prev` info. This prevents dispatch loops.
  * When traffic is dispatched from a plugin, that plugin's name is appended to the `prev` info.

  In summary:
  * Priority 1 will always receive traffic.
  * Priority 0 will receive traffic that does not have dispatch info.
  * Priority -1 will not receive traffic unless is in the dispatch info.

* `unlink` *name* [*destname*... ]  
    Removes link from plugin *name* to plugin *destname*. By default removes links between *name* and *destname* (bidirectional). To only remove link from *name* to *destname* (unidirectional) specify *destname*`:0` If no *destname* argument is given, remove all links from *name* (unidirectional, any links to *name* are not removed. Returns current links.  
    Response: `{'unlink': {name: [(destname,priority), ... ]}}`

* `sub` *name* [`*` | `-*` | *eventname*  | `-`*eventname* ... ]  
    Subscribe plugin *name* to events. If *eventname*(s) given, subscribe *name* to event *eventname*. If `-`*eventname*(s) given, unsubscribe *name* from event *eventname*. If `*` is provided as the event name, subscribe *name* to all events. If `-*` is provided as the event name, unsubscribe *name* from all events. If no event names are provided, return current subscriptions.  
    Response: `{'sub': {name: True if all events | (eventname, ... )}}`

* `show` [*name* ... ]  
    Show plugin config, links, and subscriptions. If one or more plugin names are specified, show only those plugins. Else show all loaded plugins.  
    Response: `{'show': {name: {'config':{config}, 'links': [(destname,priority), ... ], 'subs': True|(eventname,...) }, ... }}`

* `call` *name* *method* [*args*]  
    Execute *method* in plugin *name*. `call` is used to execute code in plugin *name*'s context, by generating an event and passing it to the plugin. This allows *method* to be run in the proper context even if the plugin is in a different process. All supplied positional and/or keyword (name=value) args will be passed to *method*. `call` return the result from the method called.
    Response: `{'call': {name: result}}`

* `event` *eventname* [*key*`=`*value* ... ] [`sync=1`]  
    Generate an *eventname* event containing *data*. An event with name *eventname* will be generated and queued. Any *key*=*value* pairs will populate the event data. The event will be published to all plugins subscribed to *eventname*. If the `sync=1` argument is provided, `event` will block until all subscribers have handled the event.  
    Response: `{'event': {eventname: {eventdata}}}`

* `lock` [*timeout*]  
    Lock the event queue. Tries to acquire a lock on the event queue for *timeout* seconds if specified. Otherwise, returns once queue is locked. Response indicates if lock was acquired. When event queue is locked, events may be queued but will not be published to subscribers.  
    Response: `{'lock': True|False}`

* `unlock`  
    Unlock the event queue. Response indicates if a lock was actually held.  
    Response: `{'unlock': True|False}`

* `wait` [*timeout*] [*eventname*]
    Wait for any event or *eventname* to be handled. Waits up to *timeout* seconds if provided. If *timeout* is not provided or non-numeric, waits forever. If *eventname* is not provided, will return when any event is handled. If *eventname* is provided, will handle all queued events until *eventname* is handled or timeout occurs. If the event queue is not locked, `wait` will lock the queue before waiting and unlock it before returning.  
    Response: `{'wait': None | {eventname:{eventdata}}}`

* `set` *name* *key*`=`*value* ...  
    Sets *key* to *value* in plugin *name*'s state dictionary. Dotted-keys are supported (see `config`).  
    Response: `{'set': {name: value}}`

* `get` [*name*] [*key*]  
    Get all state, *name* state, or *key* from *name* state. Dotted-keys are supported (see `config`).  
    *name* and *key* arguments will return the value of *key* in plugin *name* state.  
    Response: `{'get': {name: value}}`  
    A *name* argument will return the full state of *name*  
    Response: `{'get': {state} }}`  
    No arguments will return the state of all plugins.  
    Response `{'get': { name: {state}, ... }}`

* `del` [*name*] [*key*]  
    Delete all state, *name* state, or *key* from *name* state. Dotted-keys are supported (see `config`).  
    *name* and *key* arguments will delete *key* from plugin *name* state.  
    Response: `{'del': True|False if *key* was deleted from *name* state}`  
    A *name* argument will delete all state of *name*.  
    Response: `{'del': True|False if *name* state was deleted}`  
    No arguments will delete all state of all plugins.  
    Response `{'del': True}`

* `save` [*filename*] [*interval*]  
    Saves plugin and framework state to *filename*. The framework state is loaded plugins and their configuration, plugin links, and event subscriptions. `save` with no arguments will use previously set filename. *interval* will set the interval (in seconds) at which state will be automatically saved. If filename has been set, state will be automatically saved at framework shutdown.  
    Response: `{'save': filename}`

* `load` [*filename*] [`flush`|`flush restore`]  
    Loads plugin and optionally framework state from *filename*. If the `flush` argument is given, all plugin state will be deleted before loading state, else loaded state will be merged. If the `flush restore` argument is given, the framework state will be also restored from the loaded state. The framework state is loaded plugins and their configuration, plugin links, and event subscriptions.  
    Response: `{'load': filename}`

* `restart` [*startup config*]  
    `restart` with no arguments will restart the framework. State will be saved if `save` was previously called to set a save filename. All plugins will be stopped and the framework will then restart, reapplying any startup command line arguments such as a config file. If *startup config* arguments are provided, that will become the new configuration used whenever the framework restarts. (If specifying a config file, be sure to use the `inc` command: `restart inc` *configfile* ) Any `control` server will remain available, to prevent disconnection if `restart` is issued over the socket.  
    Response: `{'restart': [current startup config]}`

* `shutdown`  
    Shut down the framework. State will be saved if `save` was previously called to set a save filename. All plugins will be stopped and the framework will then terminate. `control` server will stop listening and disconnect any clients.  
    Response: `{'shutdown': None}`

## Plugins

Plugins are the ADF traffic-handling components, and are linked by the framework to other plugins.
Each packet (IP traffic, CAN message, etc...) is handled by a plugin in the following sequence:

1) Receive: Packets are either immediately handled or queued by the plugin. This is configured by the `queue=0|1` argument.  
    Traffic is always passed between plugins as an `(info,packet)` tuple.
    * `info` is a dictionary containing traffic metadata.
            Basic information such as timestamp and source will always be present.
            Plugins that perform decoding or traffic analysis can add to info.
    * `packet` is the actual packet data. For IP this will be a `dpkt` object, for CAN it will be a `can.Message`.
2) Filter: If a filter expression is configured by the `filter=`*expr* argument, *expr* will be evaluated and the traffic will pass if *expr* returns True.  
*expr* should be a valid Python expression using `info` the for info dictionary and `packet` for the packet data.
3) Effect: Performs traffic modification. The `effect()` method is where most custom plugin code is typically written.  
The default effect method is to execute any statements defined in `exec*` config arguments.  
        Like filtering, the statements should expect `info` and `packet` variables. Modifications to `packet` will modify the traffic.
4) Dispatch: Forward traffic to linked plugins. See `link` under usage for dispatch rules.  
Relevant keys in `info` that affect dispatch:
    * `source`: first plugin to handle this traffic.
    * `dest`: name or list of names the traffic will be unconditionally dispatched to only if plugin is linked, else `dispatch` will apply.
    * `dispatch`: name or list of names the traffic should be dispatched to. Will be deleted on dispatch.
    * `prev`: list of plugins this traffic has passed through, to prevent dispatch loops. WUll be updated on dispatch to add this plugin.

### Interface Plugins

Interface plugins are specialized plugins that receive and send traffic to and from ADF.
Normally this will be via a standard network interface, but interface plugins exist for reading/writing packet capture files,
creating virtual interfaces, and connecting to other networks such as Controller Area Network (CAN) bus.

* `Interface` captures packets from a network interface.
The Interface plugin will set the `source` key in info to the name of the plugin for incoming packets.
    Packets dispatched to an Interface plugin will be sent from the interface.  
    `device=`*devname* is required and selects which network device the plugin attaches to.
    You must have permission to put the device in promiscuous mode and capture or the plugin will not load.  
The `filter=`*expr* argument controls what packets are injected on the interface, not which packets are captured.  
`decode=0|1` disables or enables decoding with dpkt. Default is to decode.  
    If decoding is disabled, the `packet` will be raw bytes, not a dpkt object.
    Keys generated in `info` by decoding:

``` text
    data    Packet payload, as bytes
    flags   TCP flags if TCP. Integer value representing flag bits.
    len     Packet length in bytes.
    proto   “arp” if ARP or IP protocol value (1=ICMP,6=TCP,17=UDP, etc…)
    sip,dip     Source and destination IP addresses as IPy objects.
    smac,dmac   Source and destination MAC addresses as bytes.
    sport,dport Source and destination TCP/UCP ports if applicable
    ts          Timestamp of packet
    vlan        VLAN tag if present
```

* `Tap`  is an `Interface` plugin, but creates a virtual interface rather than attaching to an existing device.  
`device=`*tapname* is optional and sets the name of the tap interface. If omitted the system will choose a name.
    You must have permission to create taps or the plugin will not load.  
`hwaddr=`*macaddress* sets the MAC address of the tap.  
`addr=`*ipaddress* sets the IP address of the tap.  
`netmask=`*netmask* sets the netmask of the tap.  
`mtu=`*MTU* sets the MTU of the tap. Default is 1514.  

* `Pcap` uses libpcap to read/write PCAP files or to attach to a network interface.  
`pcap_in=`*filename*    Pcap file to read packets from.  
    `delta=1`           If delta is enabled, the pcap_in file will be replayed at actual speed based on the timestamp deltas in the file. The default is to replay the capture as fast as possible.  
`pcap_out=`*filename*   Pcap file to write packets to. Traffic dispatched to a `Pcap` plugin will be written to this file.  
`device=`*devname*      Network device to capture/inject on using libpcap. `Pcap` functions identically to `Interface` in this mode. Cannot be used with pcap_in or pcap_out, and you must have permission to capture on the device.  

### Event plugins

Plugins implement event handling as well as traffic handling. This is used to transport events between ADF instances or support external events.

* `Channel` sends and receives events via UDP.  
`addr=`*hostname/ipaddress* Enables sending to this IP address. A multicast or broadcast address can be specified if supported by the OS.  
`listen=`*ipaddress* Enables listening on this IP address. 0.0.0.0 will listen on all addresses.  
`port=`*udpport*  Send and listen on this UDP port, default 42223.  
`bytes=`*bytes*   sets maximum UDP payload size, default 1024. Larger events will be split into multiple UDP packets.

* `Sender` sends events via TCP.  
`host=`*hostname/ipaddress*     Send to this IP address. Default `localhost`.  
`port=`*tcpport*                Send to this TCP port, default 42224.  
`timeout=`*timeout*             The TCP connection is not established until an event needs to be sent.  `Sender` closes the TCP connection if no activity within *timeout* seconds, default 60. If *timeout* is 0 the connection will not be closed when idle.

* `Listener` listens for events via TCP.  
`listen=`*paddress*     Listen on this IP address. Default `localhost`.  
`port=`*tcpport*        Listen on this TCP port, default 42224.

* `MQTT` sends and receives events via MQTT. Requires paho-mqtt.  
If `MQTT` receives an event, it will publish an MQTT message with the topic set to the event name.  
If `MQTT` is subscribed to an MQTT topic, it will generate events with the name set to the MQTT topic.  
`host=`*hostname/ipaddress*     Connect to this MQTT broker. Default `localhost`.  
`port=`*tcpport*                MQTT broker port, default 1883.  
`subscribe=`*topic*             Subscribe to MQTT *topic*.  

## Sample Configurations

A `default.cfg` is included to set up basic logging, control, and event channels:  

```text
log level=INFO #filename=adf.log #set default log level and destination
control localhost 42222 #cleartext control socket
      plugin Channel addr=10.0.255.255 listen=0.0.0.0 #events broadcast via UDP
subscribe Channel * #channel subscribes/broadcasts all events
```

`inc $ADF/config/default.cfg` will include this from any config file.  

The following configuration will attach ADF to the `eth0` and `eth1` interfaces and forward traffic between the interfaces via a generic plugin. This is an inline network filter.

``` text
inc $ADF/config/default.cfg

plugin Interface name=eth0 device=eth0  #attach to eth0
plugin Interface name=eth1 device=eth1  #attach to eth1
plugin Plugin name=filtering    #generic plugin

config filtering "filter=True"  #all packets pass by default, this can be changed at any time.

link filtering eth0 eth1    #bidirectional links, so eth0<->filtering<->eth1 and vice-versa
```

This configuration is the same as above, but we attach to `eth0` and create a `tap0`. We place the system's IP address on the `tap0` interface instead of `eth0` so ADF is acting as a host-based filter.

``` text
inc $ADF/config/default.cfg

plugin Interface name=eth0 device=eth0  #attach to eth0
plugin Tap name=tap device=tap0 addr=192.168.0.42 netmask=255.255.255.0    #create a tap and assign an IP
plugin Plugin name=filtering    #generic plugin

config filtering "filter=True"  #all packets pass by default, this can be changed at any time.

link filtering eth0 tap     #bidirectional links, so eth0<->filtering<->tap and vice-versa
```

We may want to redirect certain traffic to an alternative interface and log it:

``` text
inc $ADF/config/default.cfg
plugin Interface name=eth0 device=eth0  #attach to eth0
plugin Interface name=eth1 device=eth1  #attach to eth1
plugin Interface name=eth2 device=eth2  #attach to eth2

plugin plugins.redir.Redir name=redir INTERNAL=eth1 EXTERNAL=eth0 REDIR=connlog    #redirection plugin

plugin plugin.connlog.ConnLog name=connlog logfile=connection.log    #connection logging 

# eth0<->redir<------(not redirected)----->eth1
#           ^-(redirected)<->connlog<----->eth2

link connlog eth2       #we are logging traffic to and from eth2 (the redir interface)
link redir eth0 eth1   #default bidirectional links, so eth0<->redir<->eth1 and vice-versa
link redir connlog:-1   #traffic should not go to the logging/eth2 interface unless redir sends it there
link connlog redir:0    #unidirectional, only allow logged responses back from the redir interface

config redir ... #config redirected IPs and conditions here, see plugins.redir.Redir documentation
```

ADF can also transparently log all traffic between two interfaces:

``` text
inc $ADF/config/default.cfg

plugin Interface name=eth0 device=eth0  #attach to eth0
plugin Interface name=eth1 device=eth1  #attach to eth1
plugin plugins.connlog.ConnLog  name-connlog logfile=connection.log

link eth0 eth1          #bidirectional links, so eth0<->eth1 and vice-versa
link eth0 connlog:1     #always log eth0 traffic, no traffic back from logger
link eth1 connlog:1     #always log eth1 traffic, no traffic back from logger
```
