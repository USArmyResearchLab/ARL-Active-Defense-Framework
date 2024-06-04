#!/usr/bin/env python3
'''FRAMEWORK LAUNCHER'''

import os
import signal
import sys

def usage():
    print("%s <startup-config | startup-commands | - for config from STDIN>" %
          sys.argv[0])
    print('''commands:
    inc <file> - load commands from <file>
    import <package> - import package
    env [var[=value]] - get/set environment variables, can be used in commands as $var
    log <level=CRITICAL|ERROR|WARNING|INFO|DEBUG> [filename=] [filemode=] | configuration> - set log level or config
    control <listen-address> <port> [ssl options] - start TCP control server, listens for commands
    plugin <module> [name=<name>] [key=value] ... - load <module> as <name> and set config key=value
    stop <name> - stop plugin <name>
    config <name> [key=value] ... - get or set <name> config key to value
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
    restart <startup-commands> - restart framework, replacing startup commands if specified
    shutdown - shut down framework
''')


def main():

    import logging

    # TODO convert all of these env variables to an argparse.ArgumentParser?

    # if LOG or DEBUG var is set, try setting logging to specified text/int level
    if os.environ.get('DEBUG'):
        logging.basicConfig(level=logging.DEBUG)
    if 'LOG' in os.environ:  # may be used to specify a log file so ignore errors here
        try:
            level = int(logging.__dict__.get(
                os.environ['LOG'], os.environ['LOG']))
            logging.basicConfig(level=level)
        except:
            pass

    # launch as adf_mp or set the env ADF_MP=1 to select multiprocessing mode
    if sys.argv[0].endswith('_mp'):
        os.environ['ADF_MP'] = '1'

    # set ADF envar to base directory to allow easy access to configs
    os.environ['ADF'] = base =os.path.dirname(__file__)
    #add base and src dirs (for core code if not installed) to import path
    sys.path.append(base)
    sys.path.append(os.path.join(base,'src','adf'))
    
    #now we can import
    from adf import Framework

    # parse args, setup signal handlers and jump to main
    config = sys.argv[1:]
    if not config:
        sys.exit(usage())  # no args, print usage
    if config[0] == '-':
        config = []  # we'll be reading STDIN
    elif len(config) == 1:
        # if we are passed a single arg, treat it as a config file name
        config.insert(0, 'inc')
    # do not start framework until signal handlers are ready
    # pass our globals as superglobals so import_package can make stuff available in the top-level namespace
    f = Framework(start=False, superglobals=globals())
    # trap signals to stop/restart the framework thread
    signal.signal(signal.SIGINT, f.stop)
    signal.signal(signal.SIGTERM, f.stop)
    signal.signal(signal.SIGHUP, f.restart)
    # now start framework
    f.start(*config)
    if not config:
        from pprint import pprint
        while f.is_alive():
            try:
                l = sys.stdin.readline()
                if not l:
                    break
                pprint(f.config(*l.strip().split()))
            except KeyboardInterrupt:
                f.stop()
                break
            except Exception as e:
                print(e, file=sys.stderr)
    # on framework stop, flush logging and exit
    f.join()
    logging.shutdown()
    sys.exit()


if __name__ == '__main__':
    main()
