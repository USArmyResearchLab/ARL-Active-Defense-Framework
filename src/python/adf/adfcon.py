#!/usr/bin/env python3

import sys,socket,select

def usage():
    print ('usage: adfcon [configfile, or interactive if not provided] [host=localhost] [port=42222] [timeout=10]')

def main():
    args = []
    opts = {}
    while sys.argv:
        a = sys.argv.pop(0)
        if '=' in a:
            k,v = a.split('=', 1)
            if v.isdigit(): v = int(v)
            opts[k] = v
        else:
            args.append(a)
    args = args[1:] #strip command name

    host = opts.setdefault('host','localhost')
    port = opts.setdefault('port',42222)
    del opts['host'], opts['port']

    try:
        sock = socket.create_connection((host,port))
        sock.settimeout(int(opts.get('timeout',10)))

        if args: fh = open(args[0])
        else: fh = sys.stdin

    except Exception as e:
        print ('%s:%s' % (host,port),e)
        sys.exit(usage())

    def prompt(fh):
        if fh == sys.stdin:
            sys.stdout.write('%s:%s> ' % (host,port))
            sys.stdout.flush() #fix no prompt over ssh

    prompt(fh)
    while True:
        exit = 0
        (i,o,x) = select.select([fh,sock],[],[])
        for s in i:
            if s is sock:
                r = sock.recv(4096)
                if not r: break
                r = r.decode()
                sys.stdout.write(r)
                sys.stdout.flush()
                if r.endswith('\n'):
                    if exit: exit = 2
                    prompt(fh)
            if s is fh:
                l = fh.readline()
                if not l: exit = 1
                if l != '\n': sock.send(l.encode())
                else: prompt(fh)
        if exit == 2: break

    sock.close()

if __name__ == "__main__":
    main()
