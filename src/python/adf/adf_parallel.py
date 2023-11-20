#!/usr/bin/env python3

import sys
import os
import time
import subprocess
import threading
import logging
logging.basicConfig(level=logging.INFO, stream=sys.stdout)

thread_pool = threading.Semaphore(value=int(os.environ.get('POOL', 10)))
RETRY = int(os.environ.get('RETRY', 1))


class process(threading.Thread):
    def __init__(self, cmd, *args):
        self.cmd = cmd
        self.args = list(args)
        threading.Thread.__init__(self, target=self.process, daemon=False)
        self.name = '%s_%s' % (os.path.basename(
            cmd), '_'.join(os.path.basename(a) for a in args))
        self.done = '.done_%s' % self.name
        thread_pool.acquire()
        self.start()

    def write_status(self, start, rc):
        try:
            with open(self.done, 'w') as f:
                f.write('%s %s %s %s\n' % (self.name, str(
                    time.time()), str(time.time()-start), rc))
        except Exception as e:
            logging.warning('writing %s: %s', self.done, e)

    def process(self):
        try:
            if os.path.exists(self.done):
                logging.info('%s already done', self.name)
            else:
                rc, retries, start = -1, 0, time.time()
                while rc:
                    logging.info('%s starting', self.name)
                    rc = subprocess.run([self.cmd]+self.args).returncode
                    if rc:  # abnormal exit
                        logging.warning('%s exited %s', self.name, rc)
                        retries += 1
                        if retries > RETRY:
                            logging.error('%s exceeded retry limit', self.name)
                            self.write_status(start, rc)
                            break
                    else:  # normal exit
                        logging.info('%s done', self.name)
                        self.write_status(start, rc)
        except Exception as e:
            logging.error('%s: %s', self.name, e, exc_info=True)
        thread_pool.release()

def main():
    if len(sys.argv) < 2:
        print("usage:")
        print(
            "\t%s <cmd> [args...] will run <cmd> [arg] for each arg in parallel" % sys.argv[0])
        print("\tcat <argfile> | %s <cmd> will run <cmd> for each line of <argfile> in parallel" %
              sys.argv[0])
        print("\tcat <cmdfile> | %s - will run each line of <cmdfile> in parallel" %
              sys.argv[0])
        sys.exit()

    if len(sys.argv) == 2:
        if sys.argv[1] == '-':
            CMD_FROM_STDIN = True
            logging.info('reading commands from STDIN')
        else:
            CMD_FROM_STDIN = False
            cmd = sys.argv[1]
            logging.info('reading args for %s from STDIN', cmd)
        for l in sys.stdin.readlines():
            args = l.strip().split()
            if CMD_FROM_STDIN:
                cmd, args = args[0], args[1:]
            process(cmd, *args)

    else:
        for a in sys.argv[2:]:
            process(sys.argv[1], a)

if __name__ == "__main__":
    main()
