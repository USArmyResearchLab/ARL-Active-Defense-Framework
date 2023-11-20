#!/usr/bin/env python3
'''ADF test harness'''

import sys
import os
import time
import logging
import logging.handlers
from queue import Queue, Empty
import threading

TEST_FN = os.environ.get('TEST', 'test')
FAIL_ON_WARN = int(os.environ.get('FAIL_ON_WARN', 1))
LEVELS = {10: 'DEBUG', 20: 'INFO', 30: 'WARNING', 40: 'ERROR', 50: 'CRITICAL'}
TIMEOUT = float(os.environ.get('TIMEOUT', 60.0))

# assume we're in adf/bin so add parent and parent/lib to path and load framework
root = os.path.join(os.path.dirname(sys.argv[0]), '..')
sys.path.append(root)
os.environ['ADF'] = root
sys.path.append(os.path.join(root, 'lib'))

# set up log capture and test monitoring
global fail
module = None
fail = False
start_ts = None
shutdown = threading.Event()
loglevels = {}
lq = Queue()
logging.basicConfig(level=os.environ.get('LOG', 20), handlers=[
                    logging.handlers.QueueHandler(lq)])


def monitor():
    global fail
    global module
    while not lq.empty() or not shutdown.is_set():
        try:
            m = lq.get(timeout=1)
        except Empty:
            if start_ts and time.time()-start_ts > TIMEOUT:
                break
            continue
        print(m.levelname, m.name, m.msg, file=sys.stderr)
        loglevels.setdefault(m.levelno, []).append(m.msg)
    if test_running is True:
        print('%s timed out' % TEST_FN)
        fail = True
    else:
        fail = False
    print()
    for levelno, msgs in sorted(loglevels.items()):
        if levelno > 20:
            print('%sS:' % LEVELS.get(levelno, levelno))
            fail = fail or FAIL_ON_WARN or levelno > 30
            for msg in msgs:
                print('\t%s' % msg)
            print()
    if module:
        if fail:
            print('%s %s failed' % (module, TEST_FN))
        else:
            print('%s %s passed in %s' %
                  (module, TEST_FN, time.time()-start_ts))
    if test_running is not None:
        os.kill(os.getpid(), 9)


monitor_thread = threading.Thread(target=monitor)
monitor_thread.start()

# run test
test_running = None
try:
    module = sys.argv[1]
    from adf.util import import_package
    m, attrs = import_package(module)
    logging.info('%s contains %s', m, attrs)
    test_running = True
    start_ts = time.time()
    getattr(m, TEST_FN)(*sys.argv[2:])
    test_running = None
except Exception as e:
    logging.error(e, exc_info=True)
    test_running = False

# evaluate test
shutdown.set()
monitor_thread.join()
sys.exit(int(fail))
