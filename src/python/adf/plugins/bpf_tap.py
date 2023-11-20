# /usr/bin/env python
from adf import *

import subprocess

from IPy import IP
def parse_ip(ips): return [IP(p.strip()) for p in ips.split(',')]


class bpf_tap(Plugin):
    '''generate bpf_tap BPF from events'''
    bpf = 'tap.bpf'
    command = 'pkill -HUP bpf_tap'

    def init(self):
        self.__bpf = set()
        self.__last_bpf = None
        self.template = None

    def handle_event(self, event):
        '''we don't handle packets, just events
            event name should be plugin name and 
            k/v pairs are [add/del]<type>=<expr>
            example: call plugin.event(name='bpf_tap',addips='1.1.1.1,2.2.2.2') '''
        if event.name != self.name:
            return False  # we only handle bpf_tap eventts
        for k, v in event.data().items():
            if k == 'clear':
                self.__bpf = set()
                self.__last_bpf = None  # force an update
            # set, add, or remove IPs/ranges
            elif k == 'ips':
                self.__bpf = parse_ip(v)
            elif k == 'addips':
                self.__bpf.update(parse_ip(v))
            elif k == 'delips':
                self.__bpf.difference_update(parse_ip(v))
            # set add or remove ports
            elif k == 'ports':
                self.__bpf = parse_int(v)
            elif k == 'addports':
                self.__bpf.update(parse_int(v))
            elif k == 'delports':
                self.__bpf.difference_update(parse_int(v))
            # set, add or remove BPF filter expressions
            elif k == 'filter':
                self.__bpf = set([v])
            elif k == 'addfilter':
                self.__bpf.add(v)
            elif k == 'delfilter':
                self.__bpf.remove(v)

    def stop(self, *args):
        # clear BPF when we shutdown
        self.__bpf = set()
        self.idle()
        Plugin.stop(self, *args)

    def idle(self, count):  # update BPF when we go idle
        if self.__bpf == self.__last_bpf:
            return  # if nothing has changed, do nothing
        else:
            self.__last_bpf = set(self.__bpf)  # copy set
            bpf_rules = []
            for r in self.__bpf:
                if type(r) is IP:
                    if r.len() == 1:
                        bpf_rules.append('host %s' % r)
                    else:
                        bpf_rules.append('net %s' % r)
                elif type(r) is int:
                    bpf_rules.append('port %d' % r)
                else:
                    bpf_rules.append(str(r))
            if self.template:
                with open(self.template) as template_fh:
                    template = template_fh.read()
            else:
                template = '%s'
            bpf_text = template % (" or ".join(bpf_rules))
            self.debug('BPF: '+bpf_text)
            with open(self.bpf, 'w') as bpf_fh:
                bpf_fh.write(bpf_text)
            self.debug('%d written to %s' % (len(bpf_text), self.bpf))
            p = subprocess.Popen(self.command.split())
            self.debug('%s: %s' % (p.pid, self.command))
            return p.wait()
