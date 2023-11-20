from binascii import hexlify, unhexlify
from adf import *
import socket
from IPy import IP


class Redir(Plugin):
    '''route packets between INTERNAL and EXTERNAL interfaces
    unless packet arriving at EXTERNAL interface meets any (or all if MATCH_ALL) eval conditions,
    then redirect packet back out EXTERNAL to REDIR_IP/REDIR_MAC
    track state and redirect responses from REDIR_IP back to original IP

    config items to set:

    INTERNAL: name of internal interface
    EXTERNAL: name of external interface
    REDIR: redirects will use this interface if set, else will use EXTERNAL
    REDIR_MAC: MAC address of default redirection host
    REDIR_IP: IP address of default redirection host

    eval*: pktinfo-based expression to trigger redirection. example: "pktinfo['sip']==IP('X.X.X.X')"
    redir*: MAC,IP pair to specify redirection for traffic triggering matching eval rule
        (optional, if no redirX for evalX, default REDIR_IP and REDIR_MAC are used.)

    MATCH_ALL: if set, all eval rules must match to trigger redirect. only default redirect is used.
'''

    def effect(self, pktinfo, pkt):
        # route traffic from int to ext and by default from ext to int
        if pktinfo['source'] == self.INTERNAL:
            pktinfo['dispatch'] = self.EXTERNAL
        if pktinfo['source'] == self.EXTERNAL:
            pktinfo['dispatch'] = self.INTERNAL
        if pktinfo['source'] == self.EXTERNAL and 'proto' in pktinfo and pktinfo['proto'] != 'arp':
            # responses from redirected packets
            if (pktinfo['sip'] == IP(self.REDIR_IP)) or any(pktinfo['sip'] == IP(v.split(',')[1]) for (k, v) in self.config().items() if k.startswith('redir')):
                try:
                    self.debug("%s->%s response to %s" % (socket.inet_ntop(socket.AF_INET, pkt.data.src),
                                                          socket.inet_ntop(
                                                              socket.AF_INET, pkt.data.dst),
                                                          socket.inet_ntop(socket.AF_INET, self.get_state(str(pktinfo.get('dport')))[1])))
                    # dispatch back out the external
                    pktinfo['dispatch'] = self.EXTERNAL
                    # set packet source to the external interface
                    pkt.src, pkt.data.src = pkt.dst, pkt.data.dst
                    # set packet dest to the original source based on the dest port
                    pkt.dst, pkt.data.dst = self.get_state(
                        str(pktinfo.get('dport')))
                except Exception as e:
                    self.debug(e)
                    # do not pass packets that error out here, we don't want to expose the honeypots
                    return pktinfo, None
            else:
                # save source mac/ip by source port (if possible)
                try:
                    self.set_state({str(pktinfo.get('sport'))                                   : (pkt.src, pkt.data.src)})
                    redir = None
                    for k, v in sorted(self.config().items()):
                        if k.startswith('eval') and self.eval_packet(v, pktinfo, pkt):
                            # eval0 = redir0 and so on
                            redir = k.replace('eval', 'redir')
                        if self.MATCH_ALL:
                            if not redir:
                                break  # if match all, break at false
                        elif redir:
                            break  # else break at first true
                    # redirect packets
                    if redir:
                        # if we have a redir for this source
                        if self[redir]:
                            redir_mac, redir_ip = self[redir].split(',')
                        # use the default redir
                        else:
                            redir_mac, redir_ip = self.REDIR_MAC, self.REDIR_IP
                        self.debug("%s->%s redirect to %s" % (socket.inet_ntop(socket.AF_INET, pkt.data.src),
                                                              socket.inet_ntop(
                            socket.AF_INET, pkt.data.dst),
                            redir_ip))
                        if self.REDIR:
                            # if a redir interface is set
                            pktinfo['dispatch'] = self.REDIR
                        else:
                            # assume redir IP is on the ext.
                            pktinfo['dispatch'] = self.EXTERNAL
                        # set src to dest, set dest to REDIR_IP or redirX IP matching evalX that triggered
                        pkt.src, pkt.data.src, pkt.dst, pkt.data.dst = pkt.dst, pkt.data.dst,\
                            unhexlify(redir_mac),\
                            socket.inet_pton(socket.AF_INET, redir_ip)
                except Exception as e:
                    self.error(e, exc_info=True)
                    # do not pass packets that error out here, we don't want to pass them to the protected host
                    return pktinfo, None
        return pktinfo, pkt  # pass packets on
