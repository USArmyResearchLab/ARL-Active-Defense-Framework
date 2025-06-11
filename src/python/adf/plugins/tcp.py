from adf import *
import dpkt
import socket
import random


class TCP(Plugin):
    '''very simple emulation of a TCP stack
        accepts connections and will call self.tcp_recv(key,info,data) when data has been received
        to send data, called self.tcp_send(key,info,data)
        to close connection call self.close_connection(conn)
        config options:
            port: set to only accept on this port, else will accept on all
            ip: set to only accept on this IP, else will accept on all
    '''
    port = None
    ip = None

    # each conn key will hold a pair of remote, local sequence numbers and a receive, send buffer
    conns = {}

    def reply(self, info, seq, ack, flags, data):
        # flip source and dest in info dict and generate the proper TCP packet.
        reply = {
            'dest': info['source'],
            'source': self.name,
            'smac': info['dmac'],
            'dmac': info['smac'],
            'sip': info['dip'],
            'dip': info['sip'],
            'sport': info['dport'],
            'dport': info['sport']
        }
        data = dpkt.ethernet.Ethernet(
            src=reply['smac'], dst=reply['dmac'], type=dpkt.ethernet.ETH_TYPE_IP,
            data=dpkt.ip.IP(v=4, p=dpkt.ip.IP_PROTO_TCP,
                            src=socket.inet_pton(
                                socket.AF_INET, str(reply['sip'])),
                            dst=socket.inet_pton(
                                socket.AF_INET, str(reply['dip'])),
                            data=dpkt.tcp.TCP(
                                sport=reply['sport'],
                                dport=reply['dport'],
                                seq=seq, ack=ack, flags=flags, data=bytes(data))
                            )
        )
        return reply, data

    def effect(self, info, data):
        # bypass traffic we do no care about
        if info['proto'] != dpkt.ip.IP_PROTO_TCP:
            return info, data
        if self.ip and info['dip'] != self.ip:
            return info, data
        if self.port and info['dport'] != self.port:
            return info, data

        # conn key is sip+dip+sport+dport
        key = str(info['sip'])+str(info['dip']) + \
            str(info['sport'])+str(info['dport'])

        # establish new conn on SYN
        if info['flags'] & dpkt.tcp.TH_SYN:
            # store ISN and generate a random one for our end
            self.conns[key] = [info['seq'] + 1,
                               random.randint(0, 2**32 - 1), [], []]
            # reply with SYN+ACK, seq=our ISN, ack=remote ISN+1
            return self.reply(info,
                              self.conns[key][1], self.conns[key][0],
                              dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, [])

        # from here on we do nothing if we don't have a key
        # teardowns
        if key in self.conns:
            if info['flags'] & dpkt.tcp.TH_RST:
                del self.conns[key]
                return info, None  # do not repsond on reset
            # we do reply on fin
            if info['flags'] & dpkt.tcp.TH_FIN:
                reply = self.reply(info,
                                   self.conns[key][1], self.conns[key][0],
                                   dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK, [])
                del self.conns[key]
                return reply

            # if we got an ack, just clear the buffer
            # unless our local seq != ack, in which case resend the buffer if there is anything in it
            if info['flags'] & dpkt.tcp.TH_ACK:
                if self.conns[key][1] != info['ack']:
                    if len(self.conns[key][3]):
                        return self.reply(info,
                                          self.conns[key][1], self.conns[key][0],
                                          dpkt.tcp.TH_PUSH, self.conns[key][3])
                    else:  # if buffer is empty just bump our local seq, like during handshake
                        self.conns[key][1] = info['ack']

            # if we got to this point, we can receive data if there is any to receive
            self.conns[key][0] = info['seq']
            payload = self.conns[key][2] = info['data'] 
            if len(payload):
                # update remote seq for next ack
                self.conns[key][0] = (self.conns[key][0] + len(payload)) % 2**32
                # call the recv handler, you'll override this in subclass
                self.tcp_recv(key, info, payload)

        # if we got this far we either don't handle this packet or there is nothing to return    
        return info, None 

    def tcp_send(self, key, info, payload):
        # save data in case we need to resend
        self.conns[key][3] = payload
        # generate seq=last, ack = last seq from remote, push+ack flags
        reply=self.reply(info,
                   self.conns[key][1], self.conns[key][0],
                   dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, payload)
        # update local seq, wrapping at 2^32
        self.conns[key][1] = (self.conns[key][1] + len(payload)) % 2**32
        # send immediately
        self.dispatch(*reply)

    def tcp_recv(self, key, info, payload):
        # default recv function is to echo what we got
        self.tcp_send(key, info, payload)