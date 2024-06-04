#!/usr/bin/env python3

from adf import *
import math
from adf.canbus.j1939 import is_param_valid, J1939DecodeId


class Stats(Plugin):
    '''generate statistics for parameters seen in PGNs
state generated is:
    PGN: {param: {ts: n: min: max: mean: stdev: }}

    when idle for interval, send state update since last interval'''
    interval = 1

    def init(self):
        self.__updated = {}  # cache of updated stats since last idle

    def __update(self, ts=None, pgn=None, pgn_name=None, param=None, value=None):
        # get stats from update cache, or from persistant state, or initialize
        spn, spn_name = param.split(None, 1)
        stats = self.__updated.setdefault(param,
                                          self.get_state(param,
                                                         dict(param=param, spn=spn, spn_name=spn_name, pgn=pgn, pgn_name=pgn_name,
                                                              ts=ts, value=value, count=0,
                                                              last_v=value, last_t=ts, first_t=0,
                                                              min=None, max=None, mean=0.0, M2=0.0)))
        # update stats
        stats['ts'] = ts
        if not stats['first_t']:
            stats['first_t'] = ts
        stats['value'] = value
        if stats['min'] is None or stats['min'] > value:
            stats['min'] = value
        if stats['max'] is None or stats['max'] < value:
            stats['max'] = value
        # welford's algo
        stats['count'] += 1
        delta = value - stats['mean']
        stats['mean'] += delta / stats['count']
        delta2 = value - stats['mean']
        stats['M2'] += delta * delta2
        return stats

    def idle(self, count):
        if not self.interval or not count % self.interval:
            for param, stats in self.__updated.copy().items():
                (count, mean, variance) = (
                    stats['count'], stats['mean'], stats['M2']/stats['count'])
                stats['sd'] = math.sqrt(variance)
                stats['elapsed'] = stats['ts']-stats['first_t']
                if stats['last_t'] != stats['ts']:
                    delta = (stats['value']-stats['last_v']) / \
                        (stats['ts']-stats['last_t'])
                else:
                    delta = None
                # send event for each updated param
                if self.interval:
                    self.event(**stats)
                stats['last_t'] = stats['ts']
                stats['last_v'] = stats['value']
                self.set_state({param: stats})  # save to shared state
                try:
                    del self.__updated[param]  # clear from cache
                except:
                    pass
        # self.debug('updated')

    def effect(self, info, msg):
        params = info.get('J1939', {}).get('params', {})
        for param, v in params.items():
            valid, p_range = is_param_valid(params, param)
            if valid and (type(v) is int or type(v) is float):
                self.__update(ts=info['ts'],
                              pgn_name=params['name'],
                              pgn=params['PGN'],
                              param=param,
                              value=v)
            if not self.interval:
                self.idle(0)
        return info, msg


class BusStats(Plugin):
    '''generates a count of total messages and messages per pgn
    sends as event(count=n, pgns={n:n_count,....})'''

    pgns = {}
    count = 0

    def effect(self, info, msg):
        self.count += 1
        pgn = J1939DecodeId(msg)['PGN']
        self.pgns[pgn] = self.pgns.get(pgn, 0)+1
        return info, msg

    def idle(self, count):
        if self.count:
            self.event(count=self.count, pgns=self.pgns)
        self.count = 0
        self.pgns = {}


class Alert(Plugin):
    '''build a stats profile for the vehicle by listening to events from stats, evaluate statement for param name

    config is 
    "parameter name | *"="eval statement"
    statement will be evaluated if parameter name matches or a "*" statement exists
    available vars are plugin config dict and value,param,pgn,pgn_name,ts,count,min,max,mean,sd,delta 
    expression should evaluate to True if event should be generated, False if not.

    If expression returns a dict, items will be merged into event data. 
    For example:
        "<parameter name>"="{False:False,True:dict(message=param+' is out of spec')}[<thresholding expression>]}"
    '''

    def init(self):
        self.__cache = {}
        self.__config_cache = {}

    def idle(self, count):
        '''on idle, sync shared state and config changes'''
        self.__config_cache = self.config().copy()
        self.set_state(self.__cache.copy())
        self.__cache.update(self.get_state())
        # self.debug('synced')

    def handle_event(self, event):
        '''incoming stats, update cache'''
        self.__cache.setdefault(event['param'], {}).update(event.data())

    def effect(self, info, msg):
        params = info.get('J1939', {}).get('params', {})
        for param, value in params.items():
            expr = self.__config_cache.get(param)  # get parameter expression
            if not expr:
                expr = self.__config_cache.get('*')  # get global expression
            # if not expr, we don't care about this param
            if expr:
                valid, p_range = is_param_valid(params, param)
                if valid and (type(value) is int or type(value) is float):
                    stats = self.__cache.get(param)
                    if stats:
                        stats['value'] = value  # add current value to stats
                        if expr:
                            # provide config vars and stats vars to expression
                            r = None
                            try:
                                r = eval(expr, self.__config_cache, stats)
                            except Exception as e:
                                self.debug(e, exc_info=True)
                            if r:  # generate event if ~ True
                                # if we get a dict, update the stats
                                if type(r) is dict:
                                    stats = stats.copy()  # don't mess with the dict from cache
                                    stats.update(r)
                                # self.warning("%s"%stats)
                                self.event(**stats)
        return info, msg
