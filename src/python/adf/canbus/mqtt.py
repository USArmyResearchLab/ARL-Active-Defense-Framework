from adf import *

from adf.canbus import Message

import paho.mqtt.client as mqtt
import time

import csv


class MQTTClient(Plugin):
    '''sends selected DBC decodes to MQTT topic, generates CAN messages from incoming MQTT messages
        config:
            host/port: MQTT host and port to connect to
            topic: topic to publish
            publish: [list of signal names to publish]
            rate_limit: if set, will not send MQTT faster than this limit (some CAN->MQTT will be dropped)
            subscribe_topic: topic to subscribe to
            subscribe_map: {signal_name: message_name, ...} maps signal in subscribed message to can message.
            id_map: {message_name: arbitration_id, ...} maps can message to arbitration_id 
            extended_id: if True, force 29-bit CAN IDs, else uses ID > 0x7ff to set extended id '''

    client = None
    host = 'localhost'
    port = 1883
    topic = ''
    publish = None
    subscribe_topic = None
    rate_limit = None
    extended_id = False
    subscribe_message = None
    message_id = None
    message_name = None
    message_param = None
    message_active_value = None
    message_inactive_value = None

    def init(self):
        try:
            self.publish = parse_list(self.publish)
        except:
            self.publish = None
        try:
            self.subscribe_map = parse_kvs(parse_list(self.subscribe_map))
        except:
            self.subscribe_map = None
        try:
            self.id_map = parse_kvs(parse_list(self.id_map))
        except:
            self.id_map = {}
        try:
            self.rate_limit = float(self.rate_limit)
        except:
            self.rate_limit = None
        self.__last_send = time.time()

    def main(self):
        while True:
            self.__client = mqtt.Client()
            try:
                self.__client.connect(self.host, self.port)
                self.info('connected to %s:%s', self.host, self.port)
                if self.topic:
                    self.info('publishing %s', self.topic)
                    self.debug(self.publish)
                break
            except Exception as e:
                self.warning(e, exc_info=True)
            time.sleep(1)
        if self.subscribe_topic:
            self.__last_ts = None
            self.__frame = 0  # frames of data received
            self.__params = {}
            self.__client.on_message = self.on_message
            try:
                self.__client.subscribe(self.subscribe_topic)
                self.info('subscribed to %s', self.subscribe_topic)
                self.debug(self.subscribe_map)
                self.debug(self.id_map)
                self.__client.loop_forever()
                self.info('disconnected from %s:%s', self.host, self.port)
            except Exception as e:
                self.warning(e, exc_info=True)

    def disconnect(self):
        try:
            self.__client.disconnect()
        except:
            pass

    def stop(self, *args, **kwargs):
        # if we are multiprocessing, we have to call_method to disconnect in our process
        self.call_method('disconnect')
        Plugin.stop(self, *args, **kwargs)

    def on_message(self, client, userdata, message):
        # build data frame from MQTT messages and send over CAN when new frame starts
        try:
            topic, data = message.topic, message.payload.decode().split(',')
            # data format is timestamp,param,value
            # frame data will be across multiple MQTT messages
            # but all data from the same frame will have the same timestamp
            # so buffer all data with same timestamp, and send when timestamp changes
            ts = float(data[0])
            if self.__last_ts != ts:  # new frame, send buffered one
                # if we have at least one frame buffered, send it
                if self.__frame:
                    self.send_can_messages(ts)
                self.__frame += 1
            self.__last_ts = ts
            param = data[1]
            val = float(data[2])
            self.debug('%s %s %s %s %s', self.__frame,
                       self.subscribe_topic, ts, param, val)
            # any params not seen in this frame will keep value from prev frame
            self.__params[param] = val
            #direct MQTT boolean value to CAN message (for alerts, etc..)
            if self.subscribe_message and param == self.subscribe_message:
                self.send_can_message(ts,self.message_name,self.message_id,
                {self.message_param: self.message_active_value if val else self.message_inactive_value})
        except Exception as e:
            self.warning(e, exc_info=True)

    def send_can_message(self, ts, name, canid, params):
        info = {'ts': ts, 'id': canid, 'name': name, name: params}
        self.debug(info)
        # dispatch info with params and empty CAN Message with proper IDs.
        # DBCEncoder will generate CAN Message data from info
        self.dispatch(info, Message(arbitration_id=canid,
                        is_extended_id=(self.extended_id or canid > 0x7ff)))

    def send_can_messages(self, ts):
        msgs = {}
        # build list of messages from params we subscribe to
        for k, v in self.__params.items():
            if k in self.subscribe_map:
                msgs.setdefault(self.subscribe_map[k], {})[k] = v
        # build list of CAN IDs for messages
        for name, params in msgs.items():
            canid = self.id_map[name]
            self.send_can_message(ts, name, canid, params)
            
    def effect(self, info, msg, **kwargs):
        # filter to selected messages and publish over MQTT
        # messages must be decoded by DBCDecoder
        if not self.rate_limit or (time.time()-self.__last_send > self.rate_limit):
            if self.__client and self.topic and ('name' in info and info['name'] in info) \
                    and ((not self.publish) or info['name'] in self.publish):
                for p, v in info[info['name']].items():
                    if p.startswith('spn'):
                        p = p.split('_')[0]
                    self.debug('%s %s %f %s %f', self.topic,
                               info['ts'], p, float(v))
                    self.__client.publish(
                        self.topic, '%f,%s,%f' % (info['ts'], p, float(v)))
                    self.__last_send = time.time()
        else:
            self.debug('rate limit dropped %s', info)
        return info, None  # we're a sink so do not dispatch

class MQTTLogger(Plugin):
    '''logs MQTT messages'''
    client = None
    host = 'localhost'
    port = 1883
    subscribe = None

    def main(self):
        while True:
            self.__client = mqtt.Client()
            try:
                self.__client.connect(self.host, self.port)
                self.info('connected to %s:%s', self.host, self.port)
                self.info('publishing %s', self.publish)
                break
            except Exception as e:
                self.warning(e, exc_info=True)
            time.sleep(1)
        if self.subscribe:
            self.__last_ts = None
            self.__ticks = 0
            self.__params = {}
            self.__client.on_message = self.on_message
            try:
                self.__client.subscribe(self.subscribe)
                self.info('subscribed to %s', self.subscribe)
                self.__log = open(self.subscribe+'.csv', 'w')
                self.__client.loop_forever()
            except Exception as e:
                self.warning(e, exc_info=True)

    def disconnect(self):
        try:
            self.__client.disconnect()
            self.__log.close()
        except:
            pass

    def stop(self, *args, **kwargs):
        # if we are multiprocessing, we have to call_method to disconnect in our process
        self.call_method('disconnect')
        Plugin.stop(self, *args, **kwargs)

    def on_message(self, client, userdata, message):
        try:
            topic, data = message.topic, message.payload.decode().split(',')
            ts = float(data[0])
            param = data[1]
            val = float(data[2])
            self.debug('%s %s %s', ts, param, val)
            self.__params['ts'] = ts
            self.__params[param] = val
            if self.__last_ts and self.__last_ts != ts:
                self.__ticks += 1
                if self.__ticks > 1:
                    self.write_params(ts)
            self.__last_ts = ts
        except Exception as e:
            self.warning(e, exc_info=True)

    def write_params(self, ts):
        self.debug('%s %s', self.__ticks, self.__params)
        if not self.__csv:
            self.__csv = csv.DictWriter(self.__log, self.__params.keys())
            self.__csv.writeheader()
        self.__csv.writerow(self.__params)
        self.__log.flush()
