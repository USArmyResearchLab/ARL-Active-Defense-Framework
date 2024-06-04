#!/usr/bin/env python3

# python dependencies all modules will need
import sys
import os
import time
import socket
import struct
import signal
import threading
import logging
import queue
import pickle
import json
import importlib

#select MP (multiprocessing) mode
global ADF_MP
if os.getenv('ADF_MP'): 
    ADF_MP=True
    import multiprocessing as mp
else: 
    ADF_MP=False
    import multiprocessing.dummy as mp

#modules we provide to the global namespace
#these have to be in a certain order as they all do
#from adf import *
#which will skip the importer to prevent a circular import
#so, put dependencies first, in other words, don't PEP 8 this file!

#util first as everything uses it
from .util import *

#event class next, needed by plugin and framework
from .event import Event

#once we have util and event we can import framework
from .framework import Framework

#plugin base class next
from .plugin import Plugin

#event handlers now that we have plugin
from .event import Channel, Listener, Sender, Migrate

#interface classes
from .interface import Interface

#these may not import if deps are unavailable
try: from .interface import Tap
except: pass
try: from .interface import Pcap
except: pass
try: from .interface import NFQueue
except: pass
