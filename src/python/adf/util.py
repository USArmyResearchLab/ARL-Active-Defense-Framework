#!/usr/bin/env python3

from adf import *
import importlib
import os

# Try to import setuptools' pkg_resources module for entry points
try:
    import pkg_resources
except ModuleNotFoundError:
    pkg_resources = None

#
# Utility functions
#


def import_package(pkg, get_class=False):
    '''the importomatic 
    imports a package, if get_class is set will take 'path.class', import path, and return class 
    else will import path and place the exported modules in the global namespace
    returns module and attribute list'''
    if get_class:  # strip off class name
        pkg, cls = pkg.rsplit('.',1)
    else:
        cls = None
    module = None
    # check if plugin is part of an external entry point
    if pkg_resources:
        if epp := list(pkg_resources.iter_entry_points("arl_adf_plugins", pkg)):
            module = epp[0].load()
    # otherwise, check a default location and try an import
    if not module:
        if not pkg:
            pkg = "adf"
        module = importlib.import_module(pkg)
    if get_class:
        return getattr(module, cls)
    try:
        attrlist = module.__all__
    except AttributeError:
        attrlist = dir(module)
    except Exception as e:
        return e
    return module, attrlist

def parse_list(v):
    '''parses csv to stripped strings'''
    return [p.strip() for p in v.split(',')]


def parse_int(v):
    '''parses csv to list of integers'''
    return [int(p) for p in parse_list(v)]


def parse_env(v):
    '''replace environment vars in values'''
    v = v.split(os.path.sep)  # split paths to find embedded env vars
    # build line as path with substituted vars or literal parts
    v = os.path.sep.join(os.environ.get(
        e[1:], '') if e.startswith('$') else e for e in v)
    return v


def parse_line(l):
    '''remove comments and split line into words
    detects largest quoted section and preserves contained whitespace'''
    start = end = None
    l = l.strip().split('#')[0].split()  # remove comments and split line
    # detect quoted sections and join with whitespace into one arg
    start = [i for i, w in enumerate(l) if w.startswith('"')]
    if start:
        start = start[0]  # get leftmost start quote position
        end = [i for i, w in enumerate(l[start:]) if w.endswith('"')]
        if end:
            end = start+end[-1]+1  # get rightmost end quote pos
            # return line before quote start, quoted with quotes removed, line after
            return l[:start] + [' '.join(l[start:end]).replace('"', '')] + l[end:]
    return l  # no quotes in line


def parse_kvs(kvs, f=None, parse_value=None):
    '''parse for key=value
    f: limit to set of keys in f
    parse_value:
        If None (default), will attempt to parse ints, lists of ints, and environment vars
        If True, will also split strings at commas and always return list
        If False, will not split or parse value'''
    d = {}
    if kvs:
        for kv in kvs:
            try:
                k, v = kv.split('=', 1)
                k, v = k.strip(), v.strip()
                if parse_value is not False:
                    v = parse_env(v)  # will populate $env vars in values
                    try:
                        v = parse_int(v)  # handle (list of) ints
                    except:
                        pass  # not integers
                    if parse_value is True:  # values will always be a list of strings or ints
                        try:
                            v = parse_list(v)  # turn all strings into lists
                        except:
                            pass  # not a string, already parsed
                    elif type(v) is list and len(v) == 1:
                        v = v[0]  # don't leave single item lists as lists
            except:
                k, v = kv.strip(), None  # did not parse as k=v, treat as bare key
            if f and (k not in f):
                continue  # filter by key if filter given
            d[k] = v
    return d


def dk_get(d, k, default=None):
    '''gets dotted key k from dict d
    example: if k is 'a.b.c' will return d['a']['b']['c']'''
    kk = k.split('.')
    while kk:
        k = kk.pop(0)
        try:
            d = d[k]
        except:
            return default
    return d


def dk_update(d, k, v):
    '''sets dotted key k in dict d to value v
    example: if k is 'a.b.c', will create/update d['a']['b']['c']
    updates d in place and returns d'''
    kk = k.split('.')
    dd = d
    while kk:
        k = kk.pop(0)
        if kk:  # if key parts remain
            # if next is not dict, make it a dict
            if not isinstance(dd.get(k), dict):
                dd[k] = dict()
            dd = dd[k]  # get dict under this key
    dd[k] = v  # at last key, drop value here
    return d


def dk_del(d, k):
    '''deletes dotted key k from dict d
    example: if k is 'a.b.c' will del d['a']['b']['c']
    returns if delete was successful'''
    kk = k.split('.')
    try:
        while kk:
            k = kk.pop(0)
            if not kk:  # k is last key, so del k from this level
                del d[k]
                return True
            d = d[k]
    except:
        return False
