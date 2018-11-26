#-*- coding: utf-8 -*-

try:
    import simplejson as json
except ImportError:
    import json


def loads(data):
    return json.loads(data)


def load_path(pth):
    with open(pth, 'r') as fd:
        return loads(fd.read())
