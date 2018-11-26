# coding=utf-8
import sys
import os
import os.path

try:
    import simplejson as json
except ImportError:
    import json

import click


CFG_PATH = os.environ.get('AURA_CFG', 'signatures.json')
CFG_PATH = os.path.join(os.getcwd(), CFG_PATH)


try:
    with open(CFG_PATH, 'r') as fd:
        CFG = json.loads(fd.read())
except FileNotFoundError:
    click.secho('Configuration file with signatures could not be found!', fg='red')
    click.secho("Make sure to have either 'signatures.json' in your cwd or set it's path as AURA_CFG env variable.")
    sys.exit(1)
