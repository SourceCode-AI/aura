from requests import get as fetch
import subprocess
import urllib2
from importlib import import_module as super_import
import os

import donald_trump


def network():
    fetch("https://blah.com")


def imports():
    x = super_import('importlib.import_module-test')
    __import__('__import__-test')


def cmds():
    os.system("os.system-test")
    subprocess.Popen(['subprocess.Popen-test'])
    subprocess.check_call(['subprocess.check_call-test'])
    subprocess.check_output(['subprocess.check_output-test'])
