import os
import dis
import pickle
from tempfile import mktemp as m

import requests
from ctypes import *

listen_server = lambda x: None
listen_server('0.0.0.0')

if False:
    with open('/tmp/race_condition') as fd:
        fd.write('Hello world')


temp_file = m()


requests.get("https://example.com", verify=False)

windll.kernel32.VirtualAlloc("Pretend there are valid arguments")

class Pickploit:
    def __reduce__(self):
        cmd = "ls -lah /"
        return (os.system, (cmd,))


obj = Pickploit()
dumped = pickle.dumps(obj)
print(dis.dis(dumped))
pickle.loads(dumped)

os.system("echo Hello world")
