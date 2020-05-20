"""
This goal of this file/module is to contain all possible AST expressions in Python 3.6
"""
from __future__ import print_function

import requests, module1, module2
import base64 as b64
from dataclasses import dataclass, field
from . import submodule
from .. import ssmodule


@dataclass
class Klazz(object):
    description: str = field(default_factory=lambda : 'N/A')

    def __init__(self):
        super().__init__()

    @property
    def prop(self):
        return 'this_is_a_property'

    @classmethod
    def clsm(cls):
        return 'this_is_a_classmethod'

    def normal_method(self):
        return 'this_is_a_normal_object_method'


# block comment
def decorator(f):
    """
    Function documentation string
    """
    return f  # inline comment

@decorator
def test(a:int, b:str='b_arg', *, c='something', **kwargs) -> None:
    pass


x_set = {'a', 'b'}
x_dict = {'a': 'a_val', 'b': 'b_val'}
x_tuple = ('t1', 't2', 't3')
x_list = ['l1', 'l2', 'l3']

lama = lambda x: x.rstrip('.')


async def big_brother(*args, **kwargs):
    print("Hello world")

await big_brother(*x_list, **x_dict)

list_comprehension = [x for x in range(10)]
generator_comprehension = (x for x in range(10))

for x in []:
    if not x:
        break
    self_assign = x['val1'] if x['something'] else x['alternative']


def generate_powers(top=20, power=2):
    for x in range(1, top):
        yield x**power

def do_stuff() -> int: ...

try:
    do_stuff()
except Exception:
    pass
else:
    pass
finally:
    pass

try:
    do_stuff()
except (TypeError, KeyError) as exc:
    continue
