"""
This goal of this file/module is to contain all possible AST expressions in Python 3.6
"""
from __future__ import print_function

import requests


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


def generate_powers(top=20, power=2):
    for x in range(1, top):
        yield x**power
