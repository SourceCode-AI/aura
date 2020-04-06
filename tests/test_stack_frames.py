import pytest

from aura.stack import Stack


def test_stack_operations():
    s = Stack()
    with pytest.raises(ValueError):
        s.pop()

    with pytest.raises(KeyError):
        _ = s['g']

    s['g'] = 'global_value'
    assert s['g'] == 'global_value'
    s.push()
    assert s['g'] == 'global_value'
    assert s.frame.previous is not None
    assert s.frame.previous is s.bottom
    assert s.frame is not s.bottom
    with pytest.raises(KeyError):
        _ = s['x']

    s['x'] = 'local_value'
    assert s['x'] == 'local_value'
    s.pop()
    assert s.frame.previous is None
    assert s.bottom is s.frame
    with pytest.raises(KeyError):
        _ = s['x']


def test_stack_copy():
    s1 = Stack()
    s1['var'] = 'value1'
    assert s1['var'] == 'value1'

    s1.push()
    s1['another'] = 'value2'
    assert s1['var'] == 'value1'
    assert s1['another'] == 'value2'

    s2 = s1.copy()
    assert s1 is not s2
    assert set(s1.frame.variables) == set(s2.frame.variables)
    assert s2.frame is not s1.frame
    assert s2.bottom is not s1.bottom
    assert s2.frame is not s2.bottom
    assert s2['var'] == 'value1'
    assert s2['another'] == 'value2'

    s2['var'] = 'new_value'
    assert s2['var'] == 'new_value'
    assert s1['var'] == 'value1'
