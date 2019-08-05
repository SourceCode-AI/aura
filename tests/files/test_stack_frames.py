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
