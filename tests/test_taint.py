from aura.analyzers.python.nodes import Taints


def test_taint_operations():
    u = Taints.UNKNOWN
    s = Taints.SAFE
    t = Taints.TAINTED
    # Test that the combinations of taints are correct
    assert (s + s) == Taints.SAFE
    assert (u + u) == Taints.UNKNOWN
    assert (t + t) == Taints.TAINTED
    assert (t + u) == Taints.TAINTED
    assert (u + t) == Taints.TAINTED
    assert (u + s) == Taints.UNKNOWN
    assert (s + u) == Taints.UNKNOWN
    assert (s + t) == Taints.TAINTED
    assert (t + s) == Taints.TAINTED

