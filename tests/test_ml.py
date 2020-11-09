import pytest

from aura.analyzers.python import ml


@pytest.mark.parametrize("token,expected", (
    ("helloWorld", ["hello", "World"]),
    ("get_match", ["get", "match"]),
    ("find666", ["find", "666"])
))
def test_token_split(token, expected):
    val = ml.split_token(token)
    assert val == expected
