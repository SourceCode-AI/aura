import inspect

from aura.analyzers.python import convert_ast
from aura.analyzers.python import nodes, visitor


def create_context(data):
    ctx = nodes.Context(
        node = data,
        parent = None,
        visitor = None,
    )
    return ctx


def get_raw_ast(source_code):
    out = visitor.get_ast_tree('-', bytes(source_code, 'utf-8'))
    return out['ast_tree']['body']


def test_string(fixtures):
    raw = fixtures.get_raw_ast('"Hello world"')[0]['value']
    assert type(raw) == dict
    assert raw['_type'] == 'Str'
    ctx = create_context(raw)
    out = []
    ctx.replace = lambda x: out.append(x)
    convert_ast.VISITORS['Str'](ctx)
    assert len(out) == 1
    assert isinstance(out[0], nodes.String)
    assert out[0].value == 'Hello world'


def test_dict(fixtures):
    raw = fixtures.get_raw_ast('{"key": "value"}')[0]['value']
    assert isinstance(raw, dict)
    assert raw['_type'] == 'Dict'
    out = []
    ctx = create_context(raw)
    ctx.replace = lambda x: out.append(x)
    convert_ast.VISITORS['Dict'](ctx)
    assert len(out) == 1
    assert isinstance(out[0], nodes.Dictionary)


def test_function_parameters():
    arg_node = nodes.Arguments(
        args = ['a', 'b', 'c'],
        vararg = 'arg_collector',
        kwonlyargs = ['ka', 'kb', 'kc'],
        kw_defaults= ['kdc'],
        defaults = ['dc'],
        kwarg = 'kwarg_collector'
    )

    params = arg_node.to_parameters()
    is_empty = lambda arg: bool(arg.default == inspect.Parameter.empty)

    assert len(params) == 8
    assert params[0].name == 'a'
    assert is_empty(params[0])
    assert params[1].name == 'b'
    assert is_empty(params[1])
    assert params[2].name == 'c'
    assert not is_empty(params[2])
    assert params[2].default == 'dc'
    assert params[3].name == 'arg_collector'
    assert is_empty(params[3])
    assert params[4].name == 'ka'
    assert is_empty(params[4])
    assert params[5].name == 'kb'
    assert is_empty(params[5])
    assert params[6].name == 'kc'
    assert not is_empty(params[6])
    assert params[6].default == 'kdc'
    assert params[7].name == 'kwarg_collector'
    assert is_empty(params[7])

    call_node = nodes.Call(
        func = 'yolo',
        args = ['av', 'bv', 'cv'],
        kwargs = {'ka': 'kav', 'kb': 'kbv'}
    )
    signature = arg_node.to_signature()
    result = call_node.bind(signature) # type: inspect.BoundArguments
    result.apply_defaults()
    assert result.signature == signature
    assert result.args[0] == 'av'
    assert result.args[1] == 'bv'
    assert result.args[2] == 'cv'
    assert result.kwargs['ka'] == 'kav'
    assert result.kwargs['kb'] == 'kbv'
    assert result.kwargs['kc'] == 'kdc'
