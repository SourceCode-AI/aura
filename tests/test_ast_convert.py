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


def test_list_types():
    test_table = {
        'List': '[5, 7, 11]',
        'Set': '{5, 7, 11}',
        'Tuple': '(5, 7, 11)'
    }

    for t, d in test_table.items():
        raw = get_raw_ast(d)[0]
        #print(raw)
        assert isinstance(raw, dict)
        assert raw['_type'] == 'Expr'
        list_ast = raw['value']
        assert list_ast['_type'] == t
        ctx = create_context(list_ast)

        out = []
        replace = lambda x: out.extend(x)
        ctx.replace = replace
        convert_ast.VISITORS[t](ctx)
        assert out == list_ast['elts']


def test_string():
    raw = get_raw_ast('"Hello world"')[0]['value']
    assert isinstance(raw, dict)
    assert raw['_type'] == 'Str'
    ctx = create_context(raw)
    out = []
    ctx.replace = lambda x: out.append(x)
    convert_ast.VISITORS['Str'](ctx)
    assert len(out) == 1
    assert isinstance(out[0], nodes.String)
    assert out[0].value == 'Hello world'


def test_dict():
    raw = get_raw_ast('{"key": "value"}')[0]['value']
    assert isinstance(raw, dict)
    assert raw['_type'] == 'Dict'
    out = []
    ctx = create_context(raw)
    ctx.replace = lambda x: out.append(x)
    convert_ast.VISITORS['Dict'](ctx)
    assert len(out) == 1
    assert isinstance(out[0], nodes.Dictionary)
