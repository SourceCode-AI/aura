import pytest
from collections import deque

from aura.pattern_matching import ASTPattern
from aura.analyzers.detections import Detection
from aura.stack import CallGraph
from aura.analyzers.python.nodes import ASTNode, Context, Taints


class PatternMatchingVisitor:
    def __init__(self, pattern: ASTPattern):
        self.p = pattern
        self.q = deque()
        self.call_graph = CallGraph()
        self.hits = []
        self.normalized_path = "pytest_src"
        self.path = self.normalized_path

    def traverse(self, initial_node):
        self.q.clear()
        self.q.append(Context(node=initial_node, parent=None, visitor=self))

        while len(self.q):
            ctx = self.q.popleft()
            if self.p.match(ctx.node):
                self.p.apply(ctx)
                return ctx.node

            if isinstance(ctx.node, ASTNode):
                ctx.node._visit_node(ctx)

        return False

    def push(self, ctx):
        self.q.append(ctx)


CASES = (
    # Tuple: (Source code, Pattern, should_match)
    (
        "flask.request.get_json()",
        "flask.request.get_json()",
        True
    ),
    (
        "flask.request.get_json()",
        "flask.request.get_json",
        True
    ),
    (
        "flask.request.get_json",
        "flask.request.get_json()",
        False
    ),
    (
        'requests.post("http://example.com/", verify=False)',
        "requests.post(..., verify=False)",
        True
    ),
    (
        'requests.post("http://example.com/")',
        "requests.post(...)",
        True
    ),
    (
        'requests.post()',
        "requests.post(...)",
        True
    ),
    (
        "eval(requests.get('http://example.com'))",
        "requests.get(...)",
        True
    ),
    (
        'requests.post("http://example.com/")',
        "requests.post()",
        False
    ),
    (
        'requests.post("http://example.com/", verify=True)',
        "requests.post(..., verify=False)",
        False
    ),
    (
        'requests.post("http://example.com/", verify=True)',
        "requests.post(...)",
        True
    ),
    (
        "flask.request.headers",
        "flask.request.headers",
        True
    ),
    (
        'flask.request.headers["User-Agent"]',
        "flask.request.headers",
        True
    ),
    (
        'flask.request',
        "flask.request.headers",
        False
    ),
    (
        'flask.request.headers.something',
        "flask.request.headers",
        True
    ),
    (
        "import requests",
        "import requests",
        True
    ),
    (
        "import requests2",
        "import requests",
        False
    ),
    (
        "import requests.get",
        "import requests.get",
        True
    ),
    (
        "import requests.get",
        "import requests",
        True
    ),
    (
        "import requests",
        "import requests.get",
        False
    ),
    (
        "from requests import get",
        "import requests.get",
        True
    ),
    (
        "from requests import post",
        "import requests.get",
        False
    ),
    (
        "from requests.get import something",
        "import requests.get",
        True
    ),
    (
        "subprocess.check_call(venv_cmd)",
        "subprocess.check_call(..., shell=True)",
        False
    ),
)


@pytest.mark.parametrize("src,pattern,should_match", CASES)
def test_patterns(src, pattern, should_match):
    signature = {
        "pattern": pattern,
        "taint": {
            "level": "tainted"
        }
    }
    compiled_src = ASTPattern._compile_src(src)
    p = ASTPattern(signature=signature)

    v = PatternMatchingVisitor(pattern=p)
    result = v.traverse(compiled_src)
    assert bool(result) is should_match


def test_matching_triggers():
    src = """
    import flask
    app = flask.Flask()
    app.run(debug=True)
    """
    sig = {
        "pattern": "flask.Flask.run(..., debug=True)",
        "detection": {
            "type": "CustomDetection",
            "message": "detection_message",
            "score": 666
        },
        "tags": ["detection_tag"],
        "taint": "tainted"
    }

    compiled_src = ASTPattern._compile_src(src)
    p = ASTPattern(signature=sig)
    v = PatternMatchingVisitor(pattern=p)

    result = v.traverse(compiled_src)
    assert result is not None
    assert len(v.hits) == 1, v.hits

    hit: Detection = v.hits[0]
    assert hit.detection_type == "CustomDetection"
    assert hit.score == 666
    assert "detection_tag" in hit.tags, hit.tags
    assert result._taint_class == Taints.TAINTED


def test_any_of():
    src = "eval(print('Hello world'))"
    sig = {
        "pattern": [
            "exec(...)",
            "something",
            "print(...)",
            "x"
        ],
        "taint": "tainted"
    }

    compiled_src = ASTPattern._compile_src(src)
    p = ASTPattern(sig)
    v = PatternMatchingVisitor(pattern=p)
    result = v.traverse(compiled_src)
    assert result is not None
    assert result.full_name == "print"
    assert result._taint_class == Taints.TAINTED


def disabled_test_decorator():  # TODO: add pattern matching for decorators
    src = """\
    app = flask.Flask()
    
    @app.route("/")
    def index():
        return "Hello world"
    """
    sig = {
        "pattern": """\
        @flask.Flask.route("/")
        def _(*args, **kwargs):
            ...
        """
    }
    compiled_src = ASTPattern._compile_src(src)
    p = ASTPattern(sig)
    v = PatternMatchingVisitor(pattern=p)
    result = v.traverse(compiled_src)
    assert result is not None
