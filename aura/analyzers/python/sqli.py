import re

from .. import base
from ..detections import Detection
from .nodes import *
from ...utils import Analyzer


SQL_REGEX = re.compile(
    r"^(SELECT\s.*FROM|"
    r"DELETE\s.*FROM|"
    r"INSERT\s+INTO\s.*VALUES\s|"
    r"UPDATE\s.*SET\s).*",
    flags=re.I,
)


def is_sql(data):
    return bool(SQL_REGEX.match(data))


@Analyzer.ID("sql_injection")
class SQLi(base.NodeAnalyzerV2):
    """Finds possible SQL injections via direct string manipulations"""

    def node_BinOp(self, context):
        """
        Query:
        "SELECT * FROM users WHERE id = %d" % uid
        AST:
        BinOp(op='mod', left='uid', right=String(value='SELECT * FROM users WHERE id = %d'))

        and

        "SELECT * FROM users where id = " + uid
        AST:
        BinOp(op='add', left='uid', right=String(value='SELECT * FROM users where id = '))
        """
        n = context.node
        yield from []
        if not (isinstance(n.right, String) and n.op in ("mod", "add")):
            return

        if not is_sql(n.right.value):
            return

        yield Detection(
            detection_type="SQLInjection",
            score=50,
            message="Possible SQL injection found",
            signature=f"vuln#{context.signature}",
            node = context.node,
            line_no=context.node.line_no,
        )

    def node_Call(self, context):
        """
        Query:
        "SELECT * FROM users WHERE id = {}".format(uid)
        AST:
        Call(Attribute(String(value='SELECT * FROM users WHERE id = {}') . 'format'))(*['uid'])
        """
        n = context.node
        if not (
            isinstance(n.func, Attribute)
            and isinstance(n.func.source, String)
            and n.func.attr == "format"
        ):
            return
        if not is_sql(n.func.source.value):
            return

        yield Detection(
            detection_type="SQLInjection",
            score=50,
            message="Possible SQL injection found",
            signature=f"vuln#sqli#{context.signature}",
            node = context.node,
            line_no=context.node.line_no,
        )
