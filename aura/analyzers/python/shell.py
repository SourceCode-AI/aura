import subprocess

from .nodes import *
from ..rules import Rule
from ..base import NodeAnalyzerV2
from ...utils import Analyzer


SUBPROCESS = (
    'subprocess.run',
    'subprocess.Popen',
    'subprocess.call',
    'subprocess.check_call',
    'subprocess.check_output'
)

SUBPROCESS_SIG = inspect.signature(subprocess.Popen)  # TODO: this could be hardcoded?


class ShellInjection(Rule):
    pass


@Analyzer.ID('shell_injection')
@Analyzer.description("Analyze the AST tree for potential shell injection vulnerabilities")
class ShellInjection(NodeAnalyzerV2):
    def node_Call(self, context):
        f_name = context.node.full_name
        if f_name in SUBPROCESS:
            yield from self.__check_subprocess(context=context)

    def __check_subprocess(self, context):
        try:
            params = context.node.bind(SUBPROCESS_SIG)  # type: inspect.BoundArguments
            if params.kwargs.get('shell', None) == 'True':
                yield ShellInjection(
                    score = 5,
                    message = "Possible shell injection found, using `shell=True` is dangerous if arguments are not escaped",
                    line_no = context.node.line_no,
                    signature = f"shelli#{context.node.full_name}#{context.visitor.path}#{context.node.line_no}",
                )
        except TypeError:
            pass
