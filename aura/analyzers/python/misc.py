import re
import math

from .nodes import *
from .. import base
from ..rules import Rule
from ...utils import Analyzer
from ... import config


HARDCODED_TMP = ['/tmp', '/var/tmp', '/dev/shm']
REQUESTS_REGEX = re.compile(r'requests￿\.(get|post|put|delete|patch|head|options)')
ENTROPY_THRESHOLD = float(config.CFG.get('aura', 'shanon_entropy', fallback=0.0))


@Analyzer.ID('misc')
@Analyzer.description("Various checks mostly for best-practices")
class MiscAnalyzer(base.NodeAnalyzerV2):
    def node_String(self, context):
        val = str(context.node)
        entropy = calculate_entropy(val)

        if ENTROPY_THRESHOLD > 0 and entropy >= ENTROPY_THRESHOLD:
            hit = Rule(
                message = "A string with high shanon entropy was found",
                extra = {'type': 'high_entropy_string', 'entropy': entropy, 'string': val},
                signature = f"misc#high_entropy#{context.visitor.path}#{context.node.line_no}"
            )
            hit.line_no = context.node.line_no
            yield hit

        for t in HARDCODED_TMP:
            if val.startswith(t):
                hit = Rule(
                    message = "Hardcoded tmp in the source code",
                    extra = {
                        'type': 'hardcoded_tmp',
                        'tmp_folder': val,
                    },
                    signature = f"misc#hardcoded_tmp#{context.visitor.path}#{context.node.line_no}"
                )
                hit.line_no = context.node.line_no
                yield hit
                return

        if val == '0.0.0.0':
            hit = Rule(
                message = "Possible binding to all interfaces",
                extra = {'type': 'bind_all_interfaces'},
                signature = f"misc#bind_all#{context.visitor.path}#{context.node.line_no}"
            )
            hit.line_no = context.node.line_no
            yield hit

    def node_Call(self, context):
        f_name = context.node.full_name
        if not isinstance(f_name, str):
            return


        if REQUESTS_REGEX.match(f_name):
            try:
                signature = context.node.apply_signature(
                    aura_capture_args='args',
                    aura_capture_kwargs='kwargs',
                    verify=True
                )
            except TypeError:
                return

            if signature.arguments['verify'] is False:
                hit = Rule(
                    message = 'SSL/TLS verification disabled when doing a request',
                    extra = {'type': 'request_disabled_verify'},
                    signature = f'misc#disabled_verify#{context.visitor.path}#{context.node.line_no}'
                )
                hit.line_no = context.node.line_no
                yield hit

        elif f_name == 'flask.Flask.run':
            try:
                signature = context.node.apply_signature(
                    aura_capture_args = 'args',
                    aura_capture_kwargs = 'kwargs',
                    debug = None,
                )
            except TypeError:
                return

            if signature.arguments.get('debug', False) is True:
                hit = Rule(
                    message = 'Debug mode enabled in Flask',
                    extra = {'type': 'flask_debug'},
                    signature = f'misc#flask_debug#{context.visitor.path}#{context.node.line_no}'
                )
                hit.line_no = context.node.line_no
                yield hit


def calculate_entropy(data:str, iterator=lambda :range(255)) -> float:
    """
    Calculate shanon entropy of the string
    """
    if not data:
        return 0

    entropy = 0
    for x in iterator():
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)

    return entropy
