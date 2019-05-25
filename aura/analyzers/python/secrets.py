import re


from . nodes import *
from .. import base
from .. import rules
from ...utils import Analyzer


class LeakingSecret(rules.Rule):
    pass

SECRET_REGEX = re.compile(r'.*(pass(wd|word)?|pwd|token|secrete?).*')


@Analyzer.ID('secrets')
@Analyzer.description("Look for leaking secrets such as passwords or API tokens")
class SecretsAnalyzer(base.NodeAnalyzerV2):
    def node_Var(self, context):
        name = str(context.node.var_name)
        if not SECRET_REGEX.match(name):
            return
        elif not isinstance(context.node.value, (String, str)):
            return

        secret = str(context.node.value)

        yield from self._gen_hit(context, name, secret)

    def _gen_hit(self, context, name, secret, extra:dict = None):
        if extra is None:
            extra = {}

        hit = LeakingSecret(
            message = "Possible sensitive leaking secret",
            extra= {
                'name': name,
                'secret': secret
            },
            line_no = context.node.line_no,
            signature = f"leaking_secret#{context.visitor.path}#{context.node.line_no}"
        )
        hit.extra.update(extra)
        yield hit

    def node_Call(self, context):
        f_name = context.node.full_name

        if f_name in ('requests.auth.HTTPBasicAuth', 'requests.auth.HTTPDigestAuth'):
            try:
                signature = context.node.apply_signature(
                    'user',
                    'password',
                    aura_capture_args='args',
                    aura_capture_kwargs='kwargs'
                )
                print(signature)
            except TypeError:
                return

        yield from []

