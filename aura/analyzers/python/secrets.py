import re
from urllib.parse import urlparse, parse_qs

from . nodes import *
from .. import base
from .. import rules
from ...utils import Analyzer


class LeakingSecret(rules.Rule):
    pass


URL_REGEX = re.compile(r'^(https?|ftp)://.{5,}\?.{3,}')
SECRET_REGEX = re.compile(r'.*(pass(wd|word)?|pwd|token|secrete?).*')
TOKEN_FILTER_REGEX = re.compile(r'[a-z\d_\.-]{8,}', flags=re.IGNORECASE)


@Analyzer.ID('secrets')
@Analyzer.description("Look for leaking secrets such as passwords or API tokens")
class SecretsAnalyzer(base.NodeAnalyzerV2):
    def node_Var(self, context):
        name = str(context.node.var_name)

        if not SECRET_REGEX.match(name):
            return
        elif not isinstance(context.node.value, String):
            return

        secret = str(context.node.value)

        yield from self._gen_hit(context, name, secret, extra={'type': 'variable'})

    def _gen_hit(self, context, name, secret, **extra):
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

                if not isinstance(signature.args[0], (String, str)):
                    return
                elif not isinstance(signature.args[1], (String, str)):
                    return

                user = str(signature.args[0])
                passwd = str(signature.args[1])

                yield from self._gen_hit(context, user, passwd, extra={'type': 'call'})
            except TypeError:
                return

    def node_String(self, context):
        if not URL_REGEX.match(context.node.value):
            return

        parsed = urlparse(context.node.value)
        if not parsed.query:
            return

        qs = parse_qs(parsed.query)
        for k,v in qs.items():
            if not SECRET_REGEX.match(k):
                continue
            if len(v) == 1:
                v = v[0]
                if not TOKEN_FILTER_REGEX.match(v):
                    return

            yield from self._gen_hit(context, name=k, secret=v, type='url')

    def node_Compare(self, context):
        if not len(context.node.ops) == 1:
            return
        elif not context.node.ops[0]['_type'] == 'Eq':
            return

        if isinstance(context.node.left, dict) and context.node.left['_type'] == 'Name':
            var = context.node.left['id']
            if not isinstance(context.node.comparators[0], (str, String)):
                return

            value = str(context.node.comparators[0])
            if SECRET_REGEX.match(var):
                yield from self._gen_hit(context, name=var, secret=value)
