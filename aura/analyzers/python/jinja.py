from .. import base
from .. import rules
from ...utils import Analyzer


class JinjaVulnerability(rules.Rule):
    pass


@Analyzer.ID('jinja')
@Analyzer.description("Analyze Jinja specific vulnerabilities such as XSS")
class JinjaAnalyzer(base.NodeAnalyzerV2):
    def node_Call(self, context):
        f_name = context.node.full_name

        if f_name != 'jinja2.Environment':
            return

        try:
            signature = context.node.apply_signature(
                aura_capture_args='args',
                aura_capture_kwargs='kwargs',
                autoescape=True
            )
        except TypeError:
            return

        if signature.arguments['autoescape'] is False:
            hit = JinjaVulnerability(
                message = "Detected jinja environment with autoescaping explicitly disabled",
                score = 100,
                line_no= context.node.line_no,
                signature = f"jinja#xss#{context.visitor.path}#{context.node.line_no}"
            )
            yield hit
