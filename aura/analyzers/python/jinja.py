from __future__ import annotations

from pathlib import Path
from functools import partial
from dataclasses import dataclass

from jinja2 import Environment
from jinja2 import nodes as jnodes

from .visitor import Visitor
from .. import base
from ..detections import Detection
from .nodes import Context, Taints, ASTNode, String
from ...utils import Analyzer
from ... import config


logger = config.get_logger(__name__)


class JinjaVulnerability(Detection):
    pass


@Analyzer.ID("jinja")
class JinjaAnalyzer(base.NodeAnalyzerV2):
    """Analyze Jinja specific vulnerabilities such as XSS"""

    def node_Call(self, context):
        yield from self.__analyze_jinja_template(context)
        f_name = context.node.cached_full_name

        if f_name != "jinja2.Environment":
            return

        try:
            signature = context.node.apply_signature(
                aura_capture_args="args", aura_capture_kwargs="kwargs", autoescape=True
            )
        except TypeError:
            return

        if signature.arguments.get("autoescape", True) is False:
            hit = JinjaVulnerability(
                message="Detected jinja environment with autoescaping explicitly disabled",
                score=100,
                line_no=context.node.line_no,
                signature=f"jinja#xss#{context.visitor.normalized_path}#{context.node.line_no}",
            )
            yield hit

    def __analyze_jinja_template(self, context):
        f_name = context.node.cached_full_name
        yield from []

        if f_name != "flask.render_template":
            return

        taints = {}

        # Extract taints of the arguments
        for name, kw in context.node.kwargs.items():
            if not isinstance(kw, ASTNode):
                continue

            taints[name] = kw._taint_class

        if len(context.node.args) == 0 or type(context.node.args[0]) not in (String, str):
            logger.warn(f"Unable to determine jinja template location for template located in '{context.visitor.normalized_path}'#{context.node.line_no}")
            return

        tpl_name = str(context.node.args[0])

        v = JinjaTemplateVisitor.from_template(
            context=context, template_name=tpl_name, taints=taints
        )
        if v is None:
            return
        elif not v.traversed:
            v.traverse()

        yield from v.hits


@dataclass
class NodeWrapper(ASTNode):
    jinja_node: jnodes.Node

    def __repr__(self):
        return f"NodeWrapper({repr(self.jinja_node)}, taint={self._taint_class})"

    def __getattr__(self, item):  # TODO: proxy other methods?
        return getattr(self.jinja_node, item)

    def _visit_node(self, context):
        try:
            for name, node in self.jinja_node.iter_fields():
                context.visit_child(
                    node=node,
                    replace=partial(
                        self.__replace_field, attr=name, visitor=context.visitor
                    ),
                )
        except AttributeError:
            pass

    def __replace_field(self, value, attr, visitor):
        setattr(self.jinja_node, attr, value)
        visitor.modified = True

    def is_type(self, type) -> bool:
        return isinstance(self.jinja_node, type)


class JinjaTemplateVisitor(Visitor):
    @classmethod
    def from_template(cls, context, template_name, taints) -> JinjaTemplateVisitor:
        tpl_path = Path(context.visitor.normalized_path).parent / "templates" / template_name
        if not tpl_path.exists():
            logger.info(f"Could not find jinja template: '{template_name}'")
            return

        new_location = context.visitor.location.create_child(
            new_location=tpl_path
        )

        new_location.metadata.update({
            "template_path": tpl_path,
            "template_context": context.node.args[1:],
            "taints": taints,
        })

        v = cls(location=new_location)
        v.load_tree()
        return v

    def load_tree(self):
        if self.path:
            with self.path.open("r") as fd:
                raw_template = fd.read()

            self.tree = parse_jinja_template(raw_template)

    def _visit_node(self, context: Context):
        # Check if it is an AST node in the Jinja template
        if isinstance(context.node, jnodes.Node):
            new_node = NodeWrapper(jinja_node=context.node)
            context.replace(new_node)
            return

        # Now, process only wrapped nodes
        if not isinstance(context.node, NodeWrapper):
            return

        # Propagate the taint
        taints = [
            x[1]._taint_class
            for x in context.node.jinja_node.iter_fields()
            if isinstance(x[1], (ASTNode, NodeWrapper))
        ]
        if taints:
            context.node.add_taint(taint=max(taints), context=context)

        if context.node.is_type(jnodes.TemplateData):
            context.node.set_safe(context)
        elif context.node.is_type(jnodes.Filter):
            # Mark the '|safe' filter as sink

            if context.node.name in ("safe",) and "taint_sink" not in context.node.tags:
                context.node.tags.add("taint_sink")
                context.visitor.modified = True
        elif context.node.is_type(jnodes.Output):
            taints = []
            for n in context.node.nodes:
                if not isinstance(n, (ASTNode, NodeWrapper)):
                    continue

                taints.append(n._taint_class)

            if taints:
                context.node.add_taint(taint=max(taints), context=context)
        elif context.node.is_type(jnodes.Name):
            if context.node.name in self.location.metadata["taints"]:
                context.node.add_taint(
                    self.location.metadata["taints"][context.node.name], context
                )

        if (
            "taint_sink" in context.node.tags
            and context.node._taint_class == Taints.TAINTED
        ):
            lineno = context.node.jinja_node.lineno

            hit = JinjaVulnerability(
                message="Tainted input passed to sink in the jinja template",
                score=100,
                line_no=lineno,
                signature=f"jinja#taint_analysis#{str(self.location)}#{lineno}",
                location=self.location.location,
            )
            hit.tags |= {
                "jinja",
            }

            self.hits.append(hit)

        context.node._visit_node(context=context)


def parse_jinja_template(source_code):
    e = Environment()
    template = e.parse(source_code)
    return template.body


if __name__ == "__main__":
    import sys, pprint

    with open(sys.argv[1], "r") as fd:
        src = fd.read()

    t = parse_jinja_template(src)
    pprint.pprint(t)
