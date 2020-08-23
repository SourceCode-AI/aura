from ..detections import Detection
from .nodes import Context, Import
from .visitor import Visitor
from ...pattern_matching import ASTPattern
from ... import config


LOGGER = config.get_logger(__name__)


class ASTPatternMatcherVisitor(Visitor):
    def __init__(self, *, location):
        super().__init__(location=location)
        self.convergence = None
        self._signatures = config.get_ast_patterns()

    def _visit_node(self, context: Context):
        for signature in self._signatures:  # type: ASTPattern
            if signature.match(context.node):
                signature.apply(context)

        if type(context.node) == Import:  # TODO: add configuration option to enable/disable this
            self.gen_module_import(context)

    def gen_module_import(self, context: Context):
        for module_name in context.node.get_modules():
            hit = Detection(
                detection_type="ModuleImport",
                message=f"Module '{module_name}' import in a source code",
                extra={
                    "name": module_name
                },
                node=context.node,
                signature=f"module_import#{module_name}#{context.visitor.normalized_path}",
                tags=context.node.tags
            )
            self.hits.append(hit)
