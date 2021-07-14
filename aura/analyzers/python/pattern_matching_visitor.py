import os
from typing import cast

from ..detections import Detection
from .nodes import Context, Import
from .visitor import Visitor
from ...pattern_matching import ASTPattern
from ...cache import ASTPatternCache
from ... import config


LOGGER = config.get_logger(__name__)


class ASTPatternMatcherVisitor(Visitor):
    def __init__(self, *, location):
        super().__init__(location=location)
        self.convergence = None
        self._signatures = ASTPatternCache.proxy()
        self._report_modules = (
                config.CFG["aura"].get("always_report_module_imports", True) or  # type: ignore[index]
                os.environ.get("AURA_ALL_MODULE_IMPORTS", False) or
                self.location.metadata.get("report_imports")
        )  # type: ignore[index]

    def _visit_node(self, context: Context):
        for signature in self._signatures:  # type: ASTPattern
            if signature.match(context.node):
                signature.apply(context)

        if self._report_modules and type(context.node) == Import:
            self.gen_module_import(context)

    def gen_module_import(self, context: Context):
        node = cast(Import, context.node)

        for module_name in node.get_modules():
            hit = Detection(
                detection_type="ModuleImport",
                message=f"Module '{module_name}' import in a source code",
                extra={
                    "name": module_name
                },
                node=node,
                signature=f"module_import#{module_name}#{context.signature}",
                tags=node.tags
            )
            self.hits.append(hit)
