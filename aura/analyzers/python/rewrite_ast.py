import base64
from .visitor import Visitor
from .convert_ast import ASTVisitor
from .nodes import *


class ASTRewrite(Visitor):
    """
    Visitor to transform the AST tree for deobfuscation purposes
    """
    def __init__(self, **kwargs):
        self.__mutations = (
            self.binop,
            self.resolve_variable,
            self.string_slice,
            self.decode_inline_base64
        )
        super().__init__(**kwargs)

    def load_tree(self, source):
        if self.tree is None:
            cached = ASTVisitor.from_cache(source=source, metadata=self.metadata)
            self.tree = cached.tree
            del cached

    def _visit_node(self, context):
        for mutation in self.__mutations:
            if mutation(context):
                return

    def binop(self, context):
        """
        Transformation for performing some simple binary ops
        E.g.:  + - / * etc... when left and right operands are supported constants
        """
        node = context.node

        if not isinstance(node, BinOp):
            return

        if node.op == 'add':
            if isinstance(node.left, String) and isinstance(node.right, String):
                new_str = node.right.value + node.left.value
                new_node = String(value=new_str)
                # new_node._original = context.node
                context.replace(new_node)
                return True
        # TODO cover other cases

    def string_slice(self, context):
        if not isinstance(context.node, dict):
            return
        elif context.node.get('_type') != 'Subscript':
            return
        elif not isinstance(context.node['value'], String):
            return

        lower = context.node['slice'].get('lower')
        if lower:
            lower = lower.value
        else:
            lower = 0

        upper = context.node['slice'].get('upper')
        if upper:
            upper = upper.value
        else:
            upper = len(context.node['value'].value)

        step = context.node['slice'].get('step')
        if step:
            step = step.value
        else:
            step = 1

        sliced_str = context.node['value'].value[lower:upper:step]
        new_node = String(value=sliced_str)
        context.replace(new_node)

    def resolve_variable(self, context):
        """
        Transformation for constant propagation
        """
        if type(context.node) == Attribute:  # TODO: transition inside the visit_node of Attr
            # Replace attributes such as x.decode("base64") to "test".decode("base64")

            source = context.node.source
            try:
                target = context.stack[source]
            except (TypeError, KeyError):
                return

            if target:
                context.node._original = context.node.source
                if isinstance(target, Var):
                    context.node.source = target.value
                else:
                    context.node.source = target

    def decode_inline_base64(self, context):
        node = context.node
        if not isinstance(node, Call):
            return
        #check if it is calling <str>.decode(something)
        elif not (isinstance(node.func, Attribute) and isinstance(node.func.source, String) and node.func.attr == 'decode'):
            return
        #check if the decode attribute is base64
        elif not (len(node.args) == 1 and isinstance(node.args[0], (String, str))):
            return

        codec = str(node.args[0])
        if codec != 'base64':
            return

        try:
            decoded = base64.b64decode(str(node.func.source)).decode()
            new_node = String(value=decoded)
            new_node.line_no = context.node.line_no
            context.replace(new_node)
        except Exception:
            raise
        return

    def resolve_class(self, context):
        node = context.node
        if not isinstance(node, Attribute):
            return
        elif not (isinstance(node.func, str) and node.func == 'self'):
            # TODO
            return
