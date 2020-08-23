import codecs

from .visitor import Visitor
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
            self.inline_decode,
            self.rewrite_function_call,
            self.replace_string,
        )
        super().__init__(**kwargs)

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

        if node.op == "add":
            if type(node.left) == String and type(node.right) == String:
                new_str = str(node.right) + str(node.left)
                new_node = String(value=new_str)
                new_node.enrich_from_previous(node)
                context.replace(new_node)
                return True
            if type(node.left) == Number and type(node.right) == Number:
                new_node = Number(node.left.value + node.right.value)
                new_node.enrich_from_previous(node)
                context.replace(new_node)
                return True
        # TODO cover other cases

    def string_slice(self, context):
        if not type(context.node) == Subscript:
            return
        elif not type(context.node.value) in (String, str):
            return

        step = context.node.slice.get("step")
        if step is None:
            step = 1
        elif type(step) == Number:
            step = int(step)
        else:
            return

        value = str(context.node.value)
        lower = context.node.slice.get("lower")

        if lower is None:
            lower = 0 if step >= 0 else len(value)
        elif type(lower) == Number:
            lower = int(lower)
        else:
            return

        upper = context.node.slice.get("upper")
        if upper is None:
            upper = len(value) if step >= 0 else 0
        elif type(upper) == Number:
            upper = int(upper)
        else:
            return

        sliced_str = value[lower:upper:step]
        new_node = String(sliced_str)
        new_node.enrich_from_previous(context.node)
        context.replace(new_node)

    def resolve_variable(self, context: Context):
        """
        Transformation for constant propagation
        """
        if (
            type(context.node) == Attribute
        ):  # TODO: transition inside the visit_node of Attr
            # Replace attributes such as x.decode("base64") to "test".decode("base64")
            source = context.node.source

            try:
                target = context.stack[source]
            except (TypeError, KeyError):
                return

            if target.line_no == context.node.line_no:
                return

            if target:
                context.node._original = context.node.source
                if isinstance(target, Var):
                    context.node.source = target.value
                else:
                    context.node.source = target
        elif type(context.node) == Var and context.parent is not None and type(context.parent.node) == Call:
            # Replace the following:
            # c = 10; x(c) *~> c = 10; x(c=10) -> x(10)
            context.replace(context.node.value)


    def inline_decode(self, context):
        node = context.node
        if not type(node) == Call:
            return
        elif not (
            type(node.func) == Attribute
            and type(node.func.source) in (String, Bytes)
            and node.func.attr == "decode"
        ):
            return

        elif not all(type(x) in (String, str) for x in node.args):
            return

        if len(node.args) > 0:
            try:
                _ = codecs.getdecoder(str(node.args[0]))
            except LookupError:
                return

        args = list(map(str, node.args))

        decoded = codecs.decode(bytes(node.func.source), *args)
        if type(decoded) == str:
            new_node = String(decoded)
        else:
            new_node = Bytes(decoded)

        new_node.enrich_from_previous(node)
        context.replace(new_node)

    def rewrite_function_call(self, context):
        if not isinstance(context.node, Call):
            return

        if (
            context.node.full_name is None
            and isinstance(context.node.func, Import)
            and type(context.node._original) == str
        ):
            context.node._full_name = context.node.func.names[context.node._original]
            return True

        # Replace call to functions by their targets from defined variables, e.g.
        # x = open
        # x("test.txt") will be replaced to open("test.txt")
        try:
            if isinstance(context.node.func, Var):
                source = context.node._full_name
            else:
                source = context.node.func

            target = context.stack[source]
            if isinstance(target, Import):
                name = target.names[source]
            else:
                name = target.full_name
            if (
                type(name) == str
                and context.node._full_name != name
                and target.line_no != context.node.line_no
            ):
                context.node._full_name = name
                context.visitor.modified = True
                return True
        except (TypeError, KeyError, AttributeError):
            pass

        if type(context.node.func) == str and context.node.func in context.stack:
            try:
                context.node._original = context.node.func
                context.node.func = context.stack[context.node.func]
                context.visitor.modified = True
                return True
            except (TypeError, KeyError):
                pass

    def resolve_class(self, context):
        node = context.node
        if not isinstance(node, Attribute):
            return
        elif not (type(node.func) == str and node.func == "self"):
            # TODO
            return

    def replace_string(self, context):  # TODO: add test
        """
        Rewrites an expression `"some_string".replace("s", "a")`
        AST structure:

        ::
            aura.analyzers.python.nodes.Call(
              func=aura.analyzers.python.nodes.Attribute(
                source=aura.analyzers.python.nodes.String(value='some_string'),
                attr='replace',
                action='Load'
              ),
              args=[
                aura.analyzers.python.nodes.String(value='s'),
                aura.analyzers.python.nodes.String(value='a')
              ],
              kwargs={}
            )
        """
        # We are looking for a function call
        if type(context.node) != Call:
            return
        # Function target is an attribute with `replace` attribute name
        func: Attribute = context.node.func
        if not (type(func) == Attribute and func.attr == "replace"):
            return

        replace_source = func.source
        # Source of the replace must be String
        if type(replace_source) != String:
            return

        # Check that replace args are also strings
        if len(context.node.args) < 2 or type(context.node.args[0]) != String or type(context.node.args[1]) != String:
            return

        # Rewrite the node by applying the replace operation
        # TODO: check docs if replace takes additional (kw)arguments
        data = str(replace_source).replace(str(context.node.args[0]), str(context.node.args[1]))
        new_node = String(value=data)
        new_node.enrich_from_previous(context.node)
        context.replace(new_node)

    def unary_op(self, context):
        if not type(context.node) == dict:
            return
        elif context.node.get("_type") != "UnaryOp":
            return

        if not type(context.node["operand"]) in (Number, int):
            return

        value = int(context.node["operand"])
        op_name = context.node["op"]["_type"]
        if op_name == "UAdd":
            op = lambda x: +x
        elif op_name == "USub":
            op = lambda x: -x
        elif op_name == "Invert":
            op = lambda x: ~x
        else:
            return

        new_node = Number(value= op(value))
        new_node.enrich_from_previous(context.node)
        context.replace(new_node)
