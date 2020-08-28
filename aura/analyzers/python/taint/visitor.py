import re
import pprint

from ..nodes import *
from ..visitor import Visitor


class TaintAnalysis(Visitor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.first_pass = True

    def _post_iteration(self):
        self.first_pass = False

    def _visit_node(self, context: Context):
        if not isinstance(context.node, ASTNode):
            return
        elif type(context.node) == Import:
            return

        if self.first_pass:
            self.__mark_flask_route(context)
            self.__mark_django_view(context)

        self.__mark_sources(context)
        self.__propagate_taint(context=context)

    def __mark_flask_route(self, context):
        """
        Mark a function as a flask route by adding an AST node tag
        Example:

        ::
            @app.route("/")
            def index():
                return "Hello world"


        index function in this case should be marked as a flask route
        """
        if "flask_route" in context.node.tags:
            return
        elif "django_view" in context.node.tags:
            return

        # Node is a function definition
        if not type(context.node) == FunctionDef:
            return
        # Node has at least one decorator
        if not len(context.node.decorator_list) > 0:
            return

        # Iterate over decorators
        for dec in context.node.decorator_list:
            if (
                isinstance(dec, Call)
                and dec.full_name == "flask.Flask.route"
            ):
                log = TaintLog(
                    path = self.path,
                    line_no=context.node.line_no,
                    message="AST node marked as a Flask route"
                )
                context.node._taint_log.append(log)
                context.node.tags.add("flask_route")
                context.visitor.modified = True
                return

    def __mark_django_view(self, context):
        if "flask_route" in context.node.tags:
            return
        elif "django_view" in context.node.tags:
            return
        elif not isinstance(context.node, FunctionDef):
            return

        for r in context.node.return_nodes.values():  # TODO: transition this to the apply_taint of FunctionDefPattern
            f_name = r.cached_full_name
            if type(f_name) != str:
                continue


            if "django_view" in r.value.tags:
                context.node.args.taints["request"] = Taints.TAINTED
                context.visitor.modified = True
                return

    def __mark_sources(self, context):
        if isinstance(
            context.node, FunctionDef
        ):  # Mark arguments as sources for flask routes
            if "flask_route" in context.node.tags and isinstance(
                context.node.args, Arguments
            ):
                urls = list(context.node.get_flask_routes())

                for url in urls:
                    for arg in context.node.args.args:
                        parsed_url = parse_werkzeug_url(url)
                        if arg in parsed_url and parsed_url[arg] in ("int",):
                            continue
                        else:
                            log = TaintLog(
                                path = self.path,
                                node = arg,
                                line_no = context.node.line_no,
                                message = "AST node has been marked as Taint because a variable is propagated via werkzeug URL parameter",
                                taint_level=Taints.TAINTED
                            )
                            context.node.set_taint(name=arg, taint_level=Taints.TAINTED, taint_log=log, context=context)

    def __propagate_taint(self, context):
        if isinstance(context.node, Attribute) and isinstance(
            context.node.source, ASTNode
        ):
            self.__propagate_attribute(context)
            return
        elif isinstance(context.node, Call):
            f_name = context.node.cached_full_name
            args_taints = []
            # Extract taints from arguments
            for idx, x in enumerate(context.node.args):
                if isinstance(x, Arguments) and type(context.node._orig_args[idx]) == str:
                    arg_name = context.node._orig_args[idx]
                    args_taints.append(x.taints.get(arg_name, Taints.SAFE))
                elif isinstance(x, ASTNode):
                    args_taints.append(x._taint_class)

            for x in context.node.kwargs.values():
                if isinstance(x, ASTNode):
                    args_taints.append(x._taint_class)

            # Extract taint if the function itself is tainted
            if isinstance(context.node.func, ASTNode):
                args_taints.append(context.node.func._taint_class)

            if not args_taints:
                return
            # Choose the highest taint from the extracted taints
            call_taint = max(args_taints)
            if context.node.add_taint(taint=call_taint, context=context):
                # Mark built-in objects for example [].append(<tainted>)
                if isinstance(context.node.func, Attribute) and isinstance(
                    context.node.func.source, (List,)
                ):
                    context.node.func.source.add_taint(call_taint, context)
                return

            # Lookup in a call graph if the function was defined
            if type(f_name) == str and f_name in context.call_graph.definitions:
                func_def = context.call_graph.definitions[f_name]

                # Propagate taint from the function definition
                context.node.add_taint(func_def._taint_class, context)
                # Apply taint from called arguments to the function definition
                for idx, x in enumerate(context.node.args):
                    if not isinstance(x, ASTNode):
                        continue
                    if x.cached_full_name is None:
                        arg_index = idx
                    elif type(x.cached_full_name) == str:
                        arg_index = x.cached_full_name
                    else:
                        continue
                    func_def.set_taint(name=arg_index, taint_level=x._taint_class, context=context, taint_log=None)

        elif isinstance(context.node, Var):
            var_taint = max(
                context.node._taint_class,
                getattr(context.node.value, "_taint_class", Taints.UNKNOWN),
            )

            log = TaintLog(
                path=self.path,
                taint_level=var_taint,
                node=context.node.value,
                line_no=context.node.line_no,
                message = "Taint propagated via variable assignment"
            )

            if context.node.add_taint(var_taint, context, taint_log=log):
                return

        elif isinstance(context.node, Subscript):
            if not isinstance(context.node.value, ASTNode):
                return

            log = TaintLog(
                path=self.path,
                taint_level=context.node.value._taint_class,
                node=context.node.value,
                line_no=context.node.line_no,
                message = "Taint propagated via variable subscript"
            )

            if context.node.add_taint(context.node.value._taint_class, context, taint_log=log):
                return

        elif isinstance(context.node, (ReturnStmt, Yield, YieldFrom)):
            if isinstance(context.node.value, ASTNode):
                log = TaintLog(
                    path = self.path,
                    taint_level=context.node.value._taint_class,
                    node=context.node.value,
                    line_no=context.node.line_no,
                    message = "Taint propagated by return/yield statement"
                )

                if context.node.add_taint(context.node.value._taint_class, context, taint_log=log):
                    return

        elif isinstance(context.node, BinOp):
            taints = []

            if isinstance(context.node.left, Arguments):
                t_arg = context.node.left.taints.get(
                    context.node._orig_left, Taints.SAFE
                )
                taints.append(t_arg)
                context.node.add_taint(t_arg, context)
            elif isinstance(context.node.left, ASTNode):
                taints.append(context.node.left._taint_class)

            if isinstance(context.node.right, Arguments):
                t_arg = context.node.right.taints.get(
                    context.node._orig_right, Taints.SAFE
                )
                taints.append(t_arg)
                context.node.add_taint(t_arg, context)
            elif isinstance(context.node.right, ASTNode):
                taints.append(context.node.right._taint_class)

            if not taints:
                return

            op_taint = max(taints)
            if context.node.add_taint(op_taint, context):
                return

        elif isinstance(context.node, FunctionDef):
            f_name = context.node.cached_full_name

            return_taints = []

            for r in context.node.return_nodes.values():  # type: ASTNode
                return_taints.append(r._taint_class)

            if return_taints:
                rt = max(return_taints)
                context.node.add_taint(rt, context)

            if f_name in context.call_graph:
                callers = context.call_graph[f_name]
                sig = context.node.get_signature()
                for c in callers:  # type: ASTNode
                    c.add_taint(context.node._taint_class, context)
                    try:
                        call_params = sig.bind(*c.args, **c.kwargs)
                        for param_name, param_value in call_params.arguments.items():
                            if not isinstance(param_value, ASTNode):
                                continue
                            t_param = param_value._taint_class
                            context.node.set_taint(param_name, t_param, context)

                    except (TypeError,):
                        pass

    def __propagate_attribute(self, context):
        parent = context.node.source._taint_class

        if parent != Taints.TAINTED:
            return

        log = TaintLog(
            path=self.path,
            taint_level=parent,
            line_no=context.node.line_no,
            message="Taint level has been propagated via attribute access"
        )
        context.node.add_taint(parent, context, taint_log=log)

    def _post_analysis(self):
        return #TODO
        external_taints = {}

        for name, callers in self.call_graph.references.items():
            if not name.startswith('.'):  # TODO
                continue

            for c in callers:
                call = []

                for param_name, param_value in c.arguments.items():
                    pass

        pprint.pprint(external_taints)


def parse_werkzeug_url(url: str) -> dict:
    """
    Parse a flask/werkzeug URL to extract placeholders and their processors
    This is used in taint analysis to find tainted URL arguments
    for example: /api/v1.0/lookup/<username>/info
    would extract the 'username' placeholder (with no processor)
    """
    regex = re.compile(
        r"<(?P<processor>([a-z_\d]+)(\(.*\))?:)?(?P<parameter>[a-z\d_]+)>"
    )

    parsed = {}

    for finding in regex.findall(url):
        parsed[finding[-1]] = finding[0].rstrip(":")

    return parsed
