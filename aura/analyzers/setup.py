"""
Analyzer for setup.py python package files
"""
import pprint
from dataclasses import dataclass

from . import rules
from .python.nodes import String, Call, Dictionary
from .base import NodeAnalyzerV2
from ..utils import Analyzer
from .. import config


logger = config.get_logger(__name__)


@dataclass
class SetupScript(rules.Rule):
    __hash__ = rules.Rule.__hash__


@Analyzer.ID("setup_py")
class SetupPy(NodeAnalyzerV2):
    """Audit setup.py file for anomalies such as code execution or network communication"""

    __slots__ = ("hits",)
    filename_whitelist = set(["setup.py"])

    def __init__(self):
        self.hits = []

    def node_Call(self, context):
        if context.node.full_name == "setuptools.setup":
            self.__parse_setup(context.node)

        yield from []

    def __parse_setup(self, node: Call):
        # Extract basic package identifiers
        copy_fields = ("name", "version", "description", "url")

        parsed = {"packages": []}

        for x in copy_fields:
            # Convert basic fields into string
            if x in node.kwargs:
                parsed[x] = self.__as_str(node.kwargs[x])

        if node.kwargs.get("cmdclass"):
            parsed.update(self.__parse_cmdclass(node))

        pkgs = []
        if isinstance(node.kwargs.get("packages"), list):
            pkgs = [self.__as_str(x) for x in node.kwargs["packages"]]
        elif isinstance(node.kwargs.get("packages"), str):
            pkgs = [node.kwargs["packages"]]

        for pkg in pkgs:
            parsed["packages"].append(pkg)

            if isinstance(parsed.get("name"), str) and not self.__check_name(
                parsed["name"], pkg
            ):
                sig = SetupScript(
                    score=100,
                    message=f"Package '{parsed['name']}' is installed under different name: '{pkg}'",
                    signature=f"setup_analyzer#pkg_name_mismatch#{parsed['name']}#{pkg}",
                )
                self.hits.append(sig)

        main_sig = SetupScript(
            score=0, message="Setup script found", extra={"parsed": parsed}
        )
        self.hits.append(main_sig)

        logger.debug(f"Parsed setup.py: f{pprint.pformat(parsed)}")

    def __as_str(self, node):
        if isinstance(node, String):
            return node.value
        else:
            return repr(node)

    def post_analysis(self, analyzer):
        if analyzer.path.name != "setup.py":
            return

        for x in analyzer.hits:
            if x.__class__.__name__ == "FunctionCall" and "code_execution" in x.tags:
                sig = SetupScript(
                    score=100,
                    message="Code execution capabilities found in a setup.py script",
                    tags=x.tags,
                    line=x.line,
                    line_no=x.line_no,
                    signature=f"setup_analyzer#code_execution#{x.signature}",
                )

                analyzer.hits.append(sig)
            elif isinstance(x, rules.ModuleImport) and (
                "network" in x.categories or "network" in x.tags
            ):
                sig = SetupScript(
                    score=100,
                    message="Imported module with network communication capabilities in a setup.py script",
                    tags=x.tags,
                    line=x.line,
                    line_no=x.line_no,
                    signature=f"setup_analyzer#network_communication#{x.signature}",
                )
                analyzer.hits.append(sig)

    def __parse_cmdclass(self, node):
        parsed = {}
        if isinstance(node.kwargs["cmdclass"], Dictionary):
            parsed["install_hooks"] = [
                self.__as_str(x) for x in node.kwargs["cmdclass"].keys
            ]

            if "install" in parsed["install_hooks"]:
                sig = SetupScript(
                    score=500,
                    message="Setup script hooks to the `setup.py install` command.",
                )

                self.hits.append(sig)
        else:
            sig = SetupScript(
                score=500,
                message=f"Unknown setup hook, please report a bug: {node.kwargs['cmdclass']}",
            )
            self.hits.append(sig)

        return parsed

    def __check_name(self, source: str, target: str) -> bool:
        """
        Check if tha package name (source) is matching a provided package (target)
        This helper functions is used to detect if package is installing itself under different name
        For example typosquatting "requestes" could install itself as "requests"
        """
        # Normalize name
        source = source.lower().replace("-", "_")
        target = target.lower()
        if source == target:
            return True
        elif target.startswith(source + "."):
            # It's a subpackage, e.g. Flask could install `flask.json` package which is ok
            return True
        else:
            return False

    def reset_hook(self):
        self.hits = []
