"""
Analyzer for setup.py python package files
"""
import pprint

from packaging.utils import canonicalize_name

from .detections import Detection
from .python.nodes import String, Call, Dictionary
from .base import NodeAnalyzerV2
from ..utils import Analyzer
from .. import config


logger = config.get_logger(__name__)


@Analyzer.ID("setup_py")
class SetupPy(NodeAnalyzerV2):
    """Audit setup.py file for anomalies such as code execution or network communication"""

    __slots__ = ("hits",)
    filename_whitelist = set(["setup.py"])

    def __init__(self):
        self.hits = []

    def node_Call(self, context):
        if context.node.cached_full_name == "setuptools.setup":
            self.__parse_setup(context)

        yield from []

    def __parse_setup(self, context):
        # Extract basic package identifiers
        copy_fields = ("name", "version", "description", "url")

        parsed = {"packages": []}

        for x in copy_fields:
            # Convert basic fields into string
            if x in context.node.kwargs:
                parsed[x] = self.__as_str(context.node.kwargs[x])

        if context.node.kwargs.get("cmdclass"):
            parsed.update(self.__parse_cmdclass(context))

        pkgs = []
        if type(context.node.kwargs.get("packages")) == list:
            pkgs = [self.__as_str(x) for x in context.node.kwargs["packages"]]
        elif type(context.node.kwargs.get("packages")) == str:
            pkgs = [context.node.kwargs["packages"]]

        for pkg in pkgs:
            parsed["packages"].append(pkg)

            if type(parsed.get("name")) == str and not self.__check_name(
                parsed["name"], pkg
            ):
                sig = Detection(
                    detection_type="SetupScript",
                    score=100,
                    message=f"Package '{parsed['name']}' is installed under different name: '{pkg}'",
                    signature=f"setup_analyzer#pkg_name_mismatch#{parsed['name']}#{pkg}",
                )
                self.hits.append(sig)

        main_sig = Detection(
            detection_type="SetupScript",
            score=0,
            message="Setup script found", extra={"parsed": parsed},
            signature=f"setup_analyzer#setup_script#{context.visitor.normalized_path}#{context.node.line_no}",
            node=context.node
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
            if not isinstance(x, Detection):
                continue
            elif x.name == "SetupScript":
                continue

            if "code_execution" in x.tags:
                sig = Detection(
                    detection_type="SetupScript",
                    score=100,
                    message="Code execution capabilities found in a setup.py script",
                    tags=x.tags,
                    line=x.line,
                    line_no=x.line_no,
                    signature=f"setup_analyzer#code_execution#{x.signature}",
                )

                analyzer.hits.append(sig)
            if "network" in x.tags:
                sig = Detection(
                    detection_type="SetupScript",
                    score=100,
                    message="Found code with network communication capabilities in a setup.py script",
                    tags=x.tags,
                    line=x.line,
                    line_no=x.line_no,
                    signature=f"setup_analyzer#network_communication#{x.signature}",
                )
                analyzer.hits.append(sig)

    def __parse_cmdclass(self, context):
        parsed = {}
        if isinstance(context.node.kwargs["cmdclass"], Dictionary):
            parsed["install_hooks"] = [
                self.__as_str(x) for x in context.node.kwargs["cmdclass"].keys
            ]

            if "install" in parsed["install_hooks"]:
                sig = Detection(
                    detection_type="SetupScript",
                    score=500,
                    message="Setup script hooks to the `setup.py install` command.",
                    tags={"setup.py", "install_hook"},
                    signature=f"setup_analyzer#install_hook#{context.visitor.normalized_path}#{context.node.line_no}",
                    node=context.node
                )

                self.hits.append(sig)
        else:
            logger.info(f"Unknown setup hook: {context.node.kwargs['cmdclass']}")

        return parsed

    def __check_name(self, source: str, target: str) -> bool:
        """
        Check if tha package name (source) is matching a provided package (target)
        This helper functions is used to detect if package is installing itself under different name
        For example typosquatting "requestes" could install itself as "requests"
        """
        # Normalize name
        source = canonicalize_name(source)
        target = canonicalize_name(target)
        if source == target:
            return True
        elif target.startswith(source + "."):
            # It's a subpackage, e.g. Flask could install `flask.json` package which is ok
            return True
        else:
            return False

    def reset_hook(self):
        self.hits = []
