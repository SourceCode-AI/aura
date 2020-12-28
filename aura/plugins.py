import inspect
import importlib
import importlib.util
from typing import List, Optional

import pkg_resources

from . import exceptions
from .type_definitions import AnalyzerType, ScanLocation
from .analyzers.base import NodeAnalyzerV2
from .analyzers.detections import Detection
from .analyzers.python.visitor import Visitor
from .analyzers.python.readonly import ReadOnlyAnalyzer

PLUGIN_CACHE = {"analyzers": {}}


def initialize_analyzer(analyzer: AnalyzerType, name: Optional[str]=None) -> AnalyzerType:
    """
    Initialize the analyzer (if needed)
    If analyzer is a subclass of ``NodeAnalyzerV2``, create an instance of it and add it to read only hooks
    Analyzer objects that are callable (functions) are returned back without initialization
    """
    global PLUGIN_CACHE

    if inspect.isclass(analyzer) and issubclass(analyzer, NodeAnalyzerV2):
        analyzer = analyzer()
        ReadOnlyAnalyzer.hooks.append(analyzer)
    elif callable(analyzer):
        pass
    else:
        raise TypeError(f"Could not initialize the '{name or analyzer}' analyzer")

    if name:
        setattr(analyzer, "analyzer_id", name)
        PLUGIN_CACHE["analyzers"][name] = analyzer

    return analyzer


def load_entrypoint(name: str, names=None) -> dict:
    global PLUGIN_CACHE
    if PLUGIN_CACHE.get(name):
        return PLUGIN_CACHE[name]

    data = {
        "entrypoints": {},
        "disabled": [],
    }
    for x in pkg_resources.iter_entry_points(name):
        if names and x.name not in names:
            # Prevent AST analyzers from being loaded if they are not specified in the names
            continue

        try:
            plugin = x.load()
            data["entrypoints"][x.name] = initialize_analyzer(analyzer=plugin, name=x.name)
        except (exceptions.FeatureDisabled, ImportError) as exc:
            msg = exc.args[0]
            data["disabled"].append((x.name, msg))

    PLUGIN_CACHE[name] = data
    return data


def get_analyzers(names: Optional[List[str]]=None) -> List[AnalyzerType]:
    """
    Retrieve the given analyzers
    If list of analyzer names is not provided then a default set of analyzers from entrypoint is used
    Names of analyzers can be used to load a custom group for example:

     - ``readonly`` - corresponds to the analyzer name in the entrypoint which will be returned
     - ``mypackage.module`` - import's all analyzers (e.g. all file based & AST node analyzers) from the mypackage.module
     - ``mypackage/module`` - ditto but uses the file path instead of full import name
     - ``mypackage.module:my_analyzer`` imports only ``my_analyzer`` from the module

    :param names: List of analyzer names to load or None for default group of analyzers
    :type names: Optional[List[str]]
    :return: List of initialized analyzers
    :rtype: List[Callable]
    """
    global PLUGIN_CACHE
    data = load_entrypoint("aura.analyzers", names=names)
    if not names:
        return list(data["entrypoints"].values())

    analyzers = []

    for x in names:
        if x == "ast":  # Noop stage
            continue

        if x in PLUGIN_CACHE["analyzers"]:
            analyzers.append(PLUGIN_CACHE["analyzers"][x])
            continue

        if ":" in x:  # Import only a specific analyzer from a module given by name after `:`
            modname, target = x.split(":")
        else:  # Import all analyzers in a given module
            modname = x
            target = None

        if "/" in modname:  # Module location is a path
            if target is None:
                mod_name = modname.split("/")[-1].split(".")[0]
            else:
                mod_name = target
            spec = importlib.util.spec_from_file_location(mod_name, modname)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        else:  # Module location is importable package/module
            module = importlib.import_module(modname)

        if target is not None:
            analyzer = getattr(module, target)  # Retrieve a specific analyzer from a module given it's name
            analyzers.append(initialize_analyzer(analyzer, name=x))
        else:
            # Iterate over all top level objects in a module to find out which are analyzers
            for obj in module.__dict__.values():  # TODO: add tests
                # Path based analyzer is a function with defined analyzer_id attribute
                if callable(obj) and hasattr(obj, "analyzer_id"):
                    analyzers.append(initialize_analyzer(obj, name=None))
                # AST node analyzer is a subclass of ``NodeAnalyzerV2``
                elif inspect.isclass(obj) and obj is not NodeAnalyzerV2 and issubclass(obj, NodeAnalyzerV2):
                    analyzers.append(initialize_analyzer(obj, name=None))

    return analyzers


def get_analyzer_group(names: Optional[List[str]]):
    analyzers = get_analyzers(names)

    def _run_analyzers(location: ScanLocation):
        ast_analysis = False
        for x in analyzers:
            if isinstance(x, NodeAnalyzerV2):
                ast_analysis = True
            else:
                yield from x(location=location)

        if ast_analysis and location.is_python_source_code:
            try:
                visitor = Visitor.run_stages(location=location)
                yield from visitor()
            except exceptions.ASTParseError:
                yield Detection(
                    location=location.location,
                    detection_type="ASTParseError",
                    message="Unable to parse the source code",
                    signature=f"ast_parse_error#{str(location)}",
                )
            except exceptions.PythonExecutorError as exc:
                yield Detection(
                    location=location.location,
                    detection_type="ASTParseError",
                    message="Unable to parse the source code",
                    signature=f"ast_parse_error#{str(location)}",
                    extra={
                        "stdout": exc.stdout,
                        "stderr": exc.stderr
                    }
                )

    return _run_analyzers
