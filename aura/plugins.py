import inspect
import importlib
import importlib.util
from typing import List, Optional, Callable, Union

import pkg_resources

from . import exceptions
from .analyzers.base import NodeAnalyzerV2
from .analyzers.rules import Rule
from .analyzers.python.visitor import Visitor
from .analyzers.python.readonly import ReadOnlyAnalyzer

PLUGIN_CACHE = {}


def initialize_analyzer(analyzer: Union[NodeAnalyzerV2, Callable]) -> Callable:
    """
    Initialize the analyzer (if needed)
    If analyzer is a subclass of ``NodeAnalyzerV2``, create an instance of it and add it to read only hooks
    Analyzer objects that are callable (functions) are returned back without initialization
    """
    if inspect.isclass(analyzer) and issubclass(analyzer, NodeAnalyzerV2):
        analyzer = analyzer()
        ReadOnlyAnalyzer.hooks.append(analyzer)
        return analyzer
    elif callable(analyzer):
        return analyzer
    else:
        raise ValueError(f"Could not initialize the '{analyzer}' analyzer")



def load_entrypoint(name) -> dict:
    global PLUGIN_CACHE
    if PLUGIN_CACHE.get(name):
        return PLUGIN_CACHE[name]

    data = {
        "entrypoints": {},
        "disabled": [],
    }
    for x in pkg_resources.iter_entry_points(name):
        try:
            plugin = x.load()
            data["entrypoints"][x.name] = initialize_analyzer(plugin)
        except exceptions.PluginDisabled as exc:
            msg = exc.args[0]
            data["disabled"].append((x, msg))

    PLUGIN_CACHE[name] = data
    return data


def get_analyzers(names: Optional[List[str]]=None) -> List[Callable]:
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

    data = load_entrypoint("aura.analyzers")
    if not names:
        return list(data["entrypoints"].values())

    analyzers = []

    for x in names:
        if x in data["entrypoints"]:
            analyzers.append(data["entrypoints"][x])
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
            analyzers.append(initialize_analyzer(analyzer))
        else:
            # Iterate over all top level objects in a module to find out which are analyzers
            for obj in module.__dict__.values():
                # Path based analyzer is a function with defined analyzer_id attribute
                if callable(obj) and hasattr(obj, "analyzer_id"):
                    analyzers.append(initialize_analyzer(obj))
                # AST node analyzer is a subclass of ``NodeAnalyzerV2``
                elif inspect.isclass(obj) and obj is not NodeAnalyzerV2 and issubclass(obj, NodeAnalyzerV2):
                    analyzers.append(initialize_analyzer(obj))

    return analyzers


def get_analyzer_group(names):
    analyzers = get_analyzers(names)

    def _run_analyzers(location):
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
                yield Rule(
                    detection_type="ASTParseError",
                    message="Unable to parse the source code",
                    signature=f"ast_parse_error#{str(location)}",
                )

    return _run_analyzers
