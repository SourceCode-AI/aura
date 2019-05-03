import inspect
import typing
import logging

import pkg_resources
from .python.readonly import ReadOnlyAnalyzer
from .. import config


logger = config.get_logger(__name__)

ANALYZERS = None

class NodeAnalyzerV2:
    def reset_hook(self):
        pass

    def post_analysis(self, analyzer:ReadOnlyAnalyzer):
        pass


class AnalyzerDeactivated(EnvironmentError):
    pass


def get_analyzers() -> typing.Dict[str, typing.Callable]:
    """
    Enumerate entry points for registered analyzers and return a dict
    mapping of {name: analyzer_function}
    """
    global ANALYZERS
    if ANALYZERS:
        return ANALYZERS

    d = {}
    for x in pkg_resources.iter_entry_points('aura.analyzers'):
        try:
            hook = x.load()
            if inspect.isclass(hook) and issubclass(hook, NodeAnalyzerV2):
                ReadOnlyAnalyzer.hooks.append(hook())
                continue
            # If it's a class then make an instance of it
            elif inspect.isclass(hook):
                hook = hook()

            d[x.name] = hook
        except AnalyzerDeactivated:
            pass

    ANALYZERS = d

    return d
