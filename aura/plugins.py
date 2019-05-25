import inspect
import importlib

import pkg_resources

from . import exceptions
from .analyzers.base import NodeAnalyzerV2
from .analyzers.python.readonly import ReadOnlyAnalyzer

PLUGIN_CACHE = {}


def load_entrypoint(name) -> dict:
    global PLUGIN_CACHE
    if PLUGIN_CACHE.get(name):
        return PLUGIN_CACHE[name]

    data = {
        'entrypoints': {},
        'disabled': [],
    }
    for x in pkg_resources.iter_entry_points(name):
        try:
            plugin = x.load()

            if inspect.isclass(plugin) and issubclass(plugin, NodeAnalyzerV2):
                plugin = plugin()
                data['entrypoints'][x.name] = plugin
                ReadOnlyAnalyzer.hooks.append(plugin)
                continue
            # If it is a class then make an instance of it
            elif inspect.isclass(plugin):
                plugin = plugin()

            data['entrypoints'][x.name] = plugin

        except exceptions.PluginDisabled as exc:
            msg = exc.args[0]
            data['disabled'].append((x, msg))

    PLUGIN_CACHE[name] = data
    return data


def get_analyzers(names):
    data = load_entrypoint('aura.analyzers')
    if not names:
        return list(data['entrypoints'].values())

    analyzers = []

    for x in names:
        if x in data['entrypoints']:
            analyzers.append(data['entrypoints'][x])
            continue

        modname, target = x.split(':')
        module = importlib.import_module(modname)
        analyzer = getattr(module, target)
        if inspect.isclass(analyzer) and issubclass(analyzer, NodeAnalyzerV2):
            analyzer = analyzer()
            ReadOnlyAnalyzer.hooks.append(analyzer)
            analyzers.append(analyzer)

    return analyzers


def get_analyzer_group(names):
    analyzers = get_analyzers(names)
    def _run_analyzers(path, **kwargs):
        ast_analysis = False
        for x in analyzers:
            if isinstance(x, NodeAnalyzerV2):
                ast_analysis = True
            else:
                yield from x(pth=path, **kwargs)

        if ast_analysis:
            a = ReadOnlyAnalyzer(path=path, **kwargs)
            yield from a(path)

    return _run_analyzers
