from .python.readonly import ReadOnlyAnalyzer
from .. import exceptions
from ..utils import Analyzer


class NodeAnalyzerV2:
    def reset_hook(self):
        pass

    def post_analysis(self, analyzer: ReadOnlyAnalyzer):  # TODO: check why is this here
        pass


class AnalyzerDeactivated(exceptions.PluginDisabled):
    pass
