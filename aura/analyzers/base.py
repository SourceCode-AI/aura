from .python.readonly import ReadOnlyAnalyzer
from .. import exceptions


class NodeAnalyzerV2:
    def reset_hook(self):
        pass

    def post_analysis(self, analyzer:ReadOnlyAnalyzer):
        pass


class AnalyzerDeactivated(exceptions.PluginDisabled):
    pass
