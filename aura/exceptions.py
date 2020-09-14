# -*- coding: utf-8 -*-


class AuraException(Exception):
    pass


class InvalidLocation(AuraException):
    pass


class InvalidOutput(AuraException):
    pass


class InvalidArchiveMember(AuraException):
    pass


class NoSuchPackage(InvalidLocation):
    pass


class NoSuchRepository(InvalidLocation):
    pass


class ASTNodeRewrite(AuraException):
    pass


class FeatureDisabled(AuraException):
    pass


class PluginDisabled(FeatureDisabled):  # TODO: consider removing
    pass


class AnalyzerDeactivated(FeatureDisabled):
    pass


class MinimumScoreNotReached(AuraException):
    pass


class UnsupportedDiffLocation(InvalidLocation):
    pass


class PythonExecutorError(AuraException):
    def __init__(self, *args, **kwargs):
        super(PythonExecutorError, self).__init__(*args, **kwargs)
        self.stdout = None
        self.stderr = None


class ASTParseError(AuraException):
    pass
