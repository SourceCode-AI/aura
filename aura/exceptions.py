# -*- coding: utf-8 -*-
from typing import Optional


class AuraException(RuntimeError):
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


class InvalidConfiguration(AuraException, ValueError):
    pass


class MissingFile(InvalidLocation):
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
        super().__init__(*args, **kwargs)
        self.stdout = None
        self.stderr = None


class ASTParseError(AuraException):
    pass


class RateLimitError(AuraException):
    pass
