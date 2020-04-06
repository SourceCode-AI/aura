# -*- coding: utf-8 -*-


class AuraException(Exception):
    pass


class InvalidLocation(AuraException):
    pass


class InvalidArchiveMember(AuraException):
    pass


class NoSuchPackage(InvalidLocation):
    pass


class ASTNodeRewrite(AuraException):
    pass


class PluginDisabled(AuraException):
    pass

