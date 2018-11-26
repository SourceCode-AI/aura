#-*- coding: utf-8 -*-


class AuraException(Exception): pass

class InvalidArchiveMember(AuraException): pass

class NoSuchPackage(AuraException): pass
