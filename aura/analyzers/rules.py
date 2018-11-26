from collections import namedtuple

sensitive_file = namedtuple('SensitiveFile', ['name', 'location', 'score'])
suspicious_entry = namedtuple('SuspiciousEntry', ['location', 'type', 'path', 'score'])
suspicious_file = namedtuple('SuspiciousFile', ['name', 'location', 'type', 'score'])
module_import = namedtuple('ModuleImport', ['name', 'location', 'score', 'category', 'line_no', 'line'])
function_call = namedtuple('FunctionCall', ['function', 'location', 'score', 'line_no', 'line'])


class yara_match(namedtuple('YaraMatch', ['rule', 'location', 'strings', 'meta'])):
    @property
    def score(self):
        if not self.meta:
            return False
        return self.meta.get('score', 0) * len(self.strings)
