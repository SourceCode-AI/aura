from __future__ import annotations

import re
import inspect
import fnmatch
from abc import ABCMeta, abstractmethod
from typing import List, Union

from .analyzers.python import nodes


FUNCTION_PARAMS_KINDS = {
    "POSITIONAL_ONLY": inspect.Parameter.POSITIONAL_ONLY,
    "POSITIONAL_OR_KEYWORD": inspect.Parameter.POSITIONAL_OR_KEYWORD,
    "VAR_POSITIONAL": inspect.Parameter.VAR_POSITIONAL,
    "ARGS": inspect.Parameter.VAR_POSITIONAL,
    "KEYWORD_ONLY": inspect.Parameter.KEYWORD_ONLY,
    "VAR_KEYWORD": inspect.Parameter.VAR_KEYWORD,
    "KWARGS": inspect.Parameter.VAR_KEYWORD,
}


class PatternMatcher(metaclass=ABCMeta):
    """
    Basic abstract class used for string matching patterns
    """

    # string identifying the type of the pattern used for signature parsing
    pattern_type: str = ""

    def __init__(self, signature):
        self._signature = signature
        assert signature["pattern"]

    @abstractmethod
    def match(self, value: str) -> bool:
        """
        match the ast node against the signature
        """
        ...

    @property
    def message(self):
        """
        return a message identifying the match
        """
        return f"{self.pattern_type} match: {self._signature['message']}"

    @classmethod
    def get_patterns(cls) -> List[PatternMatcher]:
        p = []
        for x in cls.__subclasses__():  # type: PatternMatcher
            if inspect.isabstract(x):
                p.extend(x.get_patterns())
            else:
                p.append(x)

        return p

    @classmethod
    def compile_patterns(cls, signatures: List[dict]) -> List[PatternMatcher]:
        """
        Compile all defined string pattern matchers into a dictionary indexed by type
        :signatures: a list of defined signatures (loaded from json file)
        """
        types = {x.pattern_type: x for x in cls.get_patterns()}

        compiled = []
        for s in signatures:
            if type(s) == str:
                s = {"type": "exact", "pattern": s, "message": "n/a"}

            if s["type"] not in types:
                raise ValueError("Unknown signature type: " + s["type"])

            compiled.append(types[s["type"]](s))

        return compiled

    @classmethod
    def find_matches(cls, value, signatures: list):
        """
        iterate over the list of compiled pattern matchers and
        attempt to match the pattern
        """
        if not isinstance(value, (str, nodes.String)):
            return
        value = str(value)

        for s in signatures:  # type: PatternMatcher
            if s.match(value):
                yield s


class StringPatternMatcher(PatternMatcher, metaclass=ABCMeta):
    def match(self, value) -> bool:
        if type(value) != str:
            return False

        return self.match_string(value)

    @abstractmethod
    def match_string(self, value: str):
        ...


class RegexPattern(StringPatternMatcher):
    """
    String matcher that supports regex expressions
    """

    pattern_type = "regex"

    def __init__(self, signature: dict):
        super().__init__(signature)

        flags = 0
        for f in signature.get("flags", ""):
            if f == "I":
                flags |= re.I

        self._regex = re.compile(signature["pattern"], flags=flags)

    def match_string(self, value: str) -> bool:
        """
        match the ast node against the signature
        """
        return bool(self._regex.match(value))


class GlobPattern(StringPatternMatcher):
    """
    String matcher that supports shell like/glob expressions
    """

    pattern_type = "glob"

    def match_string(self, value: str) -> bool:
        return fnmatch.fnmatch(value, self._signature["pattern"])


class ExactPattern(StringPatternMatcher):
    """
    String pattern matcher to match exact, e.g. equal strings
    """

    pattern_type = "exact"

    def match_string(self, value: str) -> bool:
        return value == self._signature["pattern"]


class NumberPattern(PatternMatcher):
    pass  # TODO: eq, leq, range etc..


class FunctionDefinitionPattern:
    """
    This pattern type allows to define a function signature, e.g. args & kwargs
    including their default values and values passed when the function is called
    Accepted arguments can be defined by applying constraints in the function signature
    """

    pattern_type = "function_definition"

    def __init__(self, signature: dict):
        self.signature = signature
        self.__args = {}
        parameters = []

        for s in signature.get("signature", []):
            kind = s.get("kind", "POSITIONAL_OR_KEYWORD").upper()
            p = inspect.Parameter(
                name=s["name"],
                kind=FUNCTION_PARAMS_KINDS[kind],
                default=s.get("default", inspect.Parameter.empty),
                annotation=s.get("annotation", inspect.Parameter.empty),
            )
            self.__args[s["name"]] = s
            parameters.append(p)

        if parameters:
            self.compiled = inspect.Signature(parameters=parameters)
        else:
            self.compiled = None

    def match(self, node: nodes.NodeType) -> Union[None, bool, inspect.BoundArguments]:
        """
        Determine whetever the call to the function matches a defined signature
        The following conditions are required:
        - matching function name (could be another pattern such as regex)
        - matching function args & kwargs as defined in the signature
        - matching constraints for all args/kwargs
        """
        if not self.check_name(node.full_name):
            return

        if not self.compiled:
            return True

        try:
            sig = node.bind(self.compiled)
            sig.apply_defaults()
        except TypeError:
            return

        for name, value in sig.arguments.items():
            if not self.check_constraint(name, value):
                return
        return sig

    def check_name(self, name:str) -> bool:
        """
        Checks if the call function name is matching the pattern defined in signature
        """
        patterns = PatternMatcher.compile_patterns([self.signature["name"]])
        matches = list(PatternMatcher.find_matches(name, patterns))
        return bool(matches)


    def check_constraint(self, name: str, value) -> bool:  # TODO!!!
        """
        Checks if the function argument value is matching all the constraints
        :param name: function argument name
        :param value: binded function argument value
        """
        annotation = self.__args[name].get("annotation", "").lower()
        constraint = self.__args[name].get("constraint", [])

        if not annotation:
            return True
        # TODO: check type by supported annotation
        if constraint is None or constraint == []:
            return True

        if not isinstance(constraint, (tuple, list)):
            constraint = (constraint,)

        for c in constraint:
            if not CONSTRAINTS[annotation](value, c):
                return False
        return True


def boolean_constraint(value, constraint):
    if value == 'False':
        value = False
    elif value == 'True':
        value = True
    return (value is constraint)


# Possible constraint annotations for function arguments
CONSTRAINTS = {
    "bool": boolean_constraint
}
