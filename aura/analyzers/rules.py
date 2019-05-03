import os
import typing
from pathlib import Path
from dataclasses import dataclass, field
from functools import total_ordering

from .python.nodes import NodeType


@dataclass
@total_ordering
class Rule:
    """
    Base for analyzers to produce hits/results from audit scans
    Subclass this to have different hits on semantic level
    """
    score: int = 0  # Score that affects security audit
    line_no: int = None  # Set to None to hide it from output
    line: str = ''  # Set to None or empty string to hide it from output
    # If the rule is tied to the AST tree detections, then set the node pointer appropriately
    # Set to None to hide or for rules that are not tied to the AST tree
    node: NodeType = None
    tags: set = field(default_factory=set)
    signature: str = ''
    extra: dict = field(default_factory=dict)
    informational: bool = False
    location: typing.Union[Path, str, None] = None
    message: str = ''

    def __post_init__(self):
        self._hash = None

    def _asdict(self):
        """
        Exporting mechanism for JSON output/machine processing
        Define fields to be exported here, subclass need to fetch the fields from their parent in this method
        Output dict must contain only elements that are JSON serializable

        :return: dict
        """
        data = {
            'score': self.score,
            'type': self.__class__.__name__,
        }
        if self.tags:
            data['tags'] = list(self.tags)
        if self.extra:
            data['extra'] = self.extra

        if self.line:
            data['line'] = self.line

        if self.line_no is not None:
            data['line_no'] = self.line_no

        if self.signature:
            data['signature'] = self.signature

        if self.message:
            data['message'] = self.message

        if self.location is not None:
            if isinstance(self.location, Path):
                data['location'] = os.fspath(self.location)
            else:
                data['location'] = self.location

        return data

    def __le__(self, other):
        if not isinstance(other, Rule):
            return True
        elif not (isinstance(self.line_no, int) and isinstance(other.line_no, int)):
            return True
        return self.line_no <= other.line_no

    def __hash__(self):
        if not self.signature:
            return NotImplemented

        if self._hash is None:
            self._hash = hash((self.__class__.__name__, self.signature))
        return self._hash

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        try:
            return hash(self) == hash(other)
        except:
            return False


@dataclass
class FunctionCall(Rule):
    function: str = None

    def _asdict(self):
        d = {
            'function': self.function
        }
        d.update(Rule._asdict(self))
        return d

    def __hash__(self):
        if self._hash is None:
            t = (
                self.function,
                self.location,
                self.line_no,
            )
            self._hash = hash(t)

        return self._hash


@dataclass
class ModuleImport(Rule):
    root: str = None
    name: str = None
    categories: set = field(default_factory=set)

    def _asdict(self):
        d = {
            'root': self.root,
            'name': self.name,
            'categories': list(self.categories)
        }
        d.update(Rule._asdict(self))
        return d

    def __hash__(self):
        if self._hash is None:
            t = (
                self.root,
                self.name,
                self.location,
                self.line_no,
            )
            self._hash = hash(t)

        return self._hash

