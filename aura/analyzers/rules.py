from __future__ import annotations

import os
from typing  import List, Union, Set, Optional
from pathlib import Path
from dataclasses import dataclass, field
from functools import total_ordering
from collections import defaultdict

from ..utils import lookup_lines, normalize_path
from .python.nodes import NodeType, ASTNode


@dataclass
@total_ordering
class Rule:
    """
    Base for analyzers to produce detections from audit scans that are reported back to the Aura framework
    Subclass this to have different hits on semantic level

    :param message: Detection message, intended to be displayed to a user
    :type message: str
    :param signature: Used by default for hashing/deduplication of various detections. At minimum, it is highly recommended to include at least a detection name and a normalized path to the scanned file. In case of AST based detections, line number is also recommended as it is possible that the source code can contain multiple detections of the same anomaly that are on different lines and should be reported separately.
    :type signature: str

    :param score: A score associated with this detection that is then used to compute the overall score of the input scanned by Aura.
    :type score: int, optional
    :param node: A reference to the AST node object. It is recommended to set this attribute for AST based detections as the framework will automatically fill some of the emtadata for the output such as line number or the actual content of the line.
    :type node: ASTNode, optional
    :param extra: A schema less dictionary. Use this to report back any data fields when exporting the scan data into various formats such as JSON
    :type extra: dict, optional
    :param tags: A set of strings that acts as tags for this detection. Used for filtering the outputs and tagging whole files via detections.
    :type tags: Set[str], optional
    :param detection_type: An identifier of the detection type. Used for filtering out the different detections. If not provided, class name is used.
    :type detection_type: str, optional
    """

    signature: str
    message: str
    score: int = 0  # Score that affects security audit
    line_no: Optional[int] = None  # Set to None to hide it from output
    line: Union[
        str, None
    ] = None  #  Set to None or empty string to hide it from output
    # If the rule is tied to the AST tree detections, then set the node pointer appropriately
    #  Set to None to hide or for rules that are not tied to the AST tree
    detection_type: Optional[str] = None
    node: Optional[NodeType] = None
    tags: Set[str] = field(default_factory=set)
    extra: dict = field(default_factory=dict)
    informational: bool = False
    location: Union[Path, str, None] = None
    _metadata: Optional[dict] = None

    def __post_init__(self):
        self._hash = None

        if isinstance(self.node, ASTNode) and self.line_no is None:
            self.line_no = self.node.line_no

    def _asdict(self) -> dict:
        """
        Exporting mechanism for JSON output/machine processing
        Define fields to be exported here, subclass need to fetch the fields from their parent in this method
        Output dict must contain only elements that are JSON serializable

        :return: Serialized data for the detection
        :rtype: dict
        """
        data = {
            "score": self.score,
        }
        if self.detection_type is not None:
            data["type"] = self.detection_type
        else:
            data["type"] = self.__class__.__name__

        if self.tags:
            data["tags"] = list(self.tags)
        if self.extra:
            data["extra"] = self.extra

        if self.line:
            data["line"] = self.line

        if self.line_no is not None:
            data["line_no"] = self.line_no

        if self.signature:
            data["signature"] = self.signature

        if self.message:
            data["message"] = self.message

        if self.location is not None:
            if isinstance(self.location, Path):
                data["location"] = normalize_path(self.location)
            else:
                data["location"] = self.location

        return data

    def __le__(self, other):
        if not isinstance(other, Rule):
            return True
        elif not (isinstance(self.line_no, int) and isinstance(other.line_no, int)):
            return True
        return self.line_no <= other.line_no

    def __hash__(self):
        """
        Default hash implementation for deduplication of detections.
        By default a combination of a class name and a `signature` attribute is used to produce the hash.

        Override this method for a custom deduplication logic
        """
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

    @classmethod
    def lookup_lines(cls, rules: List[Rule], location):
        """
        For each rule in the list, look-up a content of the line based on
        location and line number of the hit

        Rule.line is then modified to contain the content of a line
        """
        paths = defaultdict(list)
        for r in rules:
            if r.line_no is not None and not r.line:
                paths[r.location].append(r)
                r.location = location.strip(r.location)

        # TODO: write test for the encoding
        encoding = location.metadata.get("encoding") or "utf-8"

        for pth, rlines in paths.items():
            linenos = [x.line_no for x in rlines]
            lines = lookup_lines(pth, linenos, encoding=encoding)
            for r in rlines:
                if r.line_no in lines:
                    r.line = lines[r.line_no]



class DataProcessing(Rule):
    pass


@dataclass
class ModuleImport(Rule):  #TODO: remove and migrate to `Rule`
    root: NodeType = None
    name: NodeType = None
    categories: set = field(default_factory=set)

    def _asdict(self):
        d = {"root": self.root, "name": self.name, "categories": list(self.categories)}
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
